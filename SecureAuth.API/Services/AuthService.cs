using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SecureAuth.API.Models.Entities;
using SecureAuth.API.Interfaces;
using SecureAuth.API.Models.DTOs;
using SecureAuth.API.Data;

namespace SecureAuth.API.Services;

public class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IConfiguration _configuration;
    private readonly ApplicationDbContext _context;

    public AuthService(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        RoleManager<IdentityRole> roleManager,
        IConfiguration configuration,
        ApplicationDbContext context)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _roleManager = roleManager;
        _configuration = configuration;
        _context = context;
    }

    public async Task<AuthResponse?> Register(RegisterRequest request)
    {
        // Kullanıcı adı zaten var mı kontrol et
        if (await UserExists(request.Username))
        {
            return null;
        }

        // E-posta adresi zaten var mı kontrol et
        var existingUserByEmail = await _userManager.FindByEmailAsync(request.Email);
        if (existingUserByEmail != null)
        {
            return new AuthResponse
            {
                Id = "",
                Username = "",
                Email = "",
                Token = "",
                Role = "",
                ErrorMessage = "Bu e-posta adresi zaten kullanımda!"
            };
        }

        var user = new ApplicationUser
        {
            UserName = request.Username,
            Email = request.Email
        };

        var result = await _userManager.CreateAsync(user, request.Password);
        
        if (!result.Succeeded)
        {
            return new AuthResponse
            {
                Id = "",
                Username = "",
                Email = "",
                Token = "",
                Role = "",
                ErrorMessage = string.Join(", ", result.Errors.Select(e => e.Description))
            };
        }

        // Kullanıcıya rol atama (varsayılan olarak "User")
        if (!await _roleManager.RoleExistsAsync("User"))
        {
            await _roleManager.CreateAsync(new IdentityRole("User"));
        }
        
        await _userManager.AddToRoleAsync(user, "User");
        
        // Refresh token ve Access token oluşturma
        var tokenResponse = await CreateTokenResponse(user);
        return tokenResponse;
    }

    public async Task<AuthResponse?> Login(LoginRequest request)
    {
        var user = await _userManager.FindByNameAsync(request.Username);
        if (user == null)
        {
            return null;
        }

        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);
        
        if (!result.Succeeded)
        {
            return null;
        }

        // Yeni token ve refresh token oluştur
        var tokenResponse = await CreateTokenResponse(user);
        return tokenResponse;
    }

    public async Task<bool> UserExists(string username)
    {
        return await _userManager.FindByNameAsync(username) != null;
    }

    // Refresh token işlemi
    public async Task<AuthResponse?> RefreshToken(string refreshToken)
    {
        // Refresh token'ı veritabanında bul
        var storedToken = await _context.RefreshTokens
            .Include(rt => rt.User)
            .FirstOrDefaultAsync(rt => rt.Token == refreshToken);

        // Token bulunamadıysa, geçersizse veya süresi dolduysa null döndür
        if (storedToken == null || !storedToken.IsActive)
        {
            return null;
        }

        var user = storedToken.User;
        if (user == null)
        {
            return null;
        }

        // Eski refresh token'ı iptal et
        storedToken.IsRevoked = true;
        _context.RefreshTokens.Update(storedToken);
        await _context.SaveChangesAsync();

        // Yeni token ve refresh token oluştur
        return await CreateTokenResponse(user);
    }

    // Refresh token oluşturma
    public async Task<RefreshToken> CreateRefreshToken(ApplicationUser user)
    {
        // Rastgele bir token değeri oluştur
        var randomBytes = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        var refreshToken = Convert.ToBase64String(randomBytes);

        // Refresh token süresi için yapılandırmadaki değeri kullan
        int refreshTokenValidityInDays = 7; // Varsayılan değer
        if (int.TryParse(_configuration["JWT:RefreshTokenValidityInDays"], out int configValue))
        {
            refreshTokenValidityInDays = configValue;
        }
        
        var expires = DateTime.UtcNow.AddDays(refreshTokenValidityInDays);

        var refreshTokenEntity = new RefreshToken
        {
            Token = refreshToken,
            Created = DateTime.UtcNow,
            Expires = expires,
            UserId = user.Id
        };

        return refreshTokenEntity;
    }

    // Refresh token'ı kullanıcıya atama
    public async Task SetRefreshToken(RefreshToken refreshToken, ApplicationUser user)
    {
        // Yeni refresh token'ı veritabanına ekle
        await _context.RefreshTokens.AddAsync(refreshToken);
        await _context.SaveChangesAsync();
    }

    // Refresh token doğrulama
    public async Task<bool> ValidateRefreshToken(string refreshToken, string userId)
    {
        var token = await _context.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.Token == refreshToken && rt.UserId == userId);

        return token != null && token.IsActive;
    }

    // Kullanıcının tüm refresh token'larını iptal etme
    public async Task<bool> RevokeAllUserRefreshTokens(string userId)
    {
        try
        {
            // Kullanıcıya ait tüm aktif refresh token'ları bul
            var userTokens = await _context.RefreshTokens
                .Where(rt => rt.UserId == userId && !rt.IsRevoked && rt.Expires > DateTime.UtcNow)
                .ToListAsync();

            if (userTokens.Count == 0)
            {
                return false; // İptal edilecek token bulunamadı
            }

            // Tüm token'ları iptal et
            foreach (var token in userTokens)
            {
                token.IsRevoked = true;
            }

            _context.RefreshTokens.UpdateRange(userTokens);
            await _context.SaveChangesAsync();
            
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    // JWT token oluşturma işlemi
    private async Task<(string Token, DateTime Expires)> CreateToken(ApplicationUser user)
    {
        var userRoles = await _userManager.GetRolesAsync(user);
        
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Name, user.UserName ?? string.Empty),
            new Claim(ClaimTypes.Email, user.Email ?? string.Empty),
        };
        
        // Kullanıcı rollerini token'a ekle
        foreach (var role in userRoles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        // Yeni JWT yapılandırmasını kullan
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
            _configuration.GetSection("JWT:Secret").Value ?? throw new InvalidOperationException("JWT Secret anahtarı bulunamadı.")));

        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

        // Token süresi için yapılandırmadaki değeri kullan (varsayılan: 15 dakika)
        int tokenValidityInMinutes = 15; // Varsayılan değer
        if (int.TryParse(_configuration["JWT:TokenValidityInMinutes"], out int configValue))
        {
            tokenValidityInMinutes = configValue;
        }
        
        var expires = DateTime.UtcNow.AddMinutes(tokenValidityInMinutes);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = expires,
            SigningCredentials = creds,
            Issuer = _configuration["JWT:ValidIssuer"],
            Audience = _configuration["JWT:ValidAudience"]
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);

        return (tokenHandler.WriteToken(token), expires);
    }

    // Tam token yanıtı oluşturma
    private async Task<AuthResponse> CreateTokenResponse(ApplicationUser user)
    {
        // Access token oluştur
        var (token, tokenExpires) = await CreateToken(user);
        
        // Refresh token oluştur
        var refreshToken = await CreateRefreshToken(user);
        
        // Refresh token'ı kullanıcıyla ilişkilendir ve veritabanına kaydet
        await SetRefreshToken(refreshToken, user);
        
        // Kullanıcı rollerini al
        var roles = await _userManager.GetRolesAsync(user);
        
        // Tam yanıtı oluştur
        return new AuthResponse
        {
            Id = user.Id,
            Username = user.UserName ?? string.Empty,
            Email = user.Email ?? string.Empty,
            Token = token,
            RefreshToken = refreshToken.Token,
            TokenExpires = tokenExpires,
            Role = roles.FirstOrDefault() ?? string.Empty
        };
    }
}