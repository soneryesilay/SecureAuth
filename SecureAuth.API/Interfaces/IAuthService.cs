using SecureAuth.API.Models.DTOs;
using SecureAuth.API.Models.Entities;

namespace SecureAuth.API.Interfaces;

public interface IAuthService
{
    Task<AuthResponse?> Register(RegisterRequest request);
    Task<AuthResponse?> Login(LoginRequest request);
    Task<bool> UserExists(string username);
    
    // Refresh token ile yeni token alma metodu
    Task<AuthResponse?> RefreshToken(string refreshToken);
    
    // Refresh token oluşturma metodu
    Task<RefreshToken> CreateRefreshToken(ApplicationUser user);
    
    // Refresh tokeni veritabanına kaydetme
    Task SetRefreshToken(RefreshToken refreshToken, ApplicationUser user);
    
    // Refresh token geçerliliğini kontrol etme
    Task<bool> ValidateRefreshToken(string refreshToken, string userId);
    
    // Kullanıcının tüm refresh token'larını iptal etme metodu
    Task<bool> RevokeAllUserRefreshTokens(string userId);
    
}