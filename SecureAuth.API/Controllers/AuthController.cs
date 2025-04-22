using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureAuth.API.Models.DTOs;
using SecureAuth.API.Interfaces;

namespace SecureAuth.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("register")]
        public async Task<ActionResult<AuthResponse>> Register(RegisterRequest request)
        {
            var response = await _authService.Register(request);
            if (response == null)
            {
                return BadRequest("Kullanıcı adı zaten kayıtlı!");
            }

            if (!string.IsNullOrEmpty(response.ErrorMessage))
            {
                return BadRequest(response.ErrorMessage);
            }

            // Modified response to not include token information
            return Ok(new
            {
                message = "Kayıt başarılı! Lütfen giriş yapınız.",
            });
        }

        [HttpPost("login")]
        public async Task<ActionResult<AuthResponse>> Login(LoginRequest request)
        {
            var response = await _authService.Login(request);
            if (response == null)
            {
                return BadRequest("Kullanıcı adı veya şifre hatalı!");
            }

            return Ok(response);
        }

        // Refresh token ile yeni token alma endpoint'i
        [HttpPost("refresh-token")]
        public async Task<ActionResult<AuthResponse>> RefreshToken(RefreshTokenRequest request)
        {
            var response = await _authService.RefreshToken(request.RefreshToken);
            if (response == null)
            {
                return BadRequest("Geçersiz veya süresi dolmuş refresh token!");
            }

            return Ok(response);
        }

        // Kullanıcının tüm refresh token'larını iptal etme endpoint'i
        [Authorize(Roles = "Admin")]
        [HttpPost("revoke-all-tokens")]
        public async Task<ActionResult> RevokeAllTokens()
        {
            var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized();
            }

            var result = await _authService.RevokeAllUserRefreshTokens(userId);
            if (!result)
            {
                return BadRequest("İptal edilecek token bulunamadı veya işlem sırasında bir hata oluştu.");
            }

            return Ok("Tüm oturumlar başarıyla sonlandırıldı.");
        }


        [Authorize]
        [HttpGet("protected")]
        public ActionResult<string> Protected()
        {
            return Ok("Bu endpoint korumalıdır, yalnızca yetkilendirilmiş kullanıcılar erişebilir.");
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("admin")]
        public ActionResult<string> AdminOnly()
        {
            return Ok("Bu endpoint yalnızca Admin rolüne sahip kullanıcılar için erişilebilir.");
        }
    }
}

