namespace SecureAuth.API.Models.DTOs;

// Refresh token isteği için DTO
public class RefreshTokenRequest
{
    // Refresh token değeri
    public string RefreshToken { get; set; } = string.Empty;
}