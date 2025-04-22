namespace SecureAuth.API.Models.DTOs;

// Logout isteği için DTO
public class LogoutRequest
{
    // Oturumu kapatılacak refresh token değeri
    public string RefreshToken { get; set; } = string.Empty;
}