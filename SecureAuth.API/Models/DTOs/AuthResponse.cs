namespace SecureAuth.API.Models.DTOs;
public class AuthResponse
{
    public string Id { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Token { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty; // Refresh token eklendi
    public DateTime TokenExpires { get; set; } // Token son geçerlilik tarihi eklendi
    public string Role { get; set; } = string.Empty;
    public string? ErrorMessage { get; set; }
}