using System.ComponentModel.DataAnnotations;

namespace SecureAuth.API.Models.DTOs;


public class LoginRequest
{
    [Required]
    public string Username { get; set; } = string.Empty;
    
    [Required]
    public string Password { get; set; } = string.Empty;
}

