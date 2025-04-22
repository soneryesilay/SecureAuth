using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace SecureAuth.API.Models.Entities;

// Identity yapısıyla uyumlu kullanıcı sınıfı
public class ApplicationUser : IdentityUser
{
    // Identity'nin varsayılan özellikleri zaten mevcut:
    // Id, UserName, Email, PasswordHash, PhoneNumber, vb.
    // Identity'nin sağladığı rol yönetimi kullanılacak (AspNetRoles ve AspNetUserRoles tabloları)
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    // Kullanıcıya ait refresh token'lar için ilişki
    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}