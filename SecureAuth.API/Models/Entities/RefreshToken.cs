using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SecureAuth.API.Models.Entities;

// Kullanıcılara ait refresh token'ları saklayacak entity sınıfı
public class RefreshToken
{
    [Key]
    public int Id { get; set; }
    
    // Token değeri
    public string Token { get; set; } = string.Empty;
    
    // Token'ın oluşturulma tarihi
    public DateTime Created { get; set; } = DateTime.UtcNow;
    
    // Token'ın geçerlilik süresi sonu
    public DateTime Expires { get; set; }
    
    // Token kullanıldı mı?
    public bool IsRevoked { get; set; } = false;
    
    // Token'ın bağlı olduğu kullanıcı ID'si
    public string UserId { get; set; } = string.Empty;
    
    // ApplicationUser ile ilişki
    [ForeignKey(nameof(UserId))]
    public ApplicationUser? User { get; set; }
    
    // Token'ın hala geçerli olup olmadığını kontrol eder
    public bool IsActive => !IsRevoked && DateTime.UtcNow <= Expires;
}