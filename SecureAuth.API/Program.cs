using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using SecureAuth.API.Data;
using SecureAuth.API.Services;
using SecureAuth.API.Interfaces;
using SecureAuth.API.Models.Entities;

// Program.cs: Uygulamanın başlangıç noktası, servis konfigürasyonları ve middleware tanımları
var builder = WebApplication.CreateBuilder(args);

// Controller'lar için gerekli servisleri ekle
builder.Services.AddControllers();

// Swagger/OpenAPI desteği ekle ve konfigüre et
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    // API dokümantasyonu için temel bilgiler
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "SecureAuthApi", Version = "v1" });
    
    // Swagger UI'da JWT Authorization desteği tanımlaması
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
    
    // Tüm endpoint'ler için güvenlik gereksinimi ekle (Bearer token)
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// Entity Framework DbContext'i ve SQL Server bağlantısını ekle
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// ASP.NET Core Identity konfigürasyonu ve kuralları
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options => {
    // Parola kuralları: rakam, küçük harf, büyük harf, özel karakter ve minimum uzunluk
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 8;
    
    // Kullanıcı kuralları: benzersiz e-posta zorunluluğu
    options.User.RequireUniqueEmail = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Uygulama servis kaydı: IAuthService implementasyonu
builder.Services.AddScoped<IAuthService, AuthService>();

// JWT Bearer authentication konfigürasyonu
builder.Services.AddAuthentication(options => {
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        // İmza anahtarı doğrulaması
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
            builder.Configuration.GetSection("JWT:Secret").Value ?? throw new InvalidOperationException("JWT Secret anahtarı bulunamadı."))),
        // Token kaynağı ve hedefi doğrulama
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidIssuer = builder.Configuration["JWT:ValidIssuer"],
        ValidAudience = builder.Configuration["JWT:ValidAudience"],
        // Saat kayması toleransını sıfırla (hassas doğrulama)
        ClockSkew = TimeSpan.Zero
    };

    // Token süresinin dolması durumunda header ekleme
    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context =>
        {
            if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
            {
                context.Response.Headers.Add("IS-TOKEN-EXPIRED", "true");
            }
            return Task.CompletedTask;
        }
    };
});

// CORS politikası: tüm istekleri kabul et (geliştirme için)
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", 
        builder => builder
            .AllowAnyOrigin()
            .AllowAnyMethod()
            .AllowAnyHeader());
});

// Uygulamayı oluştur
var app = builder.Build();

// Geliştirme ortamında Swagger UI'ı etkinleştir
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// HTTPS yönlendirmesi
app.UseHttpsRedirection();

// CORS middleware'i
app.UseCors("AllowAll");

// Kimlik doğrulama ve yetkilendirme middleware'leri
app.UseAuthentication();
app.UseAuthorization();

// Controller rotalarını etkinleştir
app.MapControllers();

#region İlk Yüklemede Admin Kullanıcısı Oluşturma 
// Uygulama ilk yüklendiğinde admin kullanıcısı oluşturma işlemi
// Admin kullanıcısı oluşturulduktan sonra burayı kaldırabilirsiniz
// Geliştirme ortamı için otomatik admin kullanıcısı seed işlemi
// GÜVENLİK UYARISI: Üretim ortamına taşınmadan önce kaldırılmalıdır!
if (app.Environment.IsDevelopment())
{
    using (var scope = app.Services.CreateScope())
    {
        var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

        logger.LogInformation("Geliştirme ortamı için admin kullanıcısı seed verisi başlatılıyor...");

        try
        {
            // "Admin" rolü yoksa oluştur
            if (!await roleManager.RoleExistsAsync("Admin"))
            {
                await roleManager.CreateAsync(new IdentityRole("Admin"));
                logger.LogInformation("'Admin' rolü başarıyla oluşturuldu.");
            }

            // Belirtilen e-posta ile admin kullanıcısını bul
            var adminEmail = "admin@example.com";
            var adminUser = await userManager.FindByEmailAsync(adminEmail);
            if (adminUser == null)
            {
                // GÜVENLİK: Şifre güvenli bir kaynaktan alınmalı
                var adminPassword = "Admin123!";

                adminUser = new ApplicationUser
                {
                    UserName = "admin",
                    Email = adminEmail
                };

                // Kullanıcı oluştur ve Admin rolünü ata
                var result = await userManager.CreateAsync(adminUser, adminPassword);
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(adminUser, "Admin");
                    logger.LogInformation("Admin kullanıcısı başarıyla oluşturuldu. Email: {Email}", adminEmail);
                    logger.LogWarning("GÜVENLİK UYARISI: Seed verisi ile oluşturulan admin kullanıcısının şifresini hemen değiştirin!");
                }
                else
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    logger.LogError("Admin kullanıcısı oluşturulurken hata: {Errors}", errors);
                }
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Admin kullanıcısı seed verisi oluşturulurken bir hata oluştu.");
        }
    }
}
#endregion

// Uygulamayı çalıştır
app.Run();
