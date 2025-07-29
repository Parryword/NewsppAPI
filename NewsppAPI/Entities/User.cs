namespace NewsppAPI.Entities;

public class User
{
    public Guid Id { get; set; }
    public String Username { get; set; } = string.Empty;
    public String Password { get; set; } = string.Empty;
    public String Role { get; set; } = string.Empty;
    public String? RefreshToken { get; set; }
    public DateTime? RefreshTokenExpiryTime { get; set; }
}