using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using NewsppAPI.Data;
using NewsppAPI.Entities;
using NewsppAPI.Models;

namespace NewsppAPI.Services;

public class AuthService(UserDbContext context, IConfiguration configuration) : IAuthService
{
    public async Task<User?> RegisterAsync(UserDto request)
    {
        if (await context.Users.AnyAsync(u => u.Username == request.Username))
        {
            return null;
        }

        var user = new User();
        var hashedPassword = new PasswordHasher<User>()
            .HashPassword(user, request.Password);

        user.Username = request.Username;
        user.Password = hashedPassword;
        
        context.Users.Add(user);
        await context.SaveChangesAsync();

        return user;
    }

    public async Task<string?> LoginAsync(UserDto request)
    {
        var user = await context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);

        if (user == null)
        {
            return null;
        }

        if (new PasswordHasher<User>().VerifyHashedPassword(user, user.Password, request.Password) ==
            PasswordVerificationResult.Failed)
        {
            return null;
        }

        return CreateToken(user);
    }
    
    private string CreateToken(User user)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, user.Username),
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Role, user.Role)
        };

        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(configuration.GetValue<string>("AppSettings:Token")!));

        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

        var tokenDescriptor = new JwtSecurityToken(
            issuer: configuration.GetValue<string>("AppSettings:Issuer"),
            audience: configuration.GetValue<string>("AppSettings:Audience"),
            claims: claims,
            expires: DateTime.Now.AddDays(1),
            signingCredentials: creds
        );
        
        return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
    }
}