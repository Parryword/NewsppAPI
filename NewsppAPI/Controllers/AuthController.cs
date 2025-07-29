using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using NewsppAPI.Entities;
using NewsppAPI.Models;
using NewsppAPI.Services;

namespace NewsppAPI.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController(IAuthService authService) : ControllerBase
{
    public static User user = new();

    [HttpPost("register")]
    public async Task<ActionResult<User>> Register(UserDto request)
    {
        var user = await authService.RegisterAsync(request);
        
        if (user == null)
        {
            return BadRequest("Username already exists");
        }
        
        return Ok(user);
    }

    [HttpPost("login")]
    public async Task<ActionResult<string>> Login(UserDto request)
    {
        var token = await authService.LoginAsync(request);

        if (token == null)
        {
            return BadRequest("Invalid username or password");       
        }
        
        return Ok(token);
    }
    
    [Authorize]
    [HttpGet]
    public IActionResult AuthenticatedOnlyEndpoint()
    {
        return Ok("You are authenticated");   
    }
    
    [Authorize(Roles = "Admin")]
    [HttpGet("admin")]
    public IActionResult AdminOnlyEndpoint()
    {
        return Ok("You are an admin");   
    }
}