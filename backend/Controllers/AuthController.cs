using backend.Data;
using backend.Services;
using Microsoft.AspNetCore.Mvc;
using backend.Dtos;
using backend.Models;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace backend.Controllers;

[ApiController]
[Route("auth")]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly PasswordService _passwords;
    private readonly TokenService _tokens;

    public AuthController(AppDbContext db, PasswordService passwords, TokenService tokens)
    {
        _db = db;
        _passwords = passwords;
        _tokens = tokens;
    }

    [Authorize]
    [HttpGet("me")]
    public async Task<ActionResult<AuthRequest.AuthUser>> getUser()
    {
        var sub = User.FindFirstValue(ClaimTypes.NameIdentifier);

        if (string.IsNullOrWhiteSpace(sub))
            return Unauthorized(new ProblemDetails {Title ="Missing user id claim"});

        if (!Guid.TryParse(sub, out var publicId))
            return Unauthorized(new ProblemDetails {Title ="Invalid sub claim"});

        var AuthUser = await _db.Users
            .Where(u => u.PublicId == publicId)
            .Select(u => new AuthRequest.AuthUser(u.UserName ?? "UserName"))
            .SingleOrDefaultAsync();

        if (AuthUser is null)
            return Unauthorized(new ProblemDetails {Title = "User no longer exists"});

        return Ok(AuthUser);

    }

    [HttpPost("register")]
    public async Task<ActionResult<AuthRequest.AuthResponse>> Register(RegisterRequest req)
    {
        var email = req.Email.Trim().ToLower();

        //Check if User already exists
        var exists = await _db.Users.AnyAsync(u => u.Email == email);
        if (exists) return BadRequest(new ProblemDetails {
            Title = "Email is already registered",
        });

        //Add new user to DB
        var user = new User
        {
            PublicId = Guid.NewGuid(),
            Email = email,
            PasswordHash = _passwords.Hash(req.Password)
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        var token = _tokens.CreateToken(user);

        Response.Cookies.Append(
            "access_token",
            token,
            new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.Lax,
                Expires = DateTimeOffset.UtcNow.AddHours(1)
            }
        );

        return Ok(new AuthRequest.AuthResponse("Successfully registered"));
    }

    [HttpPost("login")]
    public async Task<ActionResult<AuthRequest.AuthResponse>> Login(LoginRequest req)
    {
        var email = req.Email.Trim().ToLower();

        var user = await _db.Users.SingleOrDefaultAsync(u => u.Email == email);
        if (user is null) return Unauthorized(new ProblemDetails {Title = "Invalid credentials"});

        var ok = _passwords.Verify(user.PasswordHash, req.Password);
        if (!ok) return Unauthorized(new ProblemDetails {Title = "Invalid Credentials"});

        var token = _tokens.CreateToken(user);

        Response.Cookies.Append(
            "access_token",
            token,
            new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.Lax,
                Expires = DateTime.UtcNow.AddHours(1)
            }
        );
        return Ok(new AuthRequest.AuthResponse("Login successful"));
    }
}