using AuthenticationApp.Data;
using AuthenticationApp.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthenticationApp.Controllers;

[ApiController]
[Route("api/auth")]

public class AuthController : ControllerBase
{
    private readonly AuthenticationDbContext _context;
    private readonly IPasswordHasher<User> _passwordHasher;
    private readonly IConfiguration _configuration;
    public AuthController(
        AuthenticationDbContext context,
        IPasswordHasher<User> passwordHasher,
        IConfiguration configuration)
    {
        _context = context;
        _passwordHasher = passwordHasher;
        _configuration = configuration;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var normalizedEmail = request.Email.Trim().ToLowerInvariant();

        var emailExists = await _context.Users
            .AnyAsync(u => u.Email.ToLower() == normalizedEmail);

        if (emailExists)
        {
            return Conflict(new { message = "A user with this email already exists" });
        }

        var user = new User
        {
            FullName = request.FullName.Trim(),
            Email = normalizedEmail,
            CreatedAt = DateTime.UtcNow
        };

        user.PasswordHash = _passwordHasher.HashPassword(user, request.Password);

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        return CreatedAtAction(
            nameof(GetUserById),
            new { id = user.UserID },
            new
            {
                userId = user.UserID,
                fullName = user.FullName,
                email = user.Email
            });
    }

    [HttpGet("users/{id:int}")]
    public async Task<IActionResult> GetUserById(int id)
    {
        var user = await _context.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.UserID == id);

        if (user is null)
        {
            return NotFound();
        }

        return Ok(new
        {
            userId = user.UserID,
            fullName = user.FullName,
            email = user.Email
        });
    }


    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var normalizedEmail = request.Email.Trim().ToLowerInvariant();

        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Email.ToLower() == normalizedEmail);

        if (user is null)
        {
            return Unauthorized(new
            {
                message = "Invalid email or password."
            });
        }

        var passwordVerificationResult = _passwordHasher.VerifyHashedPassword(
            user,
            user.PasswordHash,
            request.Password);

        if (passwordVerificationResult == PasswordVerificationResult.Failed)
        {
            return Unauthorized(new
            {
                message = "Invalid email or password."
            });
        }

        var jwtSettings = _configuration.GetSection("JwtSettings").Get<JwtSettings>()!;

        var claims = new[]
        {
        new Claim(JwtRegisteredClaimNames.Sub, user.UserID.ToString()),
        new Claim(JwtRegisteredClaimNames.Email, user.Email),
        new Claim("fullName", user.FullName)
    };

        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(jwtSettings.SecretKey));

        var credentials = new SigningCredentials(
            key,
            SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: jwtSettings.Issuer,
            audience: jwtSettings.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(jwtSettings.ExpiryMinutes),
            signingCredentials: credentials);

        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

        return Ok(new
        {
            userId = user.UserID,
            fullName = user.FullName,
            email = user.Email,
            token = tokenString,
            expiresInMinutes = jwtSettings.ExpiryMinutes,
            message = "Login successful."
        });
    }

    [Authorize]
    [HttpPut("change-password")]
    public async Task<IActionResult> ChangePassword(
    [FromBody] ChangePasswordRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (!int.TryParse(userIdClaim, out int userId))
        {
            return Unauthorized(new
            {
                message = "Invalid or expired token."
            });
        }

        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.UserID == userId);

        if (user is null)
        {
            return NotFound(new
            {
                message = "User not found."
            });
        }

        var currentPasswordResult = _passwordHasher.VerifyHashedPassword(
            user,
            user.PasswordHash,
            request.CurrentPassword);

        if (currentPasswordResult == PasswordVerificationResult.Failed)
        {
            return BadRequest(new
            {
                message = "The current password is incorrect."
            });
        }

        if (request.CurrentPassword == request.NewPassword)
        {
            return BadRequest(new
            {
                message = "The new password must be different from the current password."
            });
        }

        user.PasswordHash = _passwordHasher.HashPassword(
            user,
            request.NewPassword);

        await _context.SaveChangesAsync();

        return Ok(new
        {
            message = "Password changed successfully."
        });
    }

    [Authorize]
    [HttpPut("update-profile")]
    public async Task<IActionResult> UpdateProfile(
    [FromBody] UpdateProfileRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (!int.TryParse(userIdClaim, out int userId))
        {
            return Unauthorized(new
            {
                message = "Invalid or expired token."
            });
        }

        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.UserID == userId);

        if (user is null)
        {
            return NotFound(new
            {
                message = "User not found."
            });
        }

        user.FullName = request.FullName.Trim();

        await _context.SaveChangesAsync();

        return Ok(new
        {
            userId = user.UserID,
            fullName = user.FullName,
            email = user.Email,
            message = "Profile updated successfully."
        });
    }

    [Authorize]
    [HttpGet("profile")]
    public IActionResult GetProfile()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var email = User.FindFirst(ClaimTypes.Email)?.Value;
        var fullName = User.FindFirst("fullName")?.Value;

        return Ok(new
        {
            userId = userId,
            fullName = fullName,
            email = email,
            message = "You are authenticated."
        });
    }
}
