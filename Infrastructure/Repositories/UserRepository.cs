using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Application.Contracts;
using Application.DTOs;
using Domain.Entities;
using Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Infrastructure.Repositories;

public class UserRepository : IUser
{
    private readonly AppDbContext _dbContext;
    private readonly IConfiguration _configuration;

    public UserRepository(AppDbContext dbContext, IConfiguration configuration)
    {
        _dbContext = dbContext;
        _configuration = configuration;
    }
    public async Task<RegistrationResponse> RegisterUserAsync(RegisterUserDTO registerUserDto)
    {
        var getUser = await FindUserByEmail(registerUserDto.Email!);
        if (getUser != null)
        {
            return new RegistrationResponse(false, "User already registered");
        }

        _dbContext.Users.Add(new ApplicationUser
        {
            Name = registerUserDto.Name,
            Email = registerUserDto.Email,
            Password = BCrypt.Net.BCrypt.HashPassword(registerUserDto.Password),
        });
        await _dbContext.SaveChangesAsync();
        return new RegistrationResponse(true, "Registration completed");

    }

    private async Task<ApplicationUser> FindUserByEmail(string email)
    {
        return await _dbContext.Users.FirstOrDefaultAsync(u => u.Email == email);
    }
    public async Task<LoginResponse> LoginUserAsync(LoginDTO loginDto)
    {
        var getUser = await FindUserByEmail(loginDto.Email!);
        if (getUser == null)
        {
            return new LoginResponse(false, "User Not Found");
        }

        bool checkPassword = BCrypt.Net.BCrypt.Verify(loginDto.Password, getUser.Password);
        if (!checkPassword)
        {
            return new LoginResponse(false, "Invalid credentials");

            
        }
        return new LoginResponse(true, "Login Successful", GenerateJWTToken(getUser));
    }

    private string GenerateJWTToken(ApplicationUser user)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var userClaims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Name!),
            new Claim(ClaimTypes.Email, user.Email!)
        };
        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: userClaims,
            expires: DateTime.Now.AddDays(5),
            signingCredentials: credentials
        );
        return new JwtSecurityTokenHandler().WriteToken(token);
    } 
}