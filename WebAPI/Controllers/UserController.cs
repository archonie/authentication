using Application.Contracts;
using Application.DTOs;
using Microsoft.AspNetCore.Mvc;

namespace WebAPI.Controllers;

[Route("api/[controller]")]
[ApiController]
public class UserController : ControllerBase    
{
    private readonly IUser _user;

    public UserController(IUser user)
    {
        _user = user;
    }

    [HttpPost("login")]
    public async Task<ActionResult<LoginResponse>> LogUserIn(LoginDTO loginDto)
    {
        var result = await _user.LoginUserAsync(loginDto);
        return Ok(result);
    }
    
    [HttpPost("register")]
    public async Task<ActionResult<LoginResponse>> RegisterUser(RegisterUserDTO registerUserDto)
    {
        var result = await _user.RegisterUserAsync(registerUserDto);
        return Ok(result); 
    }
}