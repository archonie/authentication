using Application.DTOs;

namespace Application.Contracts;

public interface IUser
{
    Task<RegistrationResponse> RegisterUserAsync(RegisterUserDTO registerUserDto);
    Task<LoginResponse> LoginUserAsync(LoginDTO loginDto);
}