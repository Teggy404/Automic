using Microsoft.AspNetCore.Identity;

namespace backend.Services;

public class PasswordService
{
    private readonly PasswordHasher<object> _hasher = new PasswordHasher<object>();

    public string Hash(string password) 
    {
        return _hasher.HashPassword(new object(), password);
    }

    public bool Verify(string hashedPassword, string providedPassword)
    {
        return _hasher.VerifyHashedPassword(new object(), hashedPassword, providedPassword) == PasswordVerificationResult.Success;
    }
}