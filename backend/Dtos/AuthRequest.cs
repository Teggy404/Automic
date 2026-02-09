namespace backend.Dtos;

public class AuthRequest
{
    public record RegisterRequest(String Email, String Password);
    public record LoginRequest(String Email, String Password);
    public record AuthResponse(String Message);
    public record AuthUser(String UserName);
}
