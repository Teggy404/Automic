namespace backend.Models;

public class User
{
    public int Id { get; set; }
    public Guid PublicId { get; set; }
    public string Email { get; set; } = null!;
    public string PasswordHash { get; set; } = null!;
    public string? UserName { get; set; }
}
