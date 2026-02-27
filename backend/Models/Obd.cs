namespace backend.Models;

public class Obd
{
    public int Id { get; set; }
    public Guid PublicId { get; set; }
    public required string Code { get; set; }
    public string? Make { get; set; }
    public required string Description { get; set; }

}