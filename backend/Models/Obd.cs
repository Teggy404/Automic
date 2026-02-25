namespace backend.Models;

public class Obd
{
    public int Id { get; set; }
    public required string code { get; set; }
    public string? Make { get; set; }
    public required string Description { get; set; }

}