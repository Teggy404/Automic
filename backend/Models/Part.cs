namespace backend.Models;

public class Part
{
    public int Id { get; set; }
    public Guid PublicId { get; set; }
    public string? TrackingNumber { get; set; }
    public required string Status { get; set; }
    public int JobId { get; set; }
    public required Job Job { get; set; }
}