using Microsoft.AspNetCore.Mvc.Routing;

namespace backend.Models;

public class Video
{
    public int Id { get; set; }
    public Guid PublicId { get; set; }
    public required string Url { get; set; }
    public int JobId { get; set; }
    public required Job Job { get; set; }
}