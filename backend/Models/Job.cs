using Microsoft.Extensions.Configuration.UserSecrets;

namespace backend.Models;
  
public class Job
{
    public int Id { get; set; }
    public Guid PublicId { get; set; }
    public int UserId { get; set; }
    public required User User { get; set;}
    public int CarId { get; set; }
    public required Car Car { get; set; }
    public List<Part> Parts {get; set;} = new();
    public List<Video> Videos { get; set; } = new();
}