using Microsoft.VisualBasic;

namespace backend.Models;

public class Car
{
    public int Id {get; set;}
    public Guid PublicId {get; set;}
    public required string Make {get; set;}
    public required string Model {get; set;}
    public required string Year {get; set;}
    public List<Tsb> Tsbs {get; set;} = new();
}