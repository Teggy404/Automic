namespace backend.Models;
public class Tsb
{
    public int Id {get; set;}
    public Guid PublicId {get; set;}
    public int NhtsaId {get; set;}
    public required string TsbId {get; set;}
    public required string Component {get; set;}
    public required string Summary {get; set;}
    public Car Car {get; set;} = null!;
    public int CarId {get; set;}
} 