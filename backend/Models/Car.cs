namespace backend.Models;

public class Car
{
    public int id {get; set;}
    public Guid PublicId {get; set;}
    public string Make {get; set;}
    public string Model {get; set;}
    public string Year {get; set;}
}