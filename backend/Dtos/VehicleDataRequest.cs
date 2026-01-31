
namespace Backend.Dtos;
public class VehicleDataRequest
{
    public record VpicMakes<T>( List<T> Results );
    public record VpicMakesEntry(int Make_ID, string Make_Name);
    public record Make(int Id, string Name);

}