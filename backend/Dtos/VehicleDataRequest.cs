
namespace Backend.Dtos;
public class VehicleDataRequest
{
    //Makes
    public record VpicMakes<T>( List<T> Results );
    public record VpicMakesEntry(int Make_ID, string Make_Name);
    public record Make(int Id, string Name);

    //Models
    public record VpicModels(List<VpicModelEntry> Results);
    public record VpicModelEntry(int Model_ID, string Model_Name);
    public record Model(int Id, string Name);
}