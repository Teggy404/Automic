
namespace Backend.Dtos;
public class VehicleDataRequest
{
    //VPIC Makes
    public record VpicMakes<T>( List<T> Results );
    public record VpicMakesEntry(int Make_ID, string Make_Name);
    public record VpicMake(int Id, string Name);

    //VPIC Models
    public record VpicModels(List<VpicModelEntry> Results);
    public record VpicModelEntry(int Model_ID, string Model_Name);
    public record VpicModel(int Id, string Name);

    // DB
    public record Make(string Name);
    public record Model(string Name);
    public record Year(Guid Id, string StringYear);
}   