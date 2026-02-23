using backend.Data;
using Backend.Dtos;
using Microsoft.EntityFrameworkCore;

namespace backend.Services;
public class VehicleDataService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly AppDbContext _db;
    public VehicleDataService(AppDbContext db, IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
        _db = db;
    }

    public async Task<List<VehicleDataRequest.VpicMake>> GetAllMakesRawJson(CancellationToken ct)
    {
        var client = _httpClientFactory.CreateClient("vpic");

        var vpic = 
            await client.GetFromJsonAsync<VehicleDataRequest.VpicMakes<VehicleDataRequest.VpicMakesEntry>>(
                "GetAllMakes?format=json",
                ct
            );

        if(vpic is null) return [];

        return vpic.Results.Select(m => new VehicleDataRequest.VpicMake(m.Make_ID, m.Make_Name)).OrderBy(m => m.Name).ToList();
    }

    public async Task<List<VehicleDataRequest.VpicModel>> GetAllModelsRawJson(CancellationToken ct, string makeId)
    {
        var client = _httpClientFactory.CreateClient("vpic");

        var vpic = 
            await client.GetFromJsonAsync<VehicleDataRequest.VpicModels>(
                $"GetModelsForMakeId/{makeId}?format=json",
                ct
            );
        if (vpic is null) return [];
        return vpic.Results.Select(m => new VehicleDataRequest.VpicModel(m.Model_ID, m.Model_Name)).OrderBy(m => m.Name).ToList();
    }

    public async Task<List<VehicleDataRequest.Make>> GetAllDbMakes(CancellationToken ct)
    {
        var makes = await _db.Cars
            .Select(c => new VehicleDataRequest.Make(c.Make))
            .Distinct()
            .ToListAsync(ct);

        if(makes == null) return [];
        return makes;
    }

    public async Task<List<VehicleDataRequest.Model>> GetModelsByMake(CancellationToken ct, string make)
    {
        var models = await _db.Cars
            .Where(c => c.Make == make)
            .Select(c => new VehicleDataRequest.Model(c.Model))
            .Distinct()
            .ToListAsync(ct);
        
        if(models == null) return [];
        return models;
    }

    public async Task<List<VehicleDataRequest.Year>> GetYearsByModelMake(CancellationToken ct, string make, string model)
    {
        var years = await _db.Cars
            .Where(c => c.Make == make && c.Model == model)
            .OrderBy(c => c.Year)
            .Select(c => new VehicleDataRequest.Year(c.PublicId, c.Year))
            .ToListAsync(ct);

        if(years == null) return [];
        return years;
    } 
}