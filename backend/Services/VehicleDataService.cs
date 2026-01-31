using Backend.Dtos;
using Microsoft.AspNetCore.Mvc;

namespace backend.Services;
public class VehicleDataService
{
    private readonly IHttpClientFactory _httpClientFactory;

    public VehicleDataService(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    public async Task<List<VehicleDataRequest.Make>> GetAllMakesRawJson(CancellationToken ct)
    {
        var client = _httpClientFactory.CreateClient("vpic");

        var vpic = 
            await client.GetFromJsonAsync<VehicleDataRequest.VpicMakes<VehicleDataRequest.VpicMakesEntry>>(
                "GetAllMakes?format=json",
                ct
            );

        if(vpic is null) return [];

        return vpic.Results.Select(m => new VehicleDataRequest.Make(m.Make_ID, m.Make_Name)).OrderBy(m => m.Name).ToList();
    }
}