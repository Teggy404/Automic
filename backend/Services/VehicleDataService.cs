using Microsoft.AspNetCore.Mvc;

namespace backend.Services;
public class VehicleDataService
{
    private readonly IHttpClientFactory _httpClientFactory;

    public VehicleDataService(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    public async Task<string> GetAllMakesRawJson(CancellationToken ct)
    {
        var client = _httpClientFactory.CreateClient("vpic");

        using var response = await client.GetAsync("GetAllMakes?format=json", ct);

        response.EnsureSuccessStatusCode();

        return await response.Content.ReadAsStringAsync(ct);
    }
}