using backend.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace backend.Controllers;

[ApiController]
[Route("Vehicle")]
public  class VehicleController: ControllerBase
{
    private readonly VehicleDataService _vehicleDataService;
    
    public VehicleController(VehicleDataService vehicleDataService)
    {
        _vehicleDataService = vehicleDataService;
    }

    [HttpGet("makes")]
    public async Task<ActionResult> GetMakes(CancellationToken ct)
    {
        var json = await _vehicleDataService.GetAllMakesRawJson(ct);
        return Content(json, "application/json");
    }
}