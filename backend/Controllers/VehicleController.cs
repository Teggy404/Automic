using backend.Services;
using Backend.Dtos;
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
    public async Task<ActionResult<List<VehicleDataRequest.Make>>> GetMakes(CancellationToken ct)
    {
        var makes = await _vehicleDataService.GetAllMakesRawJson(ct);
        return Ok(makes);
    }
}