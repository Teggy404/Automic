using backend.Services;
using Backend.Dtos;
using Microsoft.AspNetCore.Mvc;

namespace backend.Controllers;

[ApiController]
[Route("vehicle")]
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
        var makes = await _vehicleDataService.GetAllDbMakes(ct);
        return Ok(makes);
    }

    [HttpGet("models/{make}")]
    public async Task<ActionResult<List<VehicleDataRequest.Model>>> GetModels(CancellationToken ct, string make)
    {
        var models = await _vehicleDataService.GetModelsByMake(ct, make);
        return Ok(models);
    }

    [HttpGet("years/{make}/{model}")]
    public async Task<ActionResult<List<VehicleDataRequest.Year>>> GetYears(CancellationToken ct, string make, string model)
    {
        var years = await _vehicleDataService.GetYearsByModelMake(ct, make, model);
        return Ok(years);
    }
}