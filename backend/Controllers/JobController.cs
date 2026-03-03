using backend.Services;
using Microsoft.AspNetCore.Mvc;

namespace backend.Controllers;

[ApiController]
[Route("job")]
public class JobController : ControllerBase
{

    public JobService _jobService;

    public JobController(JobService jobService)
    {
        _jobService = jobService;
    }

    [HttpGet("diagnose")]
    public async Task<ActionResult<List<string>>> GetDiagnosis(CancellationToken ct)
    {
        var results = await _jobService.GetDiagnosticStrings(ct);
        return Ok(results);
    }

}