using backend.Services;
using backend.Dtos;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

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

    [Authorize]
    [HttpGet("diagnose")]
    public async Task<ActionResult<List<string>>> GetJobList(JobRequest.DiagnoseRequest req, CancellationToken ct)
    {

        List<string> testString = await _jobService.GetJobNames(req);
        return Ok(testString);
    }
}
