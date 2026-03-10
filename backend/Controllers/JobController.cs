using backend.Services;
using backend.Dtos;
using Microsoft.AspNetCore.Mvc;

namespace backend.Controllers;

[ApiController]
[Route("Job")]
public class JobController : ControllerBase
{
    public JobService _jobService;

    public JobController(JobService jobService)
    {
        _jobService = jobService;
    }

    [HttpGet("diagnose")]
    public async Task<ActionResult<string>> GetJobList([FromBody] JobRequest.DiagnoseRequest req, CancellationToken ct)
    {

        string testString = await _jobService.GenerateJobs(req);
        return testString;
    }
}
