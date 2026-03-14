using System.Text.Json;
using backend.Data;
using backend.Dtos;
using Google.GenAI;
using Google.GenAI.Types;
using Microsoft.EntityFrameworkCore;

namespace backend.Services;

public class JobService
{
    public AppDbContext _db;

    public JobService(AppDbContext db)
    {
        _db = db;
    }
    public async Task<string> GetJobNames(JobRequest.DiagnoseRequest req)
    {
        JobRequest.ExpandKeywordResponse ExpandedDescription = await ExpandKeywords(req.ObdCode, req.Description);

        //Check and validate car
        bool parsed = Guid.TryParse(req.VehicleId, out Guid publicId);
        if (!parsed) throw new InvalidOperationException("Invalid vehicle Id");
        bool exists = await _db.Cars.AnyAsync(c => c.PublicId == publicId);
        if (!exists) throw new InvalidOperationException("Vehicle does not exist");

        //search tsbs by car filter by components and order by matching key words



        //call get jobs

        //return jobs
        return JsonSerializer.Serialize(ExpandedDescription);
    }

    public async Task<JobRequest.GenerateJobsResponse> GenerateJobs(List<string> Tsbs, string ObdCode, string ObdDescription, string Description, string vehicleString)
    {
        var client = new Client();

        var configuration = new GenerateContentConfig
        {
            ResponseMimeType = "application/json",
            SystemInstruction = new Content
            {
                Parts = [
                    new Google.GenAI.Types.Part{
                        Text = """
                            You are a grounded automotive job recommendation generator.

                            Your job is to read the user's symptom description, optional OBD information, and retrieved TSB evidence, then produce a structured list of possible service jobs.

                            You must stay grounded in the provided evidence.
                            You must not invent repairs that are not reasonably supported by the provided TSBs or OBD information.

                            Rules:
                            1. Every recommended job must reference at least one provided TSB id in evidence_tsb_ids, unless the job is supported only by the provided OBD information.
                            2. Do not claim certainty. These are possible jobs, not confirmed repairs.
                            3. Prefer practical service-style job names that would be useful for downstream YouTube and parts searches.
                            4. Keep job titles concise and clear.
                            5. Generate youtube_query and parts_query for each job.
                            6. If multiple TSBs point to the same kind of repair, consolidate them into one reasonable job recommendation.
                            7. Do not output duplicate jobs.
                            8. Do not include markdown, code fences, commentary, or extra explanation.
                            9. Output only valid JSON matching the required schema.
                            10. If the evidence is weak or ambiguous, return broader job recommendations and lower confidence.
                            11. If there is not enough evidence for a specific repair, prefer diagnostic/inspection-style jobs over replacement-style jobs.

                            Guidance:
                            - Good job titles are practical, search-friendly, and not overly verbose.
                            - Examples of acceptable job title styles:
                            - Inspect shift solenoids
                            - Diagnose power window motor circuit
                            - Inspect ignition coil and spark plug
                            - Check transmission fluid condition
                            - Diagnose brake vibration source

                            Do not treat TSBs as guaranteed proof of the exact repair for this vehicle.
                            Use them as supporting evidence for plausible job recommendations.
                        """
                    }
                ]
            },
            ResponseJsonSchema = new
            {
                type = "object",
                properties = new
                {
                    jobs = new
                    {
                        type = "array",
                        items = new { type = "string" }
                    }
                },
                required = new[] { "jobs" }
            }
        };

        string contentString = $"""
            Symptom Description: {Description}
            Vehicle: {vehicleString}
            OBD Code: {ObdCode}
            OBD Description: {ObdDescription}
            Tsbs: {string.Join(System.Environment.NewLine + "  ", Tsbs)}
        """;

        var response = await client.Models.GenerateContentAsync(
            model: "gemini-2.5-flash-lite",
            contents: contentString,
            config: configuration
        );

        string? stringResponse = response?.Candidates?[0].Content?.Parts?[0].Text;
        if (string.IsNullOrWhiteSpace(stringResponse)) throw new InvalidOperationException("No JSON returned from model");
        JobRequest.GenerateJobsResponse? deserialized = JsonSerializer.Deserialize<JobRequest.GenerateJobsResponse>(stringResponse);
        if (deserialized is null) throw new InvalidOperationException("Failed to deserialize JSON reponse");

        return deserialized;
    }

    public async Task<JobRequest.ExpandKeywordResponse> ExpandKeywords(string ObdCode, string Description)
    {
        var client = new Client();

        var configuration = new GenerateContentConfig
        {
            ResponseMimeType = "application/json",
            SystemInstruction = new Content
            {
                Parts =
                [
                    new Google.GenAI.Types.Part
                    {
                        Text = """
                            You are a vehicle symptom-to-retrieval planner.

                            Your job is to convert a user's symptom description into a structured search plan that will later be used to retrieve technical service bulletins (TSBs) and related diagnostic information.

                            You are NOT providing a final diagnosis.
                            You are NOT recommending repairs.
                            You are ONLY generating structured retrieval guidance.

                            Rules:
                            1. Be conservative. Do not claim certainty unless the symptom strongly suggests it.
                            2. Prefer broad, realistic automotive subsystem categories over overly specific parts unless the symptom clearly implies them.
                            3. Generate search phrases that are likely to appear in TSB summaries or service language.
                            4. Include multiple plausible interpretations when the symptom is ambiguous.
                            5. Do not invent unsupported facts about the vehicle.
                            6. Output only valid JSON that matches the required schema.
                            7. Do not include markdown, code fences, comments, or extra explanation.
                            8. If the user gives very little information, still return the best broad retrieval plan possible.

                            Guidance for keywords:
                            - Include phrases a technician or TSB might use, not just the user's exact wording.
                            - Expand symptom language into likely service-style phrasing.
                            - Include synonyms and alternate phrasings when useful.
                            - Keep phrases short and searchable.

                            Guidance for components:
                            - Return broad subsystem/component hints.
                            - Examples of the style of component hints:
                            - AUTOMATIC TRANSMISSION
                            - ELECTRICAL SYSTEM
                            - STEERING
                            - ENGINE
                            - FUEL SYSTEM
                            - SERVICE BRAKES
                            - Prefer 3 to 8 component hints unless the symptom is extremely narrow.

                            If an OBD code and/or OBD description is provided, use it as an additional signal, but do not let it completely override the user's symptom description.
                            """
                    }
                ]
            },
            ResponseJsonSchema = new
            {
                type = "object",
                properties = new
                {
                    component_hints = new
                    {
                        type = "array",
                        items = new { type = "string" }
                    },
                    keywords = new
                    {
                        type = "array",
                        items = new { type = "string" }
                    }
                },
                required = new[] { "component_hints", "keywords" }
            }

        };

        string contentString =
        $"""
            OBD Code: {ObdCode}
            Symptom Description: {Description}
        """;

        var response = await client.Models.GenerateContentAsync(
            model: "gemini-2.5-flash-lite",
            contents: contentString,
            config: configuration
        );

        string? stringResponse = response?.Candidates?[0].Content?.Parts?[0].Text;
        if (string.IsNullOrWhiteSpace(stringResponse)) throw new InvalidOperationException("No JSON returned from model");

        JobRequest.ExpandKeywordResponse? deserialized = JsonSerializer.Deserialize<JobRequest.ExpandKeywordResponse>(stringResponse);
        if (deserialized is null) throw new InvalidOperationException("Failed to deserialize JSON response");

        return deserialized;
    }
}