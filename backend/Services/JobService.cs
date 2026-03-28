using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using backend.Data;
using backend.Dtos;
using backend.Models;
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
    public async Task<List<string>> GetJobNames(JobRequest.DiagnoseRequest req)
    {
        JobRequest.ExpandKeywordResponse ExpandedDescription = await ExpandKeywords(req.ObdCode, req.Description);

        //Check and validate car
        bool parsed = Guid.TryParse(req.VehiclePublicId, out Guid publicId);
        if (!parsed) throw new InvalidOperationException("Invalid vehicle Id");
        var vehicle = await _db.Cars.FirstOrDefaultAsync(c => c.PublicId == publicId);
        if (vehicle is null) throw new InvalidOperationException("Vehicle does not exist");

        //search tsbs by car filter by components and order by matching key words

        List<string> tsbsByComponent = await _db.Tsbs
            .Where(t => t.CarId == vehicle.Id && ExpandedDescription.ComponentHints.Any(c => t.Component.Contains(c)))
            .Select(t => t.Summary)
            .ToListAsync();

        
        var orderedTsbs = tsbsByComponent
            .Select(t => new
            {
                tsb = t,
                score = ExpandedDescription.Keywords.Count(k => t.ToLower().Contains(k.ToLower()))
            })
            .OrderByDescending(r => r.score)
            .Take(10);

        string vehicleString = $"{vehicle.Make} {vehicle.Model} {vehicle.Year}";

        //call get jobs

        JobRequest.GenerateJobsResponse generateJobsResponse = await GenerateJobs(
            Tsbs: orderedTsbs.Select(t=>t.tsb).ToList(),
            ObdCode: req.ObdCode,
            ObdDescription: null, 
            VehicleString: vehicleString,
            Description: req.Description
        );

        //return jobs
        return generateJobsResponse.JobNames;
    }

    public async Task<JobRequest.GenerateJobsResponse> GenerateJobs(List<string> Tsbs, string? ObdCode, string? ObdDescription, string Description, string VehicleString)
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

                            Your job is to read the user's symptom description, optional OBD information, and retrieved TSB summaries, then generate a short list of possible service job names.

                            You must stay grounded in the provided information.
                            Do not invent repairs that are not reasonably supported by the symptom description, OBD information, or TSB summaries.

                            Rules:
                            1. Output only possible job names, not explanations.
                            2. Do not claim certainty. These are possible jobs, not confirmed repairs.
                            3. Prefer practical service-style job names that would be useful for downstream search.
                            4. Keep job titles concise, clear, and specific enough to be useful.
                            5. Do not output duplicate jobs.
                            6. If the evidence is weak or ambiguous, prefer broader diagnostic or inspection-style jobs over replacement-style jobs.
                            7. Do not include markdown, code fences, commentary, numbering, or extra text.
                            8. Output only valid JSON matching the required schema.

                            Guidance:
                            - Good job title style examples:
                            - Inspect ignition coil and spark plugs
                            - Diagnose brake noise source
                            - Inspect wheel bearing
                            - Check transmission fluid condition
                            - Diagnose power window circuit

                            Use the TSB summaries as supporting evidence for plausible jobs.
                            Do not treat the TSBs as guaranteed proof of the exact repair.
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
            Vehicle: {VehicleString}
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

    public async Task<JobRequest.ExpandKeywordResponse> ExpandKeywords(string? ObdCode, string Description)
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