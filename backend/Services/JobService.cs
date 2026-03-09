using System.Security.Principal;
using System.Text.Json;
using backend.Data;
using backend.Dtos;
using backend.Models;
using Google.GenAI;
using Google.GenAI.Types;
using Microsoft.EntityFrameworkCore.Metadata.Internal;

namespace backend.Services;

public class JobService
{
    public AppDbContext _db;

    public JobService (AppDbContext db)
    {
        _db = db;
    }
    public async Task<string> GenerateJobs(JobRequest.DiagnoseRequest req)
    {
        JobRequest.ExpandKeywordResponse ExpandedDescription = await ExpandKeywords(req.ObdCode, req.Description);

        //Check and validate car

        //search tsbs by car filter by components and order by matching key words

        //call get jobs

        //return jobs
        return ExpandedDescription.ToString();
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
                        items = new {type = "string"}
                    },
                    keywords = new
                    {
                        type = "array",
                        items = new {type = "string"} 
                    }
                },
                required = new[] {"component_hints", "keywords"}
            }
            
        };

        string contentString = 
        $"""
            OBD Code: {ObdCode}
            Symtpton Description: {Description}
        """;

        var response = await client.Models.GenerateContentAsync(
            model:"gemini-2.5-flash-lite",
            contents: contentString,
            config: configuration
        );

        string? stringResponse = response?.Candidates?[0].Content?.Parts?[0].Text;
        if(string.IsNullOrWhiteSpace(stringResponse)) throw new InvalidOperationException("The model returned no JSON content.");

        JobRequest.ExpandKeywordResponse? deserialized = JsonSerializer.Deserialize<JobRequest.ExpandKeywordResponse>(stringResponse);
        if(deserialized is null) throw new InvalidOperationException("Failed to deserialize JSON response");

        return deserialized;
    }
}