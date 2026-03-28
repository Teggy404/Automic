using System.Text.Json.Serialization;
using CsvHelper.Configuration.Attributes;

namespace backend.Dtos;

public class JobRequest
{
    public record DiagnoseResponse(List<string> JobList);
    public record DiagnoseRequest(string? ObdCode, string Description, string VehiclePublicId);
    public record ExpandKeywordResponse(
        [property: JsonPropertyName("component_hints")] List<string> ComponentHints,
        [property: JsonPropertyName("keywords")] List<string> Keywords
    );

    public record GenerateJobsResponse(
        [property: JsonPropertyName("jobs")] List<string> JobNames
    );
}