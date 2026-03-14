using System.Text.Json.Serialization;
using backend.Migrations;
using CsvHelper.Expressions;
using Newtonsoft.Json;

namespace backend.Dtos;

public class JobRequest
{
    public record DiagnoseResponse(List<string> JobList);
    public record DiagnoseRequest(string? ObdCode, string Description, string VehicleId);
    public record ExpandKeywordResponse(
        [property: JsonPropertyName("component_hints")] List<string> component_hints,
        [property: JsonPropertyName("keywords")] List<string> keywords
    );

    public record GenerateJobsResponse(
        [property: JsonPropertyName("jobs")] List<string> job_list
    );
}