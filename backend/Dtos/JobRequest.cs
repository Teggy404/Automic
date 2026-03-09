using System.Text.Json.Serialization;
using backend.Migrations;

namespace backend.Dtos;

public class JobRequest {
    public record DiagnoseResponse(List<string> JobList);
    public record DiagnoseRequest(string ObdCode, string Description, string VehicleId);
    public record ExpandKeywordResponse(
        [property: JsonPropertyName("component_hints")]List<string> component_hints, 
        [property: JsonPropertyName("keywords")]List<string> keywords
    );

}