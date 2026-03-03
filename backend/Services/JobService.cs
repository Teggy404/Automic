using backend.Data;
using Microsoft.VisualBasic;

namespace backend.Services;

public class JobService
{
    private readonly AppDbContext _db;

    public JobService(AppDbContext db)
    {
        _db = db;
    }

    public Task<List<string>> GetDiagnosticStrings(CancellationToken ct)
    {
        var dummyStrings = new List<string>();
        return Task.FromResult(dummyStrings);
    }
}