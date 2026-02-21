using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore;
using CsvHelper;
using backend.Data;
using System.Globalization;
using CsvHelper.Configuration;
class SeedVehicles
{
    static async Task Main(string[] args)
    {
        var configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", optional: true)
            .AddUserSecrets<SeedVehicles>()
            .Build();
        
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseNpgsql(configuration["ConnectionStrings:DefaultConnection"])
            .Options;
        
        using var db = new AppDbContext(options);

        var readerConfig = new CsvConfiguration(CultureInfo.InvariantCulture)
        {   
            HasHeaderRecord = true    
        };

        using var reader = new StreamReader("/home/oscar/Projects/Automic/tools/Supported_Models.csv");
        using var csvReader = new CsvReader(reader, readerConfig);

        //Write rows to database
        Console.WriteLine("Saving Data to DB...");
        int count = 0;

        csvReader.Read();
        csvReader.ReadHeader();
        
        while (csvReader.Read())
        {
            var Make = csvReader.GetField("Make")?.Trim();
            var Model = csvReader.GetField("Model")?.Trim();
            var Year = csvReader.GetField("Year")?.Trim();

            if(Year == "9999") continue;
            if(string.IsNullOrWhiteSpace(Make) || 
               string.IsNullOrWhiteSpace(Model) ||
               string.IsNullOrWhiteSpace(Year)) continue;

            db.Add( new Car {
                    PublicId = Guid.NewGuid(),
                    Make = Make,
                    Model = Model,
                    Year = Year,
                });

             count++;

            if (count >= 10) {
                await db.SaveChangesAsync();
                db.ChangeTracker.Clear();
                count = 0;
            }
        }
        await db.SaveChangesAsync();
        Console.WriteLine("Done.");
    }
}