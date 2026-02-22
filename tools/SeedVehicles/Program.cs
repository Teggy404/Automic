using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore;
using CsvHelper;
using backend.Data;
using backend.Models;
using System.Globalization;
using CsvHelper.Configuration;
using System.Data;
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

    }

    static async Task SeedTSB(AppDbContext db, string path)
    {
        Dictionary<string, int> validCars = new Dictionary<string, int>();

        var cars = await db.Cars.ToListAsync();
        
        if (cars.Count == 0)
        {
            Console.WriteLine("Nothing pulled from db.");
            return;
        }  

        for(int i = 0; i < cars.Count; i++)
        {
            var key = $"{cars[i].Make}|{cars[i].Model}|{cars[i].Year}";
            validCars.Add(key, cars[i].Id);
        }

        var readerConfig = new CsvConfiguration(CultureInfo.InvariantCulture)
        {
            Delimiter = "\t",
            HasHeaderRecord = false,
            MissingFieldFound = null,
            BadDataFound = null
        };

        using var reader = new StreamReader(path);
        using var csvReader = new CsvReader(reader, readerConfig);

        Console.WriteLine($"Reading Tsbs from {path}");
        
        int count = 0;

        while (csvReader.Read())
        {
            var nhtsaid = csvReader.GetField(0)?.Trim();
            var tsbid = csvReader.GetField(3)?.Trim();
            var communication = csvReader.GetField(6)?.Trim();
            var make = csvReader.GetField(7)?.Trim();
            var model = csvReader.GetField(8)?.Trim();
            var year = csvReader.GetField(9)?.Trim();
            var component = csvReader.GetField(10)?.Trim();
            var summary = csvReader.GetField(13)?.Trim();

            if (string.IsNullOrWhiteSpace(nhtsaid) ||
                string.IsNullOrWhiteSpace(tsbid) ||
                string.IsNullOrWhiteSpace(communication) ||
                string.IsNullOrWhiteSpace(make) ||
                string.IsNullOrWhiteSpace(model) ||
                string.IsNullOrWhiteSpace(year) ||
                string.IsNullOrWhiteSpace(component) ||
                string.IsNullOrWhiteSpace(summary)
                ) continue;
            
            if (communication == "Over The Air" ||
                communication == "Emissions" ||
                communication == "Other"
                ) continue;

            var key = $"{make}|{model}|{year}";

            if (validCars.ContainsKey(key))
            {
                db.Add(new Tsb
                {
                    PublicId = Guid.NewGuid(),
                    NhtsaId = int.Parse(nhtsaid),
                    TsbId = tsbid,
                    Component = component,
                    Summary = summary,
                    CarId = validCars[key]
                });
                count++;
            }
            

            if(count >= 10)
            {
                await db.SaveChangesAsync();
                db.ChangeTracker.Clear();
                count = 0;
            }
        }
        
        await db.SaveChangesAsync();
        Console.WriteLine("Done.");
    }

    static async Task SeedCars(AppDbContext db, string path)
    {

        var readerConfig = new CsvConfiguration(CultureInfo.InvariantCulture)
        {   
            HasHeaderRecord = true    
        };

        using var reader = new StreamReader(path);
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