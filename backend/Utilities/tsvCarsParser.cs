using System.Globalization;
using System.Runtime.InteropServices;
using CsvHelper;
using CsvHelper.Configuration;

class CarParser {
    void Main()
    {
        var readConfig = new CsvConfiguration(CultureInfo.InvariantCulture)
        {
            Delimiter="\t",
            HasHeaderRecord=true
        };

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
        using var reader = new StreamReader("Path");
        using var csvReader = new CsvReader(reader, readConfig);

        using var writer = new StreamWriter("Path");
        using var csvWriter = new CsvWriter(writer, CultureInfo.InvariantCulture);

        //header
        csvWriter.WriteField("MAKE");
        csvWriter.WriteField("MODEL");
        csvWriter.WriteField("YEAR");
        csvWriter.NextRecord();

        while (csvReader.Read())
        {
            var Make = csvReader.GetField("Make")?.Trim();
            var Model = csvReader.GetField("Model")?.Trim();
            var Year = csvReader.GetField("Year")?.Trim();

        }
    }

    public class Car
    {
        public string Make { get; set; }
        public string Model { get; set; }
        public string Year { get; set; }
    }
}