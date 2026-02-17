using System.Globalization;
using System.Runtime.InteropServices;
using CsvHelper;
using CsvHelper.Configuration;

class CarParser
{
    static void Main(string[] args)
    {
        var readConfig = new CsvConfiguration(CultureInfo.InvariantCulture)
        {
            Delimiter = "\t",
            HasHeaderRecord = false
        };

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        using var reader = new StreamReader("/home/oscarsalsa/Downloads/TSBS_RECEIVED_2025-2026.txt");
        using var csvReader = new CsvReader(reader, readConfig);

        using var writer = new StreamWriter("/home/oscarsalsa/Projects/Automic/utilities/2025-2026-Processed.csv");
        using var csvWriter = new CsvWriter(writer, CultureInfo.InvariantCulture);

        //header
        csvWriter.WriteField("MAKE");
        csvWriter.WriteField("MODEL");
        csvWriter.WriteField("YEAR");
        csvWriter.NextRecord();

        while (csvReader.Read())
        {
            var Make = csvReader.GetField(7)?.Trim();
            var Model = csvReader.GetField(8)?.Trim();
            var Year = csvReader.GetField(9)?.Trim();

            if (string.IsNullOrWhiteSpace(Make) ||
                string.IsNullOrWhiteSpace(Model) ||
                string.IsNullOrWhiteSpace(Year))
            {
                continue;
            }

            var key = $"{Make}|{Model}|{Year}";

            if (!seen.Add(key)) continue;

            csvWriter.WriteField(Make);
            csvWriter.WriteField(Model);
            csvWriter.WriteField(Year);
            csvWriter.NextRecord();
        }
        Console.WriteLine("Done");
    }
}