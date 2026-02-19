using System.Diagnostics.Contracts;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using CsvHelper;
using CsvHelper.Configuration;

class CarParser
{
    static void Main(string[] args)
    {
        var readConfig = new CsvConfiguration(CultureInfo.InvariantCulture)
        {
            Delimiter = "\t",
            HasHeaderRecord = false,
            MissingFieldFound = null,
            BadDataFound = null
        };

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        using var writer = new StreamWriter("/home/oscarsalsa/Projects/Automic/utilities/2025-2026-Processed.csv");
        using var csvWriter = new CsvWriter(writer, CultureInfo.InvariantCulture);

        //header
        csvWriter.WriteField("MAKE");
        csvWriter.WriteField("MODEL");
        csvWriter.WriteField("YEAR");
        csvWriter.NextRecord();

        readFile(seen, readConfig, "/home/oscarsalsa/Projects/Automic/utilities/inputs/TSBS_RECEIVED_1995-1999.txt", csvWriter);
        readFile(seen, readConfig, "/home/oscarsalsa/Projects/Automic/utilities/inputs/TSBS_RECEIVED_2000-2004.txt", csvWriter);
        readFile(seen, readConfig, "/home/oscarsalsa/Projects/Automic/utilities/inputs/TSBS_RECEIVED_2005-2009.txt", csvWriter);
        readFile(seen, readConfig, "/home/oscarsalsa/Projects/Automic/utilities/inputs/TSBS_RECEIVED_2010-2014.txt", csvWriter);
        readFile(seen, readConfig, "/home/oscarsalsa/Projects/Automic/utilities/inputs/TSBS_RECEIVED_2015-2019.txt", csvWriter);
        readFile(seen, readConfig, "/home/oscarsalsa/Projects/Automic/utilities/inputs/TSBS_RECEIVED_2020-2024.txt", csvWriter);
        readFile(seen, readConfig, "/home/oscarsalsa/Projects/Automic/utilities/inputs/TSBS_RECEIVED_2025-2025.txt", csvWriter);
        readFile(seen, readConfig, "/home/oscarsalsa/Projects/Automic/utilities/inputs/TSBS_RECEIVED_2025-2026.txt", csvWriter);

        Console.WriteLine("Done");
    }

    static void readFile(HashSet<string> seen, CsvConfiguration readConfig, string path, CsvWriter csvWriter)
    {
        using var reader = new StreamReader(path);
        using var csvReader = new CsvReader(reader, readConfig);

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

        Console.WriteLine($"Finished processing: {path}");
    }
}