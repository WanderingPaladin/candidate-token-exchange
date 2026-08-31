using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Collaborate.TokenExchange.Tests.Support;

public sealed class TestRunLog
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly object _gate = new();
    private readonly List<TestCaseLogEntry> _entries = [];
    private readonly string _timestampedPath;
    private readonly string _latestPath;
    private readonly string _latestJsonPath;
    private int _index;

    public string FilePath => _timestampedPath;

    public string LatestPath => _latestPath;

    private TestRunLog(string directory, string stamp)
    {
        Directory.CreateDirectory(directory);
        _timestampedPath = Path.Combine(directory, $"token-exchange-{stamp}.log");
        _latestPath = Path.Combine(directory, "token-exchange-latest.log");
        _latestJsonPath = Path.Combine(directory, "token-exchange-latest.json");

        var header = $"""
            Collaborate token exchange test log
            Started (UTC): {DateTime.UtcNow:O}
            Access tokens and signing keys are omitted.

            """;

        File.WriteAllText(_timestampedPath, header);
        File.WriteAllText(_latestPath, header);
        Console.WriteLine($"Test case log: {_timestampedPath}");
        Console.WriteLine($"Test case log (latest): {_latestPath}");
    }

    public static TestRunLog Create()
    {
        var root = FindRepoRoot();
        var directory = Path.Combine(root, "TestResults");
        var stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
        return new TestRunLog(directory, stamp);
    }

    public void WriteCase(TestCaseLogEntry entry)
    {
        lock (_gate)
        {
            _index++;
            var numbered = entry with { Number = _index };
            _entries.Add(numbered);
            var text = Format(numbered);
            File.AppendAllText(_timestampedPath, text);
            File.AppendAllText(_latestPath, text);
        }
    }

    public void Complete()
    {
        lock (_gate)
        {
            var passed = _entries.Count(e => e.Passed);
            var failed = _entries.Count - passed;
            var footer = $"""

                ------------------------------------------------------------------------
                SUMMARY  total={_entries.Count}  passed={passed}  failed={failed}
                Finished (UTC): {DateTime.UtcNow:O}
                """;

            File.AppendAllText(_timestampedPath, footer + Environment.NewLine);
            File.WriteAllText(_latestPath, File.ReadAllText(_timestampedPath));
            File.WriteAllText(_latestJsonPath, JsonSerializer.Serialize(new
            {
                started = _entries.FirstOrDefault()?.StartedAt,
                finished = DateTime.UtcNow,
                total = _entries.Count,
                passed,
                failed,
                cases = _entries
            }, JsonOptions));

            Console.WriteLine($"Test case log saved: {_timestampedPath}");
            Console.WriteLine($"Test case log saved: {_latestPath}");
            Console.WriteLine($"Test case log saved: {_latestJsonPath}");
        }
    }

    private static string Format(TestCaseLogEntry entry)
    {
        var builder = new StringBuilder();
        builder.AppendLine();
        builder.AppendLine(new string('=', 76));
        builder.AppendLine($"TEST {entry.Number}  {entry.Name}");
        builder.AppendLine($"RESULT     {(entry.Passed ? "PASS" : "FAIL")}");
        builder.AppendLine(new string('-', 76));
        builder.AppendLine("INPUT");
        builder.AppendLine(Indent(entry.Input));
        builder.AppendLine("EXPECTED_OUTPUT");
        builder.AppendLine(Indent(entry.ExpectedOutput));
        builder.AppendLine("OUTPUT");
        builder.AppendLine(Indent(entry.Output));
        if (entry.Differences.Count > 0)
        {
            builder.AppendLine("DIFF");
            foreach (var diff in entry.Differences)
            {
                builder.AppendLine("  - " + diff);
            }
        }

        builder.AppendLine("SERVER");
        if (entry.ServerLog.Count == 0)
        {
            builder.AppendLine("  (no server log)");
        }
        else
        {
            foreach (var line in entry.ServerLog)
            {
                builder.AppendLine("  " + line);
            }
        }

        builder.AppendLine(new string('=', 76));
        return builder.ToString();
    }

    private static string Indent(string value)
    {
        var lines = value.ReplaceLineEndings("\n").Split('\n');
        return string.Join(Environment.NewLine, lines.Select(line => string.IsNullOrEmpty(line) ? "" : "  " + line));
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Collaborate.TokenExchange.sln")))
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }

        return Path.Combine(AppContext.BaseDirectory, "TestResults");
    }
}

public sealed record TestCaseLogEntry
{
    public int Number { get; init; }

    public required string Name { get; init; }

    public required DateTimeOffset StartedAt { get; init; }

    public required bool Passed { get; init; }

    public required string Input { get; init; }

    public required string ExpectedOutput { get; init; }

    public required string Output { get; init; }

    public IReadOnlyList<string> Differences { get; init; } = [];

    public IReadOnlyList<string> ServerLog { get; init; } = [];
}
