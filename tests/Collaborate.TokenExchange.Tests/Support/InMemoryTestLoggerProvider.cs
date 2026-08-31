using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace Collaborate.TokenExchange.Tests.Support;

/// <summary>
/// Captures in-process server logs for the current test and also echoes them to the console.
/// </summary>
public sealed class InMemoryTestLoggerProvider : ILoggerProvider
{
    private readonly ConcurrentQueue<string> _lines = new();

    public ILogger CreateLogger(string categoryName) => new CaptureLogger(categoryName, this);

    public void Add(string line) => _lines.Enqueue(line);

    public IReadOnlyList<string> Drain()
    {
        var snapshot = new List<string>();
        while (_lines.TryDequeue(out var line))
        {
            snapshot.Add(line);
        }

        return snapshot;
    }

    public void Dispose()
    {
    }

    private sealed class CaptureLogger : ILogger
    {
        private readonly string _category;
        private readonly InMemoryTestLoggerProvider _provider;

        public CaptureLogger(string category, InMemoryTestLoggerProvider provider)
        {
            _category = category;
            _provider = provider;
        }

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var message = formatter(state, exception);
            var line = $"{DateTime.UtcNow:HH:mm:ss.fff} {logLevel.ToString().ToLowerInvariant(),-5} {_category}: {message}";
            if (exception is not null)
            {
                line += Environment.NewLine + exception.GetType().Name + ": " + exception.Message;
            }

            _provider.Add(line);
            Console.WriteLine(line);
        }
    }

    private sealed class NullScope : IDisposable
    {
        public static readonly NullScope Instance = new();

        public void Dispose()
        {
        }
    }
}
