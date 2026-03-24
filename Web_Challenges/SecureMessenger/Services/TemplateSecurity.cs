using System.Text.RegularExpressions;

namespace SecureMessenger.Services;

public sealed class TemplateSecurity
{
    private readonly int _maxLength;
    private readonly int _maxParenDepth;

    private static readonly string[] BlockedSubstrings =
    {
        // Razor structure restrictions
        "@using",
        "@{",

        // Direct file access (force reflection)
        "System.IO",
        "File",
        "ReadAllText",
        "ReadAllBytes",
        "Directory",

        // No RCE
        "Process",
        "Diagnostics",
        "Start(",
        "cmd",
        "powershell",
        "bash",
        "/bin/",
        "sh -c",

        // No environment pivot
        "Environment",
        "AppDomain",
        "DllImport",
        "Marshal"
    };

    private static readonly Regex[] BlockedRegex =
    {
        new Regex(@"@\s*using\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex(@"@\s*\{", RegexOptions.Compiled),
        new Regex(@"\bProcess\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex(@"\bDiagnostics\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
    };

    public TemplateSecurity(int maxLength, int maxParenDepth)
    {
        _maxLength = maxLength;
        _maxParenDepth = maxParenDepth;
    }

    public bool TryValidate(string? template, out string reason)
    {
        reason = "";

        if (string.IsNullOrWhiteSpace(template))
        {
            reason = "Empty template.";
            return false;
        }

        if (template.Length > _maxLength)
        {
            reason = $"Template too long (max {_maxLength}).";
            return false;
        }

        foreach (var s in BlockedSubstrings)
        {
            if (template.Contains(s, StringComparison.OrdinalIgnoreCase))
            {
                reason = $"Blocked keyword: {s}";
                return false;
            }
        }

        foreach (var r in BlockedRegex)
        {
            if (r.IsMatch(template))
            {
                reason = "Blocked pattern.";
                return false;
            }
        }

        // Paren depth limiter (anti insane chains)
        int depth = 0, maxDepth = 0;
        foreach (char c in template)
        {
            if (c == '(') { depth++; maxDepth = Math.Max(maxDepth, depth); }
            else if (c == ')') { depth = Math.Max(0, depth - 1); }
        }

        if (maxDepth > _maxParenDepth)
        {
            reason = $"Expression too complex.";
            return false;
        }

        return true;
    }
}
