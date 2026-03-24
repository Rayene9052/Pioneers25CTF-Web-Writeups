namespace RazorCtf.Models;

public sealed class EmailModel
{
    public string Username { get; set; } = "guest";
    public string Plan { get; set; } = "free";
    public int Credits { get; set; } = 1337;

    public DateTime Now => DateTime.UtcNow;

    public Dictionary<string, string> Meta { get; set; } = new()
    {
        ["company"] = "PerfectSource",
        ["campaign"] = "WinterPromo"
    };
}
