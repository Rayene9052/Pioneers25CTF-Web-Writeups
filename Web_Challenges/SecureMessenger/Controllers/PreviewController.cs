using Microsoft.AspNetCore.Mvc;
using SecureMessenger.Models;
using SecureMessenger.Services;
using RazorLight;
using RazorLight.Compilation;
using System.Net;
using System.Reflection;

namespace SecureMessenger.Controllers;

public sealed class PreviewController : Controller
{
    private readonly TemplateSecurity _security;
    private readonly RazorLightEngine _engine;

    public PreviewController(TemplateSecurity security)
    {
        _security = security;

        _engine = new RazorLightEngineBuilder()
            .UseMemoryCachingProvider()
            .Build();
    }

    [HttpGet]
    public IActionResult Index()
    {
        return View("~/Views/Home/Index.cshtml");
    }

    [HttpPost]
    public async Task<IActionResult> Preview([FromForm] string template)
    {
        // 1) Real "blocked keyword" (filter)
        if (!_security.TryValidate(template, out _))
        {
            await Task.Delay(120);
            return ErrorBox("Blocked keyword detected.");
        }

        var model = new EmailModel
        {
            Username = "Alex",
            Plan = "Pro",
            Credits = 2500
        };

        try
        {
            string output = await _engine.CompileRenderStringAsync("tpl", template, model);

            // Prevent XSS: show rendered output as text
            string safeOutput = WebUtility.HtmlEncode(output);

            return Content($"""
                <div class="chat-container">
                    <div class="chat-bubble">
                        {safeOutput}
                    </div>
                </div>
            """, "text/html");
        }
        catch (Exception ex)
        {
            // Unwrap common wrappers (reflection + aggregate) to find the true root cause
            var root = Unwrap(ex);

            // AUTHOR-ONLY logging (players won't see it)
            Console.WriteLine($"[RenderError] {root.GetType().FullName}: {root.Message}");

            // 2) Compilation error (RazorLight compile-time)
            if (root is TemplateCompilationException)
            {
                await Task.Delay(120);
                return ErrorBox("Compilation error.");
            }

            // 3) Runtime errors (ex: file missing when using relative path "flag.txt")
            if (root is FileNotFoundException || root is DirectoryNotFoundException)
            {
                await Task.Delay(120);
                return ErrorBox("File not found.");
            }

            await Task.Delay(120);
            return ErrorBox("Runtime error.");
        }
    }

    private static Exception Unwrap(Exception ex)
    {
        Exception cur = ex;

        while (true)
        {
            // MethodInfo.Invoke wraps runtime exceptions here
            if (cur is TargetInvocationException tie && tie.InnerException != null)
            {
                cur = tie.InnerException;
                continue;
            }

            // Some internals wrap in AggregateException
            if (cur is AggregateException ae && ae.InnerExceptions.Count == 1)
            {
                cur = ae.InnerExceptions[0];
                continue;
            }

            // Walk down inner exceptions
            if (cur.InnerException != null)
            {
                cur = cur.InnerException;
                continue;
            }

            return cur;
        }
    }

    private ContentResult ErrorBox(string msg)
    {
        var safe = WebUtility.HtmlEncode(msg);
        return Content($"""
            <div class="error-box">
                {safe}
            </div>
        """, "text/html");
    }
}
