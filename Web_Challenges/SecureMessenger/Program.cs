using SecureMessenger.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

builder.Services.AddSingleton(new TemplateSecurity(
    maxLength: 1200,
    maxParenDepth: 14
));

var app = builder.Build();

app.UseStaticFiles();
app.UseRouting();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Preview}/{action=Index}/{id?}"
);

app.Run();
