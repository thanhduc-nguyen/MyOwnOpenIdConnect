using OAuth20.Server.Services;
using OAuth20.Server.Services.CodeService;

var builder = WebApplication.CreateBuilder(args);


builder.Services.AddSingleton<ICodeStoreService, CodeStoreService>();
builder.Services.AddScoped<IAuthorizeResultService, AuthorizeResultService>();

builder.Services.AddHttpContextAccessor();
builder.Services.AddAuthentication();
builder.Services.AddControllersWithViews();

var app = builder.Build();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapDefaultControllerRoute();
});

app.Run();
