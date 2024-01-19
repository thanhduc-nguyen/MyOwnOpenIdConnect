using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

var builder = WebApplication.CreateBuilder(args);

JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
builder.Services.AddAuthentication(config =>
{
    config.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    config.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
    {
        options.Authority = "https://localhost:7209"; // This is the OAuth20.Server URI
        options.ClientId = "myclient";
        options.ClientSecret = "123456789";
        options.ResponseType = "code";
        //options.CallbackPath = "/signin-oidc"; // Default
        //options.SignedOutCallbackPath = "/signout-callback-oidc"; // Default
        options.SaveTokens = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = false,
            SignatureValidator = delegate (string token, TokenValidationParameters validationParameters)
            {
                var jwt = new JwtSecurityToken(token);
                return jwt;
            },
        };
        options.ClaimActions.Remove("iat");
        options.ClaimActions.Remove("aud");
    });
builder.Services.AddControllersWithViews();

var app = builder.Build();

app.UseStaticFiles();
app.UseRouting();


app.UseAuthentication();
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapDefaultControllerRoute();
});

app.Run();
