using System.Threading.Tasks;
using Auth;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthorization()
                .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddScheme<JwtBearerAuthenticationOptions, CustomAuthenticationHandler>(JwtBearerDefaults.AuthenticationScheme, null);

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", async http =>
{
    await http.Response.WriteAsync("Hello feathery MVP Summit!");
}).RequireAuthorization();

app.MapGet("/mvp-treatment", async http =>
{
    await http.Response.WriteAsync("Please authorize!");
});

await app.RunAsync();