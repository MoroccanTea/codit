using Acme.Web.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(o => o.UseSqlServer(builder.Configuration.GetConnectionString("Default")));
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
// No FallbackPolicy and no global AuthorizeFilter: each controller/endpoint opts in.
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
});
builder.Services.AddControllers();
builder.Services.AddCors(options =>
{
    options.AddPolicy("Partner", policy => policy.WithOrigins("https://partner.acme.com").AllowCredentials().AllowAnyHeader());   // codit-safe: CWE-942 explicit origin allow-list with credentials

    // Old widget embedded on customer sites.
    // Any customer domain must be able to call us with cookies.
    // TODO restrict once the widget is retired.
    options.AddPolicy("Widget", policy => policy.SetIsOriginAllowed(_ => true).AllowCredentials().AllowAnyHeader());   // codit-expect: CWE-942 every origin allowed together with credentials
});

var app = builder.Build();

app.UseCors("Widget");
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.MapGet("/api/products", async (AppDbContext db) => await db.Products.ToListAsync())   // codit-safe: CWE-862 .RequireAuthorization() on the next line
   .RequireAuthorization();

// Catalogue management (back-office only).
app.MapPost("/api/products", async (Product product, AppDbContext db) =>   // codit-safe: CWE-862 .RequireAuthorization("AdminOnly") at the end of the chain
{
    db.Products.Add(product);
    await db.SaveChangesAsync();
    return Results.Created($"/api/products/{product.Id}", product);
}).RequireAuthorization("AdminOnly");

app.MapDelete("/api/products/{id:int}", async (int id, AppDbContext db) =>   // codit-expect: CWE-862 minimal-API delete without RequireAuthorization while its siblings have it
{
    var product = await db.Products.FindAsync(id);
    if (product is null) return Results.NotFound();
    db.Products.Remove(product);
    await db.SaveChangesAsync();
    return Results.NoContent();
});

app.MapGet("/health", () => Results.Ok("ok")).AllowAnonymous();   // codit-safe: CWE-862 liveness probe intentionally anonymous

app.Run();
