using Acme.Partners.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<PartnersDbContext>(o =>
    o.UseNpgsql(builder.Configuration.GetConnectionString("Partners")));

builder.Services.AddIdentity<PartnerUser, IdentityRole>(options =>
{
    // codit-safe: CWE-521 12-character minimum
    options.Password.RequiredLength = 12;
    options.Password.RequiredUniqueChars = 4;
    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedAccount = true;

    // codit-safe: CWE-307 account locked for 15 minutes after 5 failures
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.AllowedForNewUsers = true;
})
.AddEntityFrameworkStores<PartnersDbContext>()
.AddDefaultTokenProviders();

builder.Services.Configure<DataProtectionTokenProviderOptions>(o =>
    // codit-safe: CWE-640 reset tokens expire after one hour
    o.TokenLifespan = TimeSpan.FromHours(1));

builder.Services.ConfigureApplicationCookie(o =>
{
    o.LoginPath = "/Account/Login";
    o.Cookie.HttpOnly = true;
    o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    // codit-safe: CWE-613 30-minute sliding authentication cookie
    o.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    o.SlidingExpiration = true;
});

builder.Services.AddRazorPages();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapRazorPages();

app.Run();
