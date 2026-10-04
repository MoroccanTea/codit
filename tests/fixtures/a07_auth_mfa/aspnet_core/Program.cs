using Acme.Identity.Data;
using Acme.Identity.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(o =>
    o.UseSqlServer(builder.Configuration.GetConnectionString("Default")));

builder.Services.AddIdentity<AppUser, IdentityRole>(options =>
{
    // codit-expect: CWE-521 4-character passwords without any complexity requirement
    options.Password.RequiredLength = 4;
    options.Password.RequireDigit = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;

    // codit-expect: CWE-307 lockout only after 100 failed password or 2FA attempts
    options.Lockout.MaxFailedAccessAttempts = 100;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
    options.SignIn.RequireConfirmedEmail = true;
})
.AddEntityFrameworkStores<AppDbContext>()
.AddDefaultTokenProviders();

builder.Services.Configure<DataProtectionTokenProviderOptions>(o =>
    // codit-expect: CWE-640 password-reset tokens remain valid for 30 days
    o.TokenLifespan = TimeSpan.FromDays(30));

builder.Services.ConfigureApplicationCookie(o =>
{
    o.LoginPath = "/Account/Login";
    o.Cookie.HttpOnly = true;
    // codit-expect: CWE-613 authentication cookie valid for 365 days with sliding renewal
    o.ExpireTimeSpan = TimeSpan.FromDays(365);
    o.SlidingExpiration = true;
});

builder.Services.AddScoped<TokenService>();
builder.Services.AddScoped<TotpVerifier>();
builder.Services.AddControllersWithViews();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapDefaultControllerRoute();

app.Run();
