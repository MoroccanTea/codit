using System.Security.Claims;
using System.Threading.Tasks;
using Acme.Web.Data;
using Acme.Web.Models;
using Acme.Web.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Acme.Web.Controllers
{
    public record LoginRequest(string Email, string Password);
    public record ForgotPasswordRequest(string Email);
    public record ProfileDetails(string DisplayName, string TimeZone);

    [ApiController]
    [Route("api/account")]
    [Authorize]
    public class AccountController : ControllerBase
    {
        private readonly AppDbContext _db;
        private readonly IAuthService _auth;

        public AccountController(AppDbContext db, IAuthService auth)
        {
            _db = db;
            _auth = auth;
        }

        [AllowAnonymous]
        [HttpPost("login")]   // codit-safe: CWE-862 login must be anonymous
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var token = await _auth.LoginAsync(request.Email, request.Password);
            return token is null ? Unauthorized() : Ok(new { token });
        }

        [AllowAnonymous]
        [HttpPost("forgot-password")]   // codit-safe: CWE-862 password-reset request is anonymous by design
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
        {
            await _auth.SendResetLinkIfExistsAsync(request.Email);
            return Accepted();
        }

        [HttpPut("profile")]
        public async Task<IActionResult> UpdateProfile([FromBody] ApplicationUser input)
        {
            _db.Users.Update(input);   // codit-expect: CWE-915 full entity (IsAdmin, Roles, TwoFactorEnabled) bound from the request body and saved
            await _db.SaveChangesAsync();
            return NoContent();
        }

        [HttpPut("profile/details")]
        public async Task<IActionResult> UpdateDetails([FromBody] ProfileDetails input)
        {
            var user = await _db.Users.FindAsync(User.FindFirstValue(ClaimTypes.NameIdentifier));
            user!.DisplayName = input.DisplayName;   // codit-safe: CWE-915,CWE-639 narrow DTO copied field by field onto the caller's own record
            user.TimeZone = input.TimeZone;
            await _db.SaveChangesAsync();
            return NoContent();
        }
    }
}
