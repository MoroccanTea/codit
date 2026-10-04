using System.Threading.Tasks;
using Acme.Identity.Data;
using Acme.Identity.Models;
using Acme.Identity.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Acme.Identity.Controllers.Api
{
    [ApiController]
    [Route("api/v1/token")]
    public class LegacyTokenController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly TokenService _tokens;
        private readonly ILogger<LegacyTokenController> _logger;

        public LegacyTokenController(UserManager<AppUser> userManager, TokenService tokens, ILogger<LegacyTokenController> logger)
        {
            _userManager = userManager;
            _tokens = tokens;
            _logger = logger;
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Create([FromBody] TokenRequest req)
        {
            var user = await _userManager.FindByEmailAsync(req.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, req.Password))
                return Unauthorized();

            // codit-expect: CWE-807 MFA bypassed when the caller sends X-MFA-Verified: true
            if (user.TwoFactorEnabled && Request.Headers["X-MFA-Verified"] != "true")
            {
                _logger.LogInformation("2FA required for {UserId}", user.Id);
                await _userManager.UpdateSecurityStampAsync(user);
                // codit-expect: CWE-308 full access JWT returned alongside requiresTwoFactor
                return Ok(new { requiresTwoFactor = true, accessToken = _tokens.CreateMobileToken(user) });
            }
            return Ok(new { accessToken = _tokens.CreateMobileToken(user) });
        }
    }

    [ApiController]
    [Route("api/v2/token")]
    public class TokenController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly TokenService _tokens;

        public TokenController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, TokenService tokens)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _tokens = tokens;
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Create([FromBody] TokenRequest req)
        {
            var user = await _userManager.FindByEmailAsync(req.Email);
            if (user == null)
                return Unauthorized();
            var check = await _signInManager.CheckPasswordSignInAsync(user, req.Password, lockoutOnFailure: true);
            if (!check.Succeeded)
                return Unauthorized();

            if (user.TwoFactorEnabled)
            {
                // codit-safe: CWE-308 only a 5-minute token with purpose=mfa_pending is issued before the second factor
                return Ok(new { requiresTwoFactor = true, mfaToken = _tokens.CreateMfaPendingToken(user) });
            }
            return Ok(new { accessToken = _tokens.CreateAccessToken(user) });
        }

        [HttpPost("2fa")]
        [Authorize(Policy = "MfaPending")]
        public async Task<IActionResult> Verify([FromBody] TwoFactorRequest req)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null || await _userManager.IsLockedOutAsync(user))
                return Unauthorized();
            var ok = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, req.Code);
            if (!ok)
            {
                await _userManager.AccessFailedAsync(user);
                return Unauthorized();
            }
            await _userManager.ResetAccessFailedCountAsync(user);
            return Ok(new { accessToken = _tokens.CreateAccessToken(user) });
        }
    }
}
