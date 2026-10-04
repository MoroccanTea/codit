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
    [Authorize]
    [Route("api/account/2fa")]
    public class TwoFactorSettingsController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly TotpVerifier _totp;
        private readonly ISmsSender _sms;
        private readonly ILogger<TwoFactorSettingsController> _logger;

        public TwoFactorSettingsController(UserManager<AppUser> userManager, TotpVerifier totp, ISmsSender sms,
            ILogger<TwoFactorSettingsController> logger)
        {
            _userManager = userManager;
            _totp = totp;
            _sms = sms;
            _logger = logger;
        }

        // codit-expect: CWE-308 2FA disabled with only the bearer token, no password or code re-verification
        [HttpPost("disable")]
        public async Task<IActionResult> Disable()
        {
            var user = await _userManager.GetUserAsync(User);
            await _userManager.SetTwoFactorEnabledAsync(user!, false);
            await _userManager.ResetAuthenticatorKeyAsync(user!);
            return NoContent();
        }

        // codit-safe: CWE-308 requires the current password and a valid authenticator code
        [HttpPost("v2/disable")]
        public async Task<IActionResult> DisableV2([FromBody] Disable2faRequest req)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null || !await _userManager.CheckPasswordAsync(user, req.CurrentPassword))
                return Forbid();
            var codeOk = await _userManager.VerifyTwoFactorTokenAsync(user,
                _userManager.Options.Tokens.AuthenticatorTokenProvider, req.Code);
            if (!codeOk)
                return Forbid();
            await _userManager.SetTwoFactorEnabledAsync(user, false);
            return NoContent();
        }

        [HttpPost("sms/send")]
        public async Task<IActionResult> SendSms()
        {
            var user = await _userManager.GetUserAsync(User);
            var code = _totp.NewSmsCode();
            await _sms.SendAsync(user!.PhoneNumber!, $"Your Acme code: {code}");
            // codit-expect: CWE-532 SMS one-time code written to the logs
            _logger.LogInformation("SMS code {Code} sent to {Phone}", code, user.PhoneNumber);
            return Accepted();
        }

        [HttpPost("v2/sms/send")]
        public async Task<IActionResult> SendSmsV2()
        {
            var user = await _userManager.GetUserAsync(User);
            var code = await _userManager.GenerateTwoFactorTokenAsync(user!, TokenOptions.DefaultPhoneProvider);
            await _sms.SendAsync(user!.PhoneNumber!, $"Your Acme code: {code}");
            // codit-safe: CWE-532 only the user id is logged
            _logger.LogInformation("SMS code sent to user {UserId}", user.Id);
            return Accepted();
        }
    }
}
