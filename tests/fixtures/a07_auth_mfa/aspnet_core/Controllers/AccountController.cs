using System.Threading.Tasks;
using Acme.Identity.Data;
using Acme.Identity.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Acme.Identity.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly ILogger<AccountController> _logger;

        public AccountController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager,
            ILogger<AccountController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            if (!ModelState.IsValid) return View(model);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                // codit-expect: CWE-204 different message for unknown accounts enables enumeration
                ModelState.AddModelError(string.Empty, "No user with this email address exists.");
                return View(model);
            }

            if (!await _userManager.CheckPasswordAsync(user, model.Password))
            {
                ModelState.AddModelError(string.Empty, "Wrong password.");
                return View(model);
            }

            // codit-expect: CWE-308 full authentication cookie issued before the authenticator code is verified
            await _signInManager.SignInAsync(user, isPersistent: model.RememberMe);
            if (await _userManager.GetTwoFactorEnabledAsync(user))
            {
                return RedirectToAction(nameof(LoginWith2fa), new { returnUrl });
            }
            return LocalRedirect(returnUrl ?? "/");
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginV2(LoginViewModel model, string? returnUrl = null)
        {
            if (!ModelState.IsValid) return View("Login", model);

            // codit-safe: CWE-308 PasswordSignInAsync only sets the Identity.TwoFactorUserId cookie when 2FA is enabled
            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: true);
            if (result.RequiresTwoFactor)
            {
                return RedirectToAction(nameof(LoginWith2fa), new { returnUrl, model.RememberMe });
            }
            if (result.Succeeded)
            {
                return LocalRedirect(returnUrl ?? "/");
            }

            _logger.LogWarning("Failed login attempt");
            // codit-safe: CWE-204 same message for unknown user, wrong password and locked account
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View("Login", model);
        }

        [HttpPost]
        [AllowAnonymous]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> KioskLogin([FromForm] LoginViewModel model)
        {
            // codit-expect: CWE-307 lockoutOnFailure: false disables brute-force lockout for this entry point
            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, false, lockoutOnFailure: false);
            if (result.Succeeded)
            {
                return Redirect("/kiosk");
            }

            // codit-expect: CWE-807 2FA requirement waived when the plain TrustedDevice cookie is present
            if (result.RequiresTwoFactor && Request.Cookies["TrustedDevice"] == "1")
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                await _signInManager.SignInAsync(user!, isPersistent: false);
                return Redirect("/kiosk");
            }
            return result.RequiresTwoFactor ? RedirectToAction(nameof(LoginWith2fa)) : Unauthorized();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginWith2fa(LoginWith2faViewModel model, bool rememberMe, string? returnUrl = null)
        {
            if (!ModelState.IsValid) return View(model);
            var code = model.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);
            // codit-safe: CWE-807 RememberMachine uses Identity's signed, user-bound two-factor remember cookie
            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(code, rememberMe, model.RememberMachine);
            if (result.Succeeded)
            {
                return LocalRedirect(returnUrl ?? "/");
            }
            ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
            return View(model);
        }
    }
}
