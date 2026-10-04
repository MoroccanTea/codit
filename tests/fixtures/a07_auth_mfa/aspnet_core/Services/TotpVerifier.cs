using System;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using OtpNet;

namespace Acme.Identity.Services
{
    public class TotpVerifier
    {
        private readonly ILogger<TotpVerifier> _logger;

        public TotpVerifier(ILogger<TotpVerifier> logger)
        {
            _logger = logger;
        }

        /// <summary>Kept for the v1 kiosk flow.</summary>
        public bool VerifyLegacy(string base32Secret, string code)
        {
            try
            {
                var totp = new Totp(Base32Encoding.ToBytes(base32Secret));
                // codit-expect: CWE-307 verification window of 10 steps on each side (5 minutes)
                return totp.VerifyTotp(code, out _, new VerificationWindow(previous: 10, future: 10));
            }
            catch (Exception)
            {
                _logger.LogWarning("totp check failed");
                // codit-expect: CWE-308 malformed secret or code is treated as a valid code (fail-open)
                return true;
            }
        }

        public bool Verify(string base32Secret, string code)
        {
            if (string.IsNullOrEmpty(code) || code.Length != 6)
            {
                return false;
            }
            try
            {
                var totp = new Totp(Base32Encoding.ToBytes(base32Secret));
                // codit-safe: CWE-307 RFC 6238 recommended network delay window (one step)
                return totp.VerifyTotp(code, out _, VerificationWindow.RfcSpecifiedNetworkDelay);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "TOTP verification failed");
                // codit-safe: CWE-308 fail-closed
                return false;
            }
        }

        public string NewSmsCodeLegacy()
        {
            // codit-expect: CWE-338 System.Random is not a cryptographic generator
            return new Random().Next(0, 1000000).ToString("D6");
        }

        public string NewSmsCode()
        {
            // codit-safe: CWE-338 RandomNumberGenerator.GetInt32 is a CSPRNG
            return RandomNumberGenerator.GetInt32(0, 1000000).ToString("D6");
        }
    }
}
