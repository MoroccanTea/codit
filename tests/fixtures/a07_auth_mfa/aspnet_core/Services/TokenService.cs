using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Acme.Identity.Data;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Acme.Identity.Services
{
    public class JwtOptions
    {
        public string Issuer { get; set; } = "https://id.acme.example";
        public string Audience { get; set; } = "acme-api";
        public string SigningKey { get; set; } = string.Empty;
    }

    public class TokenService
    {
        private readonly JwtOptions _opt;
        private readonly SigningCredentials _creds;

        public TokenService(IOptions<JwtOptions> options)
        {
            _opt = options.Value;
            _creds = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_opt.SigningKey)),
                SecurityAlgorithms.HmacSha256);
        }

        private static IEnumerable<Claim> BuildClaims(AppUser user, string purpose) => new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim("purpose", purpose),
        };

        public string CreateAccessToken(AppUser user)
        {
            var token = new JwtSecurityToken(
                issuer: _opt.Issuer,
                audience: _opt.Audience,
                claims: BuildClaims(user, "access"),
                // codit-safe: CWE-613 15-minute access token
                expires: DateTime.UtcNow.AddMinutes(15),
                signingCredentials: _creds);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public string CreateMfaPendingToken(AppUser user)
        {
            var token = new JwtSecurityToken(
                issuer: _opt.Issuer,
                audience: _opt.Audience,
                claims: BuildClaims(user, "mfa_pending"),
                expires: DateTime.UtcNow.AddMinutes(5),
                signingCredentials: _creds);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        /// <summary>Token of the legacy Xamarin app, which has no refresh flow.</summary>
        public string CreateMobileToken(AppUser user)
        {
            var token = new JwtSecurityToken(
                issuer: _opt.Issuer,
                audience: _opt.Audience,
                claims: BuildClaims(user, "access"),
                // codit-expect: CWE-613 mobile bearer token valid for one year
                expires: DateTime.UtcNow.AddYears(1),
                signingCredentials: _creds);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
