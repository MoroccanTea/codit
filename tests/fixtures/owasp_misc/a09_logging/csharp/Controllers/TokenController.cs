using System;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Acme.Identity.Controllers
{
    [ApiController]
    [Route("api/token")]
    public class TokenController : ControllerBase
    {
        private readonly ILogger<TokenController> _logger;
        private readonly ITokenValidator _validator;

        public TokenController(ILogger<TokenController> logger, ITokenValidator validator)
        {
            _logger = logger;
            _validator = validator;
        }

        [HttpPost("legacy/introspect")]
        public IActionResult IntrospectLegacy([FromForm] string token, [FromForm] string clientId)
        {
            // codit-expect: CWE-117 client-supplied value concatenated into the log message
            _logger.LogInformation("Introspection requested by " + clientId);
            try
            {
                return Ok(_validator.Validate(token));
            }
            // codit-expect: CWE-390 token validation failure swallowed; falls through to an empty 200
            catch (SecurityTokenException) { }
            return Ok();
        }



        [HttpPost("introspect")]
        public IActionResult Introspect([FromForm] string token, [FromForm] string clientId)
        {
            // codit-safe: CWE-117 structured logging template, value passed as a parameter
            _logger.LogInformation("Introspection requested by {ClientId}", clientId);
            try
            {
                return Ok(_validator.Validate(token));
            }
            // codit-safe: CWE-390 failure logged and answered with 401
            catch (SecurityTokenException ex)
            {
                _logger.LogWarning(ex, "Token validation failed for {ClientId}", clientId);
                return Unauthorized();
            }
        }
    }

    public interface ITokenValidator
    {
        object Validate(string token);
    }
}
