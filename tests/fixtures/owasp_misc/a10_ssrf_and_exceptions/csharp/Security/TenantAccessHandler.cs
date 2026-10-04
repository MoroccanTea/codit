using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Acme.Tenancy.Security
{
    public class TenantAccessRequirement : IAuthorizationRequirement { }

    public class LegacyTenantAccessHandler : AuthorizationHandler<TenantAccessRequirement>
    {
        private readonly ITenantDirectory _directory;

        public LegacyTenantAccessHandler(ITenantDirectory directory) => _directory = directory;

        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, TenantAccessRequirement requirement)
        {
            try
            {
                if (await _directory.IsMemberAsync(context.User.Identity?.Name, context.Resource))
                    context.Succeed(requirement);
            }
            catch (Exception)
            {
                // codit-expect: CWE-755 directory outage grants access (fail-open)
                context.Succeed(requirement);
            }
        }
    }



    public class TenantAccessHandler : AuthorizationHandler<TenantAccessRequirement>
    {
        private readonly ITenantDirectory _directory;
        private readonly ILogger<TenantAccessHandler> _logger;

        public TenantAccessHandler(ITenantDirectory directory, ILogger<TenantAccessHandler> logger)
        {
            _directory = directory;
            _logger = logger;
        }

        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, TenantAccessRequirement requirement)
        {
            try
            {
                if (await _directory.IsMemberAsync(context.User.Identity?.Name, context.Resource))
                    context.Succeed(requirement);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Tenant directory unavailable");
                // codit-safe: CWE-755 fail closed when the directory cannot be reached
                context.Fail();
            }
        }
    }

    [ApiController]
    [Route("api/reports")]
    public class ReportsController : ControllerBase
    {
        private readonly IHttpClientFactory _http;
        private readonly IReportService _reports;

        public ReportsController(IHttpClientFactory http, IReportService reports)
        {
            _http = http;
            _reports = reports;
        }

        [HttpGet("legacy/{id}")]
        public async Task<IActionResult> GetLegacy(int id)
        {
            try
            {
                return Ok(await _reports.LoadAsync(id));
            }
            catch (Exception ex)
            {
                // codit-expect: CWE-209 exception details (stack trace, SQL) returned in the response
                return Problem(ex.ToString());
            }
        }



        [HttpGet("{id}")]
        public async Task<IActionResult> Get(int id)
        {
            try
            {
                return Ok(await _reports.LoadAsync(id));
            }
            catch (Exception)
            {
                // codit-safe: CWE-209 generic problem details only
                return Problem("An unexpected error occurred.");
            }
        }



        [HttpGet("import")]
        public async Task<IActionResult> Import([FromQuery] string sourceUrl)
        {
            // codit-expect: CWE-918 report imported from an arbitrary user-supplied URL
            var csv = await _http.CreateClient().GetStringAsync(sourceUrl);
            return Ok(await _reports.ImportCsvAsync(csv));
        }
    }

    public interface ITenantDirectory
    {
        Task<bool> IsMemberAsync(string user, object resource);
    }

    public interface IReportService
    {
        Task<object> LoadAsync(int id);
        Task<int> ImportCsvAsync(string csv);
    }
}
