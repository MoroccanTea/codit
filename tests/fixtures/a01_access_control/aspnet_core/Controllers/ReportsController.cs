using System.Threading.Tasks;
using Acme.Web.Services;
using Microsoft.AspNetCore.Mvc;

namespace Acme.Web.Controllers
{
    [ApiController]
    [Route("api/reports")]
    public class ReportsController : ControllerBase
    {
        private readonly IReportService _reports;

        public ReportsController(IReportService reports)
        {
            _reports = reports;
        }

        [HttpGet("payroll")]   // codit-expect: CWE-862 controller has no [Authorize]; Program.cs has no fallback policy or global AuthorizeFilter
        public async Task<IActionResult> Payroll()
        {
            return Ok(await _reports.PayrollAsync());
        }

        [HttpDelete("{id:int}")]   // codit-expect: CWE-862 unauthenticated delete in a project where other controllers use [Authorize]
        public async Task<IActionResult> Delete(int id)
        {
            await _reports.DeleteAsync(id);
            return NoContent();
        }
    }
}
