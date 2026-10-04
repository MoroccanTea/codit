using System.Threading.Tasks;
using Acme.Web.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Acme.Web.Controllers
{
    [ApiController]
    [Route("api/support")]
    [Authorize]
    public class SupportController : ControllerBase
    {
        private readonly ITicketService _tickets;

        public SupportController(ITicketService tickets)
        {
            _tickets = tickets;
        }

        [HttpPost("tickets/{id:int}/escalate")]
        public async Task<IActionResult> Escalate(int id)
        {
            if (Request.Headers["X-Role"] != "Supervisor")   // codit-expect: CWE-807 role read from a client-controlled request header
                return Forbid();
            await _tickets.EscalateAsync(id);
            return NoContent();
        }

        [HttpGet("tickets/export")]
        public async Task<IActionResult> Export()
        {
            if (Request.Cookies["isAdmin"] != "true")   // codit-expect: CWE-807 admin flag read from an unsigned cookie
                return Forbid();
            return Ok(await _tickets.ExportAllAsync());
        }

        [HttpPost("tickets/{id:int}/close")]
        public async Task<IActionResult> Close(int id)
        {
            if (!User.IsInRole("Supervisor"))   // codit-safe: CWE-807 role claim from the authenticated principal
                return Forbid();
            await _tickets.CloseAsync(id);
            return NoContent();
        }
    }
}
