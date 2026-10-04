using System.Threading.Tasks;
using Acme.Web.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Acme.Web.Controllers
{
    [ApiController]
    [Route("api/admin")]
    [Authorize(Roles = "Admin")]
    public class AdminController : ControllerBase
    {
        private readonly IAdminService _admin;

        public AdminController(IAdminService admin)
        {
            _admin = admin;
        }

        [HttpGet("users")]   // codit-safe: CWE-862 class-level [Authorize(Roles = "Admin")]
        public async Task<IActionResult> ListUsers()
        {
            return Ok(await _admin.ListUsersAsync());
        }

        [Authorize]
        [HttpDelete("users/{id:int}")]   // codit-safe: CWE-862,CWE-863 method [Authorize] is ADDED to the class-level Roles="Admin" requirement (both must pass)
        public async Task<IActionResult> DeleteUser(int id)
        {
            await _admin.DeleteUserAsync(id);
            return NoContent();
        }

        [AllowAnonymous]   // codit-expect: CWE-862 [AllowAnonymous] overrides the class-level admin requirement on a destructive action
        [HttpPost("audit-log/purge")]
        public async Task<IActionResult> PurgeAuditLog()
        {
            await _admin.PurgeAuditLogAsync();
            return NoContent();
        }
    }
}
