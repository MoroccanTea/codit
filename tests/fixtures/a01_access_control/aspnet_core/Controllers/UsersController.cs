using System.Collections.Generic;
using System.Threading.Tasks;
using Acme.Web.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Acme.Web.Controllers
{
    [ApiController]
    [Route("api/users")]
    public class UsersController : ControllerBase
    {
        private readonly IUserDirectory _users;

        public UsersController(IUserDirectory users)
        {
            _users = users;
        }

        [Authorize(Roles = "Admin")]
        [HttpGet]   // codit-safe: CWE-862 [Authorize(Roles = "Admin")]
        public async Task<IActionResult> List()
        {
            return Ok(await _users.ListAsync());
        }

        [Authorize(Roles = "Admin")]
        [HttpPut("{id:int}/roles")]   // codit-safe: CWE-862,CWE-863 [Authorize(Roles = "Admin")]
        public async Task<IActionResult> SetRoles(int id, [FromBody] List<string> roles)
        {
            await _users.SetRolesAsync(id, roles);
            return NoContent();
        }

        [Authorize]   // codit-expect: CWE-863 authentication-only [Authorize] on an admin delete; every sibling requires Roles="Admin"
        [HttpDelete("{id:int}")]
        public async Task<IActionResult> Delete(int id)
        {
            await _users.DeleteAsync(id);
            return NoContent();
        }

        [Authorize]
        [HttpGet("me")]   // codit-safe: CWE-862,CWE-863 self-service endpoint; authentication is the right requirement
        public IActionResult Me()
        {
            return Ok(new { Name = User.Identity?.Name });
        }
    }
}
