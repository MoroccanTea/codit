using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Acme.Web.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Acme.Web.Controllers
{
    [ApiController]
    [Route("api/orders")]
    [Authorize]
    public class OrdersController : ControllerBase
    {
        private readonly AppDbContext _db;

        public OrdersController(AppDbContext db)
        {
            _db = db;
        }

        [HttpGet]   // codit-safe: CWE-862,CWE-639 class-level [Authorize]; query filtered by the caller's id
        public IActionResult List()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            return Ok(_db.Orders.Where(o => o.UserId == userId).ToList());
        }

        [HttpGet("{id:int}")]
        public async Task<IActionResult> Get(int id)
        {
            var order = await _db.Orders.FindAsync(id);   // codit-expect: CWE-639 any customer's order by id, no UserId filter
            return order is null ? NotFound() : Ok(order);
        }

        [HttpGet("mine/{id:int}")]
        public async Task<IActionResult> GetMine(int id)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var order = await _db.Orders.FirstOrDefaultAsync(o => o.Id == id && o.UserId == userId);   // codit-safe: CWE-639 filtered by the caller's NameIdentifier claim
            return order is null ? NotFound() : Ok(order);
        }

        [HttpPost("{id:int}/cancel")]
        public IActionResult Cancel(int id)
        {
            var order = _db.Orders.Find(id);   // codit-expect: CWE-639 cancels any customer's order (Find without user filter)
            if (order is null) return NotFound();
            order.Status = "Cancelled";
            _db.SaveChanges();
            return NoContent();
        }
    }
}
