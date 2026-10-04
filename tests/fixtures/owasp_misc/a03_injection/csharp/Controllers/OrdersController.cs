using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

namespace Acme.Shop.Controllers
{
    [ApiController]
    [Authorize]
    [Route("api/orders")]
    public class OrdersController : ControllerBase
    {
        private readonly ShopDbContext _db;
        private readonly string _connectionString;

        public OrdersController(ShopDbContext db, Microsoft.Extensions.Configuration.IConfiguration config)
        {
            _db = db;
            _connectionString = config.GetConnectionString("Shop");
        }

        [HttpGet("legacy/{id}")]
        public async Task<IActionResult> GetLegacy(string id)
        {
            using var conn = new SqlConnection(_connectionString);
            await conn.OpenAsync();
            // codit-expect: CWE-89 route value concatenated into SqlCommand text
            using var cmd = new SqlCommand("SELECT Id, Total FROM Orders WHERE Id = " + id, conn);
            var total = await cmd.ExecuteScalarAsync();
            return Ok(total);
        }



        [HttpGet("{id:int}")]
        public async Task<IActionResult> Get(int id)
        {
            using var conn = new SqlConnection(_connectionString);
            await conn.OpenAsync();
            using var cmd = new SqlCommand("SELECT Id, Total FROM Orders WHERE Id = @id", conn);
            // codit-safe: CWE-89 SqlParameter binding
            cmd.Parameters.AddWithValue("@id", id);
            return Ok(await cmd.ExecuteScalarAsync());
        }

        [HttpGet("search")]
        public List<Order> Search(string customer)
        {
            // codit-expect: CWE-89 FromSqlRaw with an interpolated string is not parameterised
            return _db.Orders.FromSqlRaw($"SELECT * FROM Orders WHERE CustomerName = '{customer}'").ToList();
        }



        [HttpGet("search-safe")]
        public List<Order> SearchSafe(string customer)
        {
            // codit-safe: CWE-89 FromSqlInterpolated turns each hole into a DbParameter
            return _db.Orders.FromSqlInterpolated($"SELECT * FROM Orders WHERE CustomerName = {customer}").ToList();
        }
    }

    public class Order
    {
        public int Id { get; set; }
        public string CustomerName { get; set; }
        public decimal Total { get; set; }
    }

    public class ShopDbContext : DbContext
    {
        public DbSet<Order> Orders { get; set; }
    }
}
