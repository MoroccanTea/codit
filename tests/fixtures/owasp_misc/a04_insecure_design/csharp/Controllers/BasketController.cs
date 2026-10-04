using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Acme.Store.Controllers
{
    [ApiController]
    [Authorize]
    [Route("api/basket")]
    public class BasketController : ControllerBase
    {
        private readonly IBasketService _baskets;
        private readonly ICouponService _coupons;

        public BasketController(IBasketService baskets, ICouponService coupons)
        {
            _baskets = baskets;
            _coupons = coupons;
        }

        [HttpPost("legacy/discount")]
        public async Task<IActionResult> ApplyDiscountLegacy([FromBody] DiscountDto dto)
        {
            var basket = await _baskets.ForUserAsync(User.Identity.Name);
            // codit-expect: CWE-840 discount percentage taken directly from the request body
            basket.DiscountPercent = dto.DiscountPercent;
            await _baskets.SaveAsync(basket);
            return Ok(basket);
        }



        [HttpPost("discount")]
        public async Task<IActionResult> ApplyDiscount([FromBody] DiscountDto dto)
        {
            var basket = await _baskets.ForUserAsync(User.Identity.Name);
            var coupon = await _coupons.FindActiveAsync(dto.CouponCode, User.Identity.Name);
            if (coupon == null) return BadRequest();
            // codit-safe: CWE-840 percentage comes from the server-side coupon record
            basket.DiscountPercent = coupon.Percent;
            await _baskets.SaveAsync(basket);
            return Ok(basket);
        }
    }

    public class DiscountDto
    {
        public string CouponCode { get; set; }
        public decimal DiscountPercent { get; set; }
    }

    public class Basket { public decimal DiscountPercent { get; set; } }
    public class Coupon { public decimal Percent { get; set; } }

    public interface IBasketService
    {
        Task<Basket> ForUserAsync(string user);
        Task SaveAsync(Basket basket);
    }

    public interface ICouponService
    {
        Task<Coupon> FindActiveAsync(string code, string user);
    }
}
