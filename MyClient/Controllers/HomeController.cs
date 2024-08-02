using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace MyClient.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult SecretZone()
        {
            var roles = ((ClaimsIdentity)User.Identity).Claims
                .Where(c => c.Type == ClaimTypes.Role)
                .Select(c => c.Value);
            return View();
        }

        [Authorize(Roles = "PayingUser")]
        public IActionResult PayingUserZone()
        {

            return View();
        }
    }
}
