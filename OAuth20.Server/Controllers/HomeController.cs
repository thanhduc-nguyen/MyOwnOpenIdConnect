using Microsoft.AspNetCore.Mvc;
using OAuth20.Server.OauthRequest;
using OAuth20.Server.Services.CodeService;
using OAuth20.Server.Services;
using System.IdentityModel.Tokens.Jwt;
using OAuth20.Server.Models;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace OAuth20.Server.Controllers
{
    public class HomeController : Controller
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IAuthorizeResultService _authorizeResultService;
        private readonly ICodeStoreService _codeStoreService;
        private readonly IConfiguration _configuration;

        public HomeController(IHttpContextAccessor httpContextAccessor, IAuthorizeResultService authorizeResultService, ICodeStoreService codeStoreService, IConfiguration configuration)
        {
            _httpContextAccessor = httpContextAccessor;
            _authorizeResultService = authorizeResultService;
            _codeStoreService = codeStoreService;
            _configuration = configuration;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Authorize(AuthorizationRequest authorizationRequest)
        {
            var result = _authorizeResultService.AuthorizeRequest(_httpContextAccessor, authorizationRequest);

            if (result.HasError)
                return RedirectToAction("Error", new { error = result.Error });

            var loginModel = new OpenIdConnectLoginRequest
            {
                RedirectUri = result.RedirectUri,
                Code = result.Code,
                RequestedScopes = result.RequestedScopes,
                Nonce = result.Nonce
            };

            return View("Login", loginModel);
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpGet]
        public IActionResult LoggedOut(string post_logout_redirect_uri, string state)
        {
            if (bool.Parse(_configuration["OpenIdConnect:AutomaticRedirectAfterSignOut"]))
            {
                return Redirect($"{post_logout_redirect_uri}?state={state}");
            }
            else
            {
                var model = new LoggedOutViewModel
                {
                    PostLogoutRedirectUri = post_logout_redirect_uri,
                    State = state
                };

                return View(model);
            }
        }

        [HttpPost]
        public async Task<IActionResult> Login(OpenIdConnectLoginRequest loginRequest)
        {
            var user = UserStore.Users.Find(u => u.Username.Equals(loginRequest.UserName, StringComparison.OrdinalIgnoreCase) &&
                u.Password.Equals(loginRequest.Password, StringComparison.OrdinalIgnoreCase));

            if(user != null)
            {
                var claims = user.Claims.ToList();
                claims.Add(new Claim("sub", user.SubjectId.ToString()));
                var claimIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var claimsPrincipal = new ClaimsPrincipal(claimIdentity);
                var result = _codeStoreService.UpdatedClientDataByCode(loginRequest.Code, loginRequest.RequestedScopes,
                    claimsPrincipal, nonce: loginRequest.Nonce);

                if (result != null)
                {
                    loginRequest.RedirectUri = loginRequest.RedirectUri + "&code=" + loginRequest.Code;
                    return Redirect(loginRequest.RedirectUri);
                }

                return RedirectToAction("Error", new { error = "invalid_request" });
            }
            else
            {
                return RedirectToAction("Error", new { error = "invalid username or password" });
            }
           
        }

        public JsonResult Token()
        {
            var result = _authorizeResultService.GenerateToken(_httpContextAccessor);

            return result.HasError ? Json("0") : Json(result);
        }

        public IActionResult Error(string error)
        {
            return View(error);
        }
    }
}
