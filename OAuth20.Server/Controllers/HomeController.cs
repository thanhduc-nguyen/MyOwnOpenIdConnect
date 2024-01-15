﻿using Microsoft.AspNetCore.Mvc;
using OAuth20.Server.OauthRequest;
using OAuth20.Server.Services.CodeService;
using OAuth20.Server.Services;

namespace OAuth20.Server.Controllers
{
    public class HomeController : Controller
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IAuthorizeResultService _authorizeResultService;
        private readonly ICodeStoreService _codeStoreService;

        public HomeController(IHttpContextAccessor httpContextAccessor, IAuthorizeResultService authorizeResultService, ICodeStoreService codeStoreService)
        {
            _httpContextAccessor = httpContextAccessor;
            _authorizeResultService = authorizeResultService;
            _codeStoreService = codeStoreService;
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

        [HttpPost]
        public async Task<IActionResult> Login(OpenIdConnectLoginRequest loginRequest)
        {
            // here I have to check if the username and passowrd is correct
            // and I will show you how to integrate the ASP.NET Core Identity
            // With our framework

            var result = _codeStoreService.UpdatedClientDataByCode(loginRequest.Code, loginRequest.RequestedScopes,
                loginRequest.UserName, nonce: loginRequest.Nonce);
            
            if (result != null)
            {
                loginRequest.RedirectUri = loginRequest.RedirectUri + "&code=" + loginRequest.Code;
                return Redirect(loginRequest.RedirectUri);
            }

            return RedirectToAction("Error", new { error = "invalid_request" });
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
