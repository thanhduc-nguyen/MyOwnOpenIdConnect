using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualBasic;
using OAuth20.Server.Common;
using OAuth20.Server.Models;
using OAuth20.Server.OauthRequest;
using OAuth20.Server.OauthResponse;
using OAuth20.Server.Services.CodeService;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace OAuth20.Server.Services
{
    public class AuthorizeResultService : IAuthorizeResultService
    {
        private static string keyAlg = "66007d41-6924-49f2-ac0c-e63c4b1a1730";
        private readonly ClientStore _clientStore = new ClientStore();
        private readonly ICodeStoreService _codeStoreService;

        public AuthorizeResultService(ICodeStoreService codeStoreService)
        {
            _codeStoreService = codeStoreService;
        }

        public AuthorizeResponse AuthorizeRequest(IHttpContextAccessor httpContextAccessor, AuthorizationRequest authorizationRequest)
        {
            var response = new AuthorizeResponse();

            if (httpContextAccessor == null)
            {
                response.Error = ErrorTypeEnum.ServerError.GetEnumDescription();
                return response;
            }

            var client = VerifyClientById(authorizationRequest.client_id);
            if (!client.IsSuccess)
            {
                response.Error = client.ErrorDescription;
                return response;
            }

            if (string.IsNullOrEmpty(authorizationRequest.response_type) || authorizationRequest.response_type != "code")
            {
                response.Error = ErrorTypeEnum.InvalidRequest.GetEnumDescription();
                response.ErrorDescription = "ResponseType is required or is not valid";
                return response;
            }

            if (!authorizationRequest.redirect_uri.IsRedirectUriStartWithHttps() && !httpContextAccessor.HttpContext.Request.IsHttps)
            {
                response.Error = ErrorTypeEnum.InvalidRequest.GetEnumDescription();
                response.ErrorDescription = "RedirectUrl is not secure, MUST be TLS";
                return response;
            }


            // check the return url is match the one that in the client store


            // check the scope in the client store with the
            // one that is comming from the request MUST be matched at leaset one
            var scopes = authorizationRequest.scope.Split(' ');

            var clientScopes = from m in client.Client.AllowedScopes
                               where scopes.Contains(m)
                               select m;

            if (!clientScopes.Any())
            {
                response.Error = ErrorTypeEnum.InValidScope.GetEnumDescription();
                response.ErrorDescription = "scopes are invalids";
                return response;
            }

            string nonce = httpContextAccessor.HttpContext.Request.Query["nonce"].ToString();

            // Verify that a scope parameter is present and contains the openid scope value.
            // (If no openid scope value is present,
            // the request may still be a valid OAuth 2.0 request, but is not an OpenID Connect request.)

            string code = _codeStoreService.GenerateAuthorizationCode(authorizationRequest, clientScopes.ToList());
            if (code == null)
            {
                response.Error = ErrorTypeEnum.TemporarilyUnAvailable.GetEnumDescription();
                return response;
            }

            response.RedirectUri = client.Client.RedirectUri + "?response_type=code" + "&state=" + authorizationRequest.state;
            response.Code = code;
            response.State = authorizationRequest.state;
            response.RequestedScopes = clientScopes.ToList();
            response.Nonce = nonce;

            return response;
        }

        public TokenResponse GenerateToken(IHttpContextAccessor httpContextAccessor)
        {
            var request = new TokenRequest
            {
                code_verifier = httpContextAccessor.HttpContext.Request.Form["code_verifier"],
                client_id = httpContextAccessor.HttpContext.Request.Form["client_id"],
                client_secret = httpContextAccessor.HttpContext.Request.Form["client_secret"],
                code = httpContextAccessor.HttpContext.Request.Form["code"],
                grant_type = httpContextAccessor.HttpContext.Request.Form["grant_type"],
                redirect_uri = httpContextAccessor.HttpContext.Request.Form["redirect_uri"]
            };

            var checkClientResult = VerifyClientById(request.client_id, true, request.client_secret);
            if (!checkClientResult.IsSuccess)
            {
                return new TokenResponse { Error = checkClientResult.Error, ErrorDescription = checkClientResult.ErrorDescription };
            }

            // check code from the Concurrent Dictionary
            var clientCodeChecker = _codeStoreService.GetClientDataByCode(request.code);
            if (clientCodeChecker == null)
            {
                return new TokenResponse { Error = ErrorTypeEnum.InvalidGrant.GetEnumDescription() };
            }


            // check if the current client who made this authentication request
            if (request.client_id != clientCodeChecker.ClientId)
                return new TokenResponse { Error = ErrorTypeEnum.InvalidGrant.GetEnumDescription() };

            // TODO: 
            // also I have to check the rediret uri 

            if (checkClientResult.Client.UsePkce)
            {
                var pkceResult = CodeVerifierIsSendByTheClientThatReceivedTheCode(request.code_verifier,
                    clientCodeChecker.CodeChallenge, clientCodeChecker.CodeChallengeMethod);

                if (!pkceResult)
                    return new TokenResponse { Error = ErrorTypeEnum.InvalidGrant.GetEnumDescription() };
            }

            // Here I will Issue the Id_token
            JwtSecurityToken id_token = null;
            if (clientCodeChecker.IsOpenId)
            {
                // Generate Identity Token
                string iat = DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds.ToString();

                string[] amrs = new string[] { "pwd" };

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyAlg));
                var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);


                var claims = clientCodeChecker.Subject.Claims.ToList();
                claims.Add(new Claim("iat", iat));
                claims.Add(new Claim("nonce", clientCodeChecker.Nonce));
                
                foreach (var amr in amrs)
                {
                    claims.Add(new Claim("amr", amr)); // authentication method reference 
                }

                id_token = new JwtSecurityToken("https://localhost:7000", request.client_id, claims, signingCredentials: credentials, 
                    expires: DateTime.UtcNow.AddMinutes(int.Parse("5")));
            }

            // Here I have to generate access token 
            var key_at = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyAlg));
            var credentials_at = new SigningCredentials(key_at, SecurityAlgorithms.HmacSha256);
            var claims_at = new List<Claim>();
            
            var access_token = new JwtSecurityToken("https://localhost:7275", request.client_id, claims_at, signingCredentials: credentials_at,
                expires: DateTime.UtcNow.AddMinutes(
                   int.Parse("5")));

            // here remoce the code from the Concurrent Dictionary
            _codeStoreService.RemoveClientDataByCode(request.code);

            return new TokenResponse
            {
                access_token = new JwtSecurityTokenHandler().WriteToken(access_token),
                id_token = id_token != null ? new JwtSecurityTokenHandler().WriteToken(id_token) : null,
                code = request.code
            };
        }

        private CheckClientResult VerifyClientById(string clientId, bool checkWithSecret = false, string? clientSecret = null)
        {
            var result = new CheckClientResult()
            {
                IsSuccess = false
            };

            if (!string.IsNullOrWhiteSpace(clientId))
            {
                var client = _clientStore.Clients.Where(x => x.ClientId.Equals(clientId, StringComparison.OrdinalIgnoreCase)).FirstOrDefault();

                if (client != null)
                {
                    if (checkWithSecret && !string.IsNullOrEmpty(clientSecret))
                    {
                        bool hasSamesecretId = client.ClientSecret.Equals(clientSecret, StringComparison.InvariantCulture);
                        if (!hasSamesecretId)
                        {
                            result.Error = ErrorTypeEnum.InvalidClient.GetEnumDescription();
                            return result;
                        }
                    }

                    // check if client is enabled or not
                    if (client.IsActive)
                    {
                        result.IsSuccess = true;
                        result.Client = client;

                        return result;
                    }
                    else
                    {
                        result.ErrorDescription = ErrorTypeEnum.UnAuthoriazedClient.GetEnumDescription();
                        return result;
                    }
                }
            }

            result.ErrorDescription = ErrorTypeEnum.AccessDenied.GetEnumDescription();
            return result;
        }

        private bool CodeVerifierIsSendByTheClientThatReceivedTheCode(string codeVerifier, string codeChallenge, string codeChallengeMethod)
        {
            var odeVerifireAsByte = Encoding.ASCII.GetBytes(codeVerifier);

            if (codeChallengeMethod == "plain")
            {
                using var shaPalin = SHA256.Create();
                var computedHashPalin = shaPalin.ComputeHash(odeVerifireAsByte);
                var tranformedResultPalin = Base64UrlEncoder.Encode(computedHashPalin);
                return tranformedResultPalin.Equals(codeChallenge);
            }

            using var shaS256 = SHA256.Create();
            var computedHashS256 = shaS256.ComputeHash(odeVerifireAsByte);
            var tranformedResultS256 = Base64UrlEncoder.Encode(computedHashS256);

            return tranformedResultS256.Equals(codeChallenge);
        }
    }
}
