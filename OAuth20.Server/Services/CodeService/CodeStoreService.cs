using Microsoft.AspNetCore.Authentication.Cookies;
using OAuth20.Server.Models;
using OAuth20.Server.OauthRequest;
using System.Collections.Concurrent;
using System.Security.Claims;

namespace OAuth20.Server.Services.CodeService
{
    public class CodeStoreService : ICodeStoreService
    {
        private readonly ConcurrentDictionary<string, AuthorizationCode> _codeIssued = new ConcurrentDictionary<string, AuthorizationCode>();
        private readonly ClientStore _clientStore = new ClientStore();

        // Here I genrate the code for authorization, and I will store it 
        // in the Concurrent Dictionary

        public string GenerateAuthorizationCode(AuthorizationRequest authorizationRequest, IList<string> requestedScope)
        {
            var client = _clientStore.Clients.Where(x => x.ClientId == authorizationRequest.client_id).FirstOrDefault();

            if (client != null)
            {
                var code = Guid.NewGuid().ToString();

                var authoCode = new AuthorizationCode
                {
                    ClientId = client.ClientId,
                    RedirectUri = client.RedirectUri,
                    RequestedScopes = requestedScope,
                    Nonce = authorizationRequest.nonce,
                    CodeChallenge = authorizationRequest.code_challenge,
                    CodeChallengeMethod = authorizationRequest.code_challenge_method,
                };

                // then store the code is the Concurrent Dictionary
                _codeIssued[code] = authoCode;

                return code;
            }

            return string.Empty;
        }

        public AuthorizationCode? GetClientDataByCode(string key)
        {
            if (_codeIssued.TryGetValue(key, out AuthorizationCode authorizationCode))
            {
                return authorizationCode;
            }

            return null;
        }

        public AuthorizationCode? RemoveClientDataByCode(string key)
        {
            _codeIssued.TryRemove(key, out AuthorizationCode authorizationCode);

            return null;
        }

        // Before updating the Concurrent Dictionary I have to Process User Sign In, and check the user crediential first
        // But here I merge this process here inside update Concurrent Dictionary method
        public AuthorizationCode UpdatedClientDataByCode(string key, IList<string> requestedScopes,
            string userName, string password = null, string nonce = null)
        {
            var oldValue = GetClientDataByCode(key);

            if (oldValue != null)
            {
                // check the requested scopes with the one that are stored in the Client Store 
                var client = _clientStore.Clients.Where(x => x.ClientId == oldValue.ClientId).FirstOrDefault();

                if (client != null)
                {
                    var clientScope = (from m in client.AllowedScopes
                                       where requestedScopes.Contains(m)
                                       select m).ToList();

                    if (!clientScope.Any())
                    {
                        return null;
                    }

                    var newValue = new AuthorizationCode
                    {
                        ClientId = oldValue.ClientId,
                        CreationTime = oldValue.CreationTime,
                        IsOpenId = requestedScopes.Contains("openId") || requestedScopes.Contains("profile"),
                        RedirectUri = oldValue.RedirectUri,
                        RequestedScopes = requestedScopes,
                        Nonce = oldValue.Nonce,
                        CodeChallenge = oldValue.CodeChallenge,
                        CodeChallengeMethod = oldValue.CodeChallengeMethod,
                    };

                    // ------------------ I suppose the user name and password is correct  -----------------
                    var claims = new List<Claim>();
                    
                    if (newValue.IsOpenId)
                    {
                        // TODO
                        // Add more claims to the claims

                    }

                    var claimIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    newValue.Subject = new ClaimsPrincipal(claimIdentity);
                    // ------------------ -----------------------------------------------  -----------------

                    var result = _codeIssued.TryUpdate(key, newValue, oldValue);

                    if (result)
                    {
                        return newValue;
                    }

                    return null;
                }
            }

            return null;
        }
    }
}
