using OAuth20.Server.Models;
using OAuth20.Server.OauthRequest;
using System.Security.Claims;

namespace OAuth20.Server.Services.CodeService
{
    public interface ICodeStoreService
    {
        string GenerateAuthorizationCode(AuthorizationRequest clientId, IList<string> requestedScope);
        AuthorizationCode GetClientDataByCode(string key);
        AuthorizationCode RemoveClientDataByCode(string key);
        AuthorizationCode UpdatedClientDataByCode(string key, IList<string> requestedScopes,
            ClaimsPrincipal claimsPrincipal, string nonce = null);
    }
}
