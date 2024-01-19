namespace OAuth20.Server.Models
{
    public class ClientStore
    {
        public IEnumerable<Client> Clients = new[]
        {
            new Client
            {
                ClientName = "myclient .Net 6",
                ClientId = "myclient",
                ClientSecret = "123456789",
                AllowedScopes = new[]{ "openid", "profile"},
                GrantType = GrantTypes.Code,
                IsActive = true,
                ClientUri = "https://localhost:2000",
                RedirectUri = "https://localhost:2000/signin-oidc",
                UsePkce = true,
            }
        };
    }
}