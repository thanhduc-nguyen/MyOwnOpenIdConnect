namespace OAuth20.Server.Models
{
    public class LoggedOutViewModel
    {
        public string PostLogoutRedirectUri;
        public string State { get; set; }
    }
}
