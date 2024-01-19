using System.Security.Claims;

namespace OAuth20.Server.Models
{
    public class TestUser
    {
        public string SubjectId { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public IEnumerable<Claim> Claims { get; set; }
    }
}
