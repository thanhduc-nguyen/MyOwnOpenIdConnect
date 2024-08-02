using OAuth20.Server.Models;
using System.Security.Claims;

namespace OAuth20.Server
{
    public class UserStore
    {
        public static List<TestUser> Users
        {
            get
            {
                return new List<TestUser>
            {
                new TestUser
                {
                    SubjectId = "ca9c5923-d77d-4ee3-bdce-71a8c6671fc6",
                    Username = "rooney",
                    Password = "p@ssword",

                    Claims = new List<Claim>
                    {
                        new Claim("role", "FreeUser"),
                        new Claim("given_name", "Wayne"),
                        new Claim("family_name", "Rooney")
                    }
                },
                new TestUser
                {
                    SubjectId = "ee76d6df-2c4a-4390-94c1-7c9480bf53e3",
                    Username = "scholes",
                    Password = "p@ssword",

                    Claims = new List<Claim>
                    {
                        new Claim("role", "PayingUser"),
                        new Claim("given_name", "Paul"),
                        new Claim("family_name", "Scholes")
                    }
                }
            };
            }
        }
    }
}
