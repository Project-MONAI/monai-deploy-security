

using Microsoft.Extensions.Configuration;

namespace Monai.Deploy.Security.Authentication.Configurations
{
    public class BasicAuthOptions
    {
        [ConfigurationKeyName("userName")]
        public string? Id { get; set; }

        [ConfigurationKeyName("password")]
        public string? Password { get; set; }
    }
}
