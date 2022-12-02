/*
 * Copyright 2022 MONAI Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Monai.Deploy.Security.Authentication.Middleware;
using AuthenticationOptions = Monai.Deploy.Security.Authentication.Configurations.AuthenticationOptions;

namespace Monai.Deploy.Security.Authentication.Extensions
{
    public static class MonaiAuthenticationExtensions
    {
        /// <summary>
        /// Adds MONAI OpenID Configuration to services.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/>.</param>
        /// <param name="configuration">The <see cref="IConfiguration"/>.</param>
        public static IServiceCollection AddMonaiAuthentication(
            this IServiceCollection services)
        {
            var serviceProvider = services.BuildServiceProvider();
            var logger = serviceProvider.GetRequiredService<ILogger<EndpointAuthorizationMiddleware>>();
            var configurations = serviceProvider.GetRequiredService<IOptions<AuthenticationOptions>>();

            if (configurations.Value.BypassAuth(logger))
            {
                services.AddAuthentication(options => options.DefaultAuthenticateScheme = AuthKeys.BypassSchemeName)
                        .AddScheme<AuthenticationSchemeOptions, BypassAuthenticationHandler>(AuthKeys.BypassSchemeName, null);
                return services;
            }

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, AuthKeys.OpenId, options =>
            {
                options.Authority = configurations.Value.OpenId!.Realm;
                options.Audience = configurations.Value.OpenId!.Realm;
                options.RequireHttpsMetadata = false;

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configurations.Value.OpenId!.RealmKey!)),
                    RoleClaimType = configurations.Value.OpenId.RoleClaimType,
                    ValidIssuer = configurations.Value.OpenId.Realm,
                    ValidAudiences = configurations.Value.OpenId.Audiences,
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateLifetime = true,
                    ValidateAudience = true,
                };
            });

            services.AddAuthorization();
            return services;
        }
    }
}
