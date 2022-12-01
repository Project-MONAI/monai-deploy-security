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

using Ardalis.GuardClauses;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Monai.Deploy.Security.Authentication.Extensions;
using Monai.Deploy.WorkflowManager.Logging;

namespace Monai.Deploy.Security.Authentication.Configurations
{
    public class AuthenticationOptions
    {
        [ConfigurationKeyName("BypassAuthentication")]
        public bool? BypassAuthentication { get; set; }

        [ConfigurationKeyName("OpenId")]
        public OpenIdOptions? OpenId { get; set; }

        public bool BypassAuth(ILogger logger)
        {
            Guard.Against.Null(logger);

            if (BypassAuthentication.HasValue && BypassAuthentication.Value is true)
            {
                logger.BypassAuthentication();
                return true;
            }

            if (OpenId is null)
            {
                throw new InvalidOperationException("OpenId configuration is invalid.");
            }
            if (OpenId.Claims is null || OpenId.Claims.UserClaims!.IsNullOrEmpty() || OpenId.Claims.AdminClaims!.IsNullOrEmpty())
            {
                throw new InvalidOperationException("No claims defined for OpenId.");
            }
            if (string.IsNullOrWhiteSpace(OpenId.ClientId))
            {
                throw new InvalidOperationException("No ClientId defined for OpenId.");
            }
            if (string.IsNullOrWhiteSpace(OpenId.ServerRealmKey))
            {
                throw new InvalidOperationException("No ServerRealmKey defined for OpenId.");
            }
            if (string.IsNullOrWhiteSpace(OpenId.ServerRealm))
            {
                throw new InvalidOperationException("No ServerRealm defined for OpenId.");
            }

            return false;
        }
    }
}
