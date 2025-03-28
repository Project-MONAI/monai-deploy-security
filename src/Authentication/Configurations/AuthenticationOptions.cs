﻿/*
 * Copyright 2022-2025 MONAI Consortium
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
        [ConfigurationKeyName("bypassAuthentication")]
        public bool? BypassAuthentication { get; set; }

        [ConfigurationKeyName("openId")]
        public OpenIdOptions? OpenId { get; set; }

        [ConfigurationKeyName("basicAuth")]
        public BasicAuthOptions? BasicAuth { get; set; }

        public bool BypassAuth(ILogger logger)
        {
            Guard.Against.Null(logger);

            if (BypassAuthentication.HasValue && BypassAuthentication.Value is true)
            {
                logger.BypassAuthentication();
                return true;
            }

            if (BasicAuthEnabled(logger))
            {
                return false;
            }

            if (OpenId is null)
            {
                throw new InvalidOperationException("openId configuration is invalid.");
            }
            if (string.IsNullOrWhiteSpace(OpenId.ClientId))
            {
                throw new InvalidOperationException("No clientId defined for OpenId.");
            }
            if (string.IsNullOrWhiteSpace(OpenId.RealmKey))
            {
                throw new InvalidOperationException("No realmKey defined for OpenId.");
            }
            if (string.IsNullOrWhiteSpace(OpenId.Realm))
            {
                throw new InvalidOperationException("No realm defined for OpenId.");
            }
            if (OpenId.Claims is null || OpenId.Claims.UserClaims!.IsNullOrEmpty() || OpenId.Claims.AdminClaims!.IsNullOrEmpty())
            {
                throw new InvalidOperationException("No claimMappings defined for OpenId.");
            }

            ValidateClaims(OpenId.Claims.UserClaims!, true);
            ValidateClaims(OpenId.Claims.AdminClaims!, false);

            return false;
        }

        public bool BasicAuthEnabled(ILogger logger)
        {
            if (BasicAuth is not null && BasicAuth.Id is not null && BasicAuth.Password is not null)
            {
                return true;
            }
            return false;
        }

        private void ValidateClaims(List<ClaimMapping> claims, bool validateEndpoints)
        {
            foreach (var claim in claims)
            {
                if (string.IsNullOrWhiteSpace(claim.ClaimType))
                {
                    throw new InvalidOperationException("Value for claimType is invalid.");
                }

                if (claim.ClaimValues.IsNullOrEmpty())
                {
                    throw new InvalidOperationException("Value for claimType is invalid.");
                }

                foreach (var claimValue in claim.ClaimValues)
                {
                    if (string.IsNullOrWhiteSpace(claimValue))
                    {
                        throw new InvalidOperationException($"Invalid claimValue for {claim.ClaimType}.");
                    }
                }

                if (validateEndpoints && claim.Endpoints!.IsNullOrEmpty())
                {
                    throw new InvalidOperationException("Value for claimType is invalid.");
                }
            }
        }
    }
}
