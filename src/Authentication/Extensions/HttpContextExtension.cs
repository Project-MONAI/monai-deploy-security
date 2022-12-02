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
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Monai.Deploy.Security.Authentication.Middleware;
using Monai.Deploy.WorkflowManager.Logging;

namespace Monai.Deploy.Security.Authentication.Extensions
{
    public static class HttpContextExtension
    {
        /// <summary>
        /// Gets endpoints specified in config for roles in claims.
        /// </summary>
        /// <param name="httpContext"></param>
        /// <param name="requiredClaims"></param>
        /// <returns></returns>
        public static List<string> GetValidEndpoints(this HttpContext httpContext, ILogger<EndpointAuthorizationMiddleware> logger, List<Configurations.ClaimMapping> adminClaims, List<Configurations.ClaimMapping> userClaims)
        {
            Guard.Against.Null(adminClaims);
            Guard.Against.Null(userClaims);

            foreach (var claim in httpContext.User.Claims)
            {
                logger.UserClaimFound(claim.Type, claim.Value);

            }

            foreach (var claim in adminClaims!)
            {
                foreach (var role in claim.ClaimValues)
                {
                    logger.CheckingUserClaim(claim.ClaimType, role);
                    if (httpContext.User.HasClaim(claim.ClaimType, role))
                    {
                        return new List<string> { "*" };
                    }
                }
            }

            var endpoints = new List<string>();
            foreach (var claim in userClaims!)
            {
                foreach (var role in claim.ClaimValues)
                {
                    logger.CheckingUserClaim(claim.ClaimType, role);
                    if (httpContext.User.HasClaim(claim.ClaimType, role))
                    {
                        endpoints.AddRange(claim.Endpoints!);
                    }
                }
            }

            return endpoints.Distinct().ToList();
        }
    }
}
