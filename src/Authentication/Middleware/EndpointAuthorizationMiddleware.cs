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

using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Monai.Deploy.Security.Authentication.Configurations;
using Monai.Deploy.Security.Authentication.Extensions;

namespace Monai.Deploy.Security.Authentication.Middleware
{
    /// <summary>
    /// EndpointAuthorizationMiddleware for checking endpoint configuration.
    /// </summary>
    public class EndpointAuthorizationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IOptions<AuthenticationOptions> _options;
        private readonly ILogger<EndpointAuthorizationMiddleware> _logger;

        public EndpointAuthorizationMiddleware(RequestDelegate next, IOptions<AuthenticationOptions> options, ILogger<EndpointAuthorizationMiddleware> logger)
        {
            _next = next;
            _options = options;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext httpcontext)
        {
            if (_options.Value.BypassAuth(_logger))
            {
                await _next(httpcontext);
                return;
            }

            if (httpcontext.User is not null
                && httpcontext.User.Identity is not null
                && httpcontext.User.Identity.IsAuthenticated)
            {
                if (httpcontext.GetRouteValue("controller") is string controller)
                {
                    var validEndpoints = httpcontext.GetValidEndpoints(_options.Value.OpenId!.Claims!.RequiredAdminClaims!, _options.Value.OpenId!.Claims!.RequiredUserClaims!);
                    var result = validEndpoints.Any(e => e.Equals(controller, StringComparison.InvariantCultureIgnoreCase)) || validEndpoints.Contains("all");

                    if (result is false)
                    {
                        httpcontext.Response.StatusCode = (int)HttpStatusCode.Forbidden;

                        await httpcontext.Response.CompleteAsync().ConfigureAwait(false);

                        return;
                    }
                }
                await _next(httpcontext).ConfigureAwait(false);
            }
            else
            {
                httpcontext.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
            }
        }
    }
}
