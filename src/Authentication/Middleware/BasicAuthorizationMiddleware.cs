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
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Monai.Deploy.Security.Authentication.Configurations;
using Monai.Deploy.Security.Authentication.Extensions;

namespace Monai.Deploy.Security.Authentication.Middleware
{
    /// <summary>
    /// EndpointAuthorizationMiddleware for checking endpoint configuration.
    /// </summary>
    public class BasicAuthorizationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IOptions<AuthenticationOptions> _options;
        private readonly ILogger<BasicAuthorizationMiddleware> _logger;

        public BasicAuthorizationMiddleware(
            RequestDelegate next,
            IOptions<AuthenticationOptions> options,
            ILogger<BasicAuthorizationMiddleware> logger)
        {
            _next = next;
            _options = options;
            _logger = logger;
        }


        public async Task InvokeAsync(HttpContext httpContext)
        {

            if ((_options.Value.BypassAuthentication.HasValue && _options.Value.BypassAuthentication.Value is true)
                || _options.Value.BasicAuthEnabled(_logger) is false)
            {
                await _next(httpContext).ConfigureAwait(false);
                return;
            }
            try
            {
                var authHeader = AuthenticationHeaderValue.Parse(httpContext.Request.Headers["Authorization"]);
                if (authHeader.Scheme == "Basic")
                {
                    var credentialBytes = Convert.FromBase64String(authHeader.Parameter);
                    var credentials = Encoding.UTF8.GetString(credentialBytes).Split(':', 2);
                    var username = credentials[0];
                    var password = credentials[1];
                    if (string.Compare(username, _options.Value.BasicAuth.Id, false) is 0 &&
                        string.Compare(password, _options.Value.BasicAuth.Password, false) is 0)
                    {
                        var claims = new[] { new Claim("name", credentials[0]) };
                        var identity = new ClaimsIdentity(claims, "Basic");
                        var claimsPrincipal = new ClaimsPrincipal(identity);
                        httpContext.User = claimsPrincipal;
                        await _next(httpContext).ConfigureAwait(false);
                        return;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception ");
            }
            httpContext.Response.StatusCode = (int)HttpStatusCode.Unauthorized;

        }
    }
}
