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

using Microsoft.AspNetCore.Builder;
using Monai.Deploy.Security.Authentication.Middleware;

namespace Monai.Deploy.Security.Authentication.Extensions
{
    /// <summary>
    /// EndpointAuthorizationMiddlewareExtensions for IApplication builder
    /// </summary>
    public static class IApplicationBuilderExtensions
    {
        public static IApplicationBuilder UseEndpointAuthorizationMiddleware(
            this IApplicationBuilder builder)
        {
            builder.UseMiddleware<BasicAuthorizationMiddleware>();
            builder.UseMiddleware<EndpointAuthorizationMiddleware>();
            return builder;
        }
    }
}
