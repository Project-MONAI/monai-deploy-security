/*
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

using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Claim = System.Security.Claims.Claim;

namespace Monai.Deploy.Security.Authentication.Tests
{
    public partial class EndpointAuthorizationMiddlewareTest
    {
        public static class MockJwtTokenHandler
        {
            public static string Issuer { get; } = "TEST-REALM";
            public static SecurityKey SecurityKey { get; }
            public static SigningCredentials SigningCredentials { get; }

            private static readonly JwtSecurityTokenHandler TokenHandler = new();

            static MockJwtTokenHandler()
            {
                SecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("l9ZRlbMQBt9k1klUUrlWFuke8WbqnEde")) { KeyId = Guid.NewGuid().ToString() };
                SigningCredentials = new SigningCredentials(SecurityKey, SecurityAlgorithms.HmacSha256Signature);
            }

            public static string GenerateJwtToken(string role, int expiresInMinutes = 5)
            {
                var claims = new[] { new Claim("user_roles", role) };
                return TokenHandler.WriteToken(new JwtSecurityToken(Issuer, "monai-app", claims, null, DateTime.UtcNow.AddMinutes(expiresInMinutes), SigningCredentials));
            }
        }
    }
}
