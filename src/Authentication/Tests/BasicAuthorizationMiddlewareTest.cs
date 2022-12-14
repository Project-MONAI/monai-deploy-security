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
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.TestHost;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Monai.Deploy.Security.Authentication.Configurations;
using Monai.Deploy.Security.Authentication.Extensions;

namespace Monai.Deploy.Security.Authentication.Tests
{
    public partial class BasicAuthorizationMiddlewareTest
    {


        [Fact]
        public async Task GivenConfigurationFileToBypassAuthentication_ExpectToBypassAuthentication()
        {
            using var host = await new HostBuilder().ConfigureWebHost(SetupWebServer("test.basicbypass.json")).StartAsync().ConfigureAwait(false);

            var server = host.GetTestServer();
            server.BaseAddress = new Uri("https://example.com/");

            var client = server.CreateClient();
            var responseMessage = await client.GetAsync("api/Test").ConfigureAwait(false);

            Assert.True(responseMessage.IsSuccessStatusCode);
        }



        [Fact]
        public async Task GivenConfigurationFileWithBasicConfigured_WhenUserIsNotAuthenticated_ExpectToDenyRequest()
        {
            using var host = await new HostBuilder().ConfigureWebHost(SetupWebServer("test.basic.json")).StartAsync().ConfigureAwait(false);

            var server = host.GetTestServer();
            server.BaseAddress = new Uri("https://example.com/");

            var client = server.CreateClient();
            var responseMessage = await client.GetAsync("api/Test").ConfigureAwait(false);

            Assert.Equal(HttpStatusCode.Unauthorized, responseMessage.StatusCode);
        }

        [Fact]
        public async Task GivenConfigurationFileWithBasicConfigured_WhenUserIsAuthenticated_ExpectToAllowRequest()
        {
            using var host = await new HostBuilder().ConfigureWebHost(SetupWebServer("test.basic.json")).StartAsync().ConfigureAwait(false);

            var server = host.GetTestServer();
            server.BaseAddress = new Uri("https://example.com/");

            var client = server.CreateClient();
            client.DefaultRequestHeaders.Add("Authorization", $"Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes("user:pass"))}");
            var responseMessage = await client.GetAsync("api/Test").ConfigureAwait(false);

            Assert.Equal(HttpStatusCode.OK, responseMessage.StatusCode);
        }

        [Fact]
        public async Task GivenConfigurationFileWithBasicConfigured_WhenHeaderIsInvalid_ExpectToDenyRequest()
        {
            using var host = await new HostBuilder().ConfigureWebHost(SetupWebServer("test.basic.json")).StartAsync().ConfigureAwait(false);

            var server = host.GetTestServer();
            server.BaseAddress = new Uri("https://example.com/");

            var client = server.CreateClient();
            client.DefaultRequestHeaders.Add("Authorization", $"BasicBad {Convert.ToBase64String(Encoding.UTF8.GetBytes("user:pass"))}");
            var responseMessage = await client.GetAsync("api/Test").ConfigureAwait(false);

            Assert.Equal(HttpStatusCode.Unauthorized, responseMessage.StatusCode);
        }

        private static Action<IWebHostBuilder> SetupWebServer(string configFile) => webBuilder =>
        {
            webBuilder
                .ConfigureAppConfiguration((builderContext, config) =>
                {
                    config.Sources.Clear();
                    config.AddJsonFile(configFile, optional: false);
                    _ = config.Build();
                })
                .ConfigureLogging((hostContext, logging) =>
                {
                    logging.AddDebug();
                    logging.AddConsole();
                })
                .ConfigureServices((hostContext, services) =>
                {
                    services.AddOptions<AuthenticationOptions>().Bind(hostContext.Configuration.GetSection("MonaiDeployAuthentication"));

                    services.AddControllers();
                    services.AddMonaiAuthentication();

                    services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, op =>
                    {
                        var config = new OpenIdConnectConfiguration()
                        {
                            Issuer = Guid.NewGuid().ToString(),
                        };

                        config.SigningKeys.Add(EndpointAuthorizationMiddlewareTest.MockJwtTokenHandler.SecurityKey);
                        op.Configuration = config;
                    });
                })
                .Configure(app =>
                {
                    app.UseHttpsRedirection();
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpointAuthorizationMiddleware();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapControllers();
                    });
                })
                .UseTestServer();
        };
    }
}
