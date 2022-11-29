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
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.TestHost;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Monai.Deploy.Security.Authentication.Configurations;
using Monai.Deploy.Security.Authentication.Extensions;

namespace Monai.Deploy.Security.Authentication.Tests
{
    public partial class EndpointAuthorizationMiddlewareTest
    {
        [Theory]
        [InlineData("test.noauth.json")]
        [InlineData("test.emptyopenid.json")]
        public async Task GivenConfigurationFilesIsBad_ExpectExceptionToBeThrown(string configFile)
        {
            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            {
                using var host = await new HostBuilder().ConfigureWebHost(SetupWebServer(configFile)).StartAsync().ConfigureAwait(false);
            }).ConfigureAwait(false);
        }

        [Fact]
        public async Task GivenConfigurationFileToBypassAuthentication_ExpectToBypassAuthentication()
        {
            using var host = await new HostBuilder().ConfigureWebHost(SetupWebServer("test.bypassd.json")).StartAsync().ConfigureAwait(false);

            var server = host.GetTestServer();
            server.BaseAddress = new Uri("https://example.com/");

            var client = server.CreateClient();
            var responseMessage = await client.GetAsync("api/Test").ConfigureAwait(false);

            Assert.True(responseMessage.IsSuccessStatusCode);
        }

        [Fact]
        public async Task GivenConfigurationFileWithOpenIdConfigured_WhenUserIsNotAuthenticated_ExpectToDenyRequest()
        {
            using var host = await new HostBuilder().ConfigureWebHost(SetupWebServer("test.auth.json")).StartAsync().ConfigureAwait(false);

            var server = host.GetTestServer();
            server.BaseAddress = new Uri("https://example.com/");

            var client = server.CreateClient();
            var responseMessage = await client.GetAsync("api/Test").ConfigureAwait(false);

            Assert.Equal(HttpStatusCode.Unauthorized, responseMessage.StatusCode);
        }

        [Theory]
        [InlineData("monai-role-admin")]
        [InlineData("role-with-test")]
        public async Task GivenConfigurationFileWithOpenIdConfigured_WhenUserIsAuthenticated_ExpectToServeTheRequest(string role)
        {
            using var host = await new HostBuilder().ConfigureWebHost(SetupWebServer("test.auth.json")).StartAsync().ConfigureAwait(false);

            var server = host.GetTestServer();
            server.BaseAddress = new Uri("https://example.com/");

            var token = MockJwtTokenHandler.GenerateJwtToken(role);

            var client = server.CreateClient();
            client.DefaultRequestHeaders.Add("Authorization", $"{JwtBearerDefaults.AuthenticationScheme} {token}");
            var responseMessage = await client.GetAsync("api/Test").ConfigureAwait(false);

            Assert.Equal(HttpStatusCode.OK, responseMessage.StatusCode);

            var data = await responseMessage.Content.ReadFromJsonAsync<List<string>>().ConfigureAwait(false);

            Assert.NotNull(data);
            Assert.Collection(data,
                item => item.Equals("A", StringComparison.Ordinal),
                item => item.Equals("B", StringComparison.Ordinal),
                item => item.Equals("C", StringComparison.Ordinal));
        }

        [Theory]
        [InlineData("role-without-test")]
        public async Task GivenConfigurationFileWithOpenIdConfigured_WhenUserIsAuthenticatedWithoutProperRoles_ExpectToDenyRequest(string role)
        {
            using var host = await new HostBuilder().ConfigureWebHost(SetupWebServer("test.auth.json")).StartAsync().ConfigureAwait(false);

            var server = host.GetTestServer();
            server.BaseAddress = new Uri("https://example.com/");

            var token = MockJwtTokenHandler.GenerateJwtToken(role);

            var client = server.CreateClient();
            client.DefaultRequestHeaders.Add("Authorization", $"{JwtBearerDefaults.AuthenticationScheme} {token}");
            var responseMessage = await client.GetAsync("api/Test").ConfigureAwait(false);

            Assert.Equal(HttpStatusCode.Forbidden, responseMessage.StatusCode);
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

                        config.SigningKeys.Add(MockJwtTokenHandler.SecurityKey);
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
