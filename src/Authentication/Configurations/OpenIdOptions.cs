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

using Microsoft.Extensions.Configuration;

namespace Monai.Deploy.Security.Authentication.Configurations
{
    public class OpenIdOptions
    {
        [ConfigurationKeyName("ServerRealm")]
        public string? ServerRealm { get; set; }

        [ConfigurationKeyName("ServerRealmKey")]
        public string? ServerRealmKey { get; set; }

        [ConfigurationKeyName("ClientId")]
        public string? ClientId { get; set; }

        [ConfigurationKeyName("ClaimMappings")]
        public ClaimMappings? Claims { get; set; }

        [ConfigurationKeyName("Audiences")]
        public IList<string>? Audiences { get; set; }
    }
}
