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
    public class ClaimMappings
    {
        [ConfigurationKeyName("userClaims")]
        public List<ClaimMapping>? UserClaims { get; set; }

        [ConfigurationKeyName("adminClaims")]
        public List<ClaimMapping>? AdminClaims { get; set; }
    }

    public class ClaimMapping
    {
        [ConfigurationKeyName("claimType")]
        public string ClaimType { get; set; } = string.Empty;

        [ConfigurationKeyName("claimValues")]
        public List<string> ClaimValues { get; set; } = new List<string>();

        [ConfigurationKeyName("endpoints")]
        public List<string>? Endpoints { get; set; } = default;
    }
}
