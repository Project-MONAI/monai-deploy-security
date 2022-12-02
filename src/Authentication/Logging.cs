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

using Microsoft.Extensions.Logging;

namespace Monai.Deploy.WorkflowManager.Logging
{
    public static partial class Log
    {
        [LoggerMessage(EventId = 500000, Level = LogLevel.Information, Message = "Bypass authentication.")]
        public static partial void BypassAuthentication(this ILogger logger);

        [LoggerMessage(EventId = 500001, Level = LogLevel.Debug, Message = "User '{user}' attempting to access controller '{controller}'.")]
        public static partial void UserAccessingController(this ILogger logger, string? user, string controller);

        [LoggerMessage(EventId = 500002, Level = LogLevel.Debug, Message = "User '{user}' access denied due to limited permissions: '{permissions}'.")]
        public static partial void UserAccessDenied(this ILogger logger, string? user, string? permissions);

        [LoggerMessage(EventId = 500003, Level = LogLevel.Trace, Message = "User claim {claim}={value}.")]
        public static partial void UserClaimFound(this ILogger logger, string? claim, string? value);

        [LoggerMessage(EventId = 500004, Level = LogLevel.Trace, Message = "Checking user claim {claim}={value}.")]
        public static partial void CheckingUserClaim(this ILogger logger, string? claim, string? value);
    }
}
