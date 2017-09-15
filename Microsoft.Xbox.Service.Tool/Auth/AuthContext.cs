// Copyright (c) Microsoft Corporation
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Xbox.Services.Tool
{
    using System.Threading.Tasks;

    internal interface IAuthContext
    {
        string XtdsEndpoint { get; set; }

        Task<string> AcquireTokenSilentAsync();

        Task<string> AcquireTokenAsync(string userName);

        DevAccountSource AccountSource { get; }
    }
}
