// Copyright (c) Microsoft Corporation
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace XboxLiveCmdlet
{
    using Microsoft.Tools.WindowsDevicePortal;
    using Microsoft.Win32;
    using System;
    using System.Collections.Generic;
    using System.Management.Automation;

    [Cmdlet(VerbsCommon.Get, "XblTestAccounts")]
    public class GetXblTestAccounts : XboxliveCmdlet
    {
        protected override void ProcessRecord()
        {
            try
            {
                IEnumerable<string> result = Microsoft.Xbox.Services.Tool.Helper.GetTestAccountsAsync().Result;

                WriteObject(result, true);
            }
            catch (AggregateException e)
            {
                var innerEx = e.InnerException;
                WriteError(new ErrorRecord(innerEx, "GetXblTestAccounts failed", ErrorCategory.InvalidOperation, null));
            }
        }

    }
}
