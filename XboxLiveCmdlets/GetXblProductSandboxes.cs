// Copyright (c) Microsoft Corporation
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace XboxLiveCmdlet
{
    using Microsoft.Tools.WindowsDevicePortal;
    using Microsoft.Win32;
    using System;
    using System.Collections.Generic;
    using System.Management.Automation;

    [Cmdlet(VerbsCommon.Get, "XblProductSandboxes")]
    public class GetXblProductSandboxes : XboxliveCmdlet
    {
        protected override void ProcessRecord()
        {
            try
            {
                IEnumerable<string> result = Microsoft.Xbox.Services.Tool.Helper.GetSandboxesAsync().Result;

                WriteObject(result, true);
            }
            catch (AggregateException e)
            {
                var innerEx = e.InnerException;
                WriteError(new ErrorRecord(innerEx, "GetXblProductSandboxes failed", ErrorCategory.InvalidOperation, null));
            }
        }

    }
}
