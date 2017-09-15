// Copyright (c) Microsoft Corporation
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Xbox.Services.Tool
{
    using System;

    internal class ClientSettings
    {

        public static ClientSettings Singleton
        {
            get
            {
                lock(singletonLock)
                {
                    if (singleton == null)
                    {
                        singleton = new ClientSettings("");
                    }
                }

                return singleton;
            }
        }

        private static object singletonLock = new object();
        private static ClientSettings singleton;


        private ClientSettings(string environment)
        {
            if (string.IsNullOrEmpty(environment))
            {
                environment = "PROD";
            }

            Log.WriteLog($"client setting environment: {environment}");

            // Override values for other environments
            if (environment.ToUpper() == "DNET")
            {
                this.OmegaResetToolEndpoint = "https://eraser.dnet.xboxlive.com";
                this.UDCAuthEndpoint = "https://devx.microsoft-tst.com/xdts/authorize";
                this.XmintAuthEndpoint = "https://xmint.dnet.xboxlive.com/adfs/authorize?rp=https%3A%2F%2Fxdp.dnet.xboxlive.com%2F";
                this.XorcEndpoint = "https://xorc.dnet.xboxlive.com";
                this.XtasEndpoint = "https://xtas.dnet.xboxlive.com";
                this.XdpqEndpoint = "http://jicailiu5";
            }

        }

        public string ActiveDirectoryAuthenticationEndpoint { get; private set; } = "https://login.microsoftonline.com/";

        public string OmegaResetToolEndpoint { get; private set; } = "https://eraser.xboxlive.com";

        public string XorcEndpoint { get; private set; } = "https://xorc.xboxlive.com";

        public string XtasEndpoint { get; private set; } = "https://xtas.xboxlive.com";

        public string XDTSToolTokenType { get; private set; } = "http://oauth.net/grant_type/jwt/1.0/bearer";

        // TODO: Update this to runtime etoken after it's ready, for now we use design time etoken.
        public string XDTSToolRelyingParty { get; private set; } = "http://developer.xboxlive.com";
        public string AADApplicationId { get; private set; } = "872cd9fa-d31f-45e0-9eab-6e460a02d1f1";
        public string AADResource { get; private set; } = "https://developer.microsoft.com/";
        public string UDCAuthEndpoint{ get; private set; } = "https://developer.microsoft.com/xdts/authorize";

        public string MsalXboxLiveClientId = "b1eab458-325b-45a5-9692-ad6079c1eca8";
        public string XmintAuthEndpoint { get; private set; } = "https://xmint.xboxlive.com/adfs/authorize?rp=https%3A%2F%2Fxdp.xboxlive.com%2F";

        public string XdpqEndpoint { get; private set; } = "https://jicailiu5";
    }
}
