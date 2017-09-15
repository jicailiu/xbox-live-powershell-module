using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Xbox.Services.Tool
{
    public class Helper
    {
        private static Uri xorBaseUri = new Uri(ClientSettings.Singleton.XorcEndpoint);
        private static Uri xtasBaseUri = new Uri(ClientSettings.Singleton.XtasEndpoint);
        private static Uri xdpqBaseUri = new Uri(ClientSettings.Singleton.XdpqEndpoint);

        static public async Task<IEnumerable<string>> GetProductsAsync()
        {
            if (Auth.Client.Account != null)
            {
                if (Auth.Client.AccountSource == DevAccountSource.UniversalDeveloperCenter)
                {
                    using (var submitRequest = new XboxLiveHttpRequest())
                    {
                        DevAccount devAccount = Auth.Client.Account;
                        var requestMsg = new HttpRequestMessage(HttpMethod.Get, new Uri(xorBaseUri, $"/products?accountId={devAccount.AccountId}"));

                        string eToken = await Auth.GetETokenSilentlyAsync(string.Empty, string.Empty);
                        AddRequestHeaders(ref requestMsg, eToken);

                        var responseContent = await submitRequest.SendAsync(requestMsg);
                    }
                }
            }
            else
            {
                throw new XboxLiveException("No dev account siged in");
            }

            return new List<string>();
        }

        static public async Task<IEnumerable<string>> GetSandboxesAsync()
        {
            if (Auth.Client.Account != null)
            {
                if (Auth.Client.AccountSource == DevAccountSource.UniversalDeveloperCenter)
                {
                    using (var submitRequest = new XboxLiveHttpRequest())
                    {
                        DevAccount devAccount = Auth.Client.Account;
                        var requestMsg = new HttpRequestMessage(HttpMethod.Get, new Uri(xorBaseUri, $"/sandboxes?accountId={devAccount.AccountId}"));

                        string eToken = await Auth.GetETokenSilentlyAsync(string.Empty, string.Empty);
                        AddRequestHeaders(ref requestMsg, eToken);

                        var responseContent = await submitRequest.SendAsync(requestMsg);
                    }
                }
            }
            else
            {
                throw new XboxLiveException("No dev account siged in");
            }

            return new List<string>();
        }

        static public async Task<IEnumerable<string>> GetTestAccountsAsync()
        {
            if (Auth.Client.Account != null)
            {
                if (Auth.Client.AccountSource == DevAccountSource.UniversalDeveloperCenter)
                {
                    using (var submitRequest = new XboxLiveHttpRequest())
                    {
                        DevAccount devAccount = Auth.Client.Account;
                        var requestMsg = new HttpRequestMessage(HttpMethod.Get,
                            new Uri(xtasBaseUri, $"/testaccounts?accountId={devAccount.AccountId}"));

                        string eToken = await Auth.GetETokenSilentlyAsync(string.Empty, string.Empty);
                        AddRequestHeaders(ref requestMsg, eToken);

                        var responseContent = await submitRequest.SendAsync(requestMsg);
                    }
                }
                else
                {
                    using (var submitRequest = new XboxLiveHttpRequest())
                    {
                        var requestMsg = new HttpRequestMessage(HttpMethod.Get,
                            new Uri(xdpqBaseUri, $"/testaccounts"));

                        string eToken = await Auth.GetETokenSilentlyAsync(string.Empty, string.Empty);
                        AddRequestHeaders(ref requestMsg, eToken);

                        var responseContent = await submitRequest.SendAsync(requestMsg);
                    }
                }
            }
            else
            {
                throw new XboxLiveException("No dev account siged in");
            }

            return new List<string>();
        }

        private static void AddRequestHeaders(ref HttpRequestMessage request, string eToken)
        {
            request.Headers.Add("x-xbl-contract-version", "100");
            request.Headers.Add("Authorization", eToken);
        }
    }
}
