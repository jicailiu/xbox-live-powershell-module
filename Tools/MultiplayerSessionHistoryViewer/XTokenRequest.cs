//-----------------------------------------------------------------------
// <copyright file="XTokenRequest.cs" company="Microsoft">
//     Copyright (c) Microsoft. All rights reserved.
//     Internal use only.
// </copyright>
//-----------------------------------------------------------------------

using System;
using System.Configuration;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace SessionHistoryViewer
{
    class XTokenRequest
    {
        static readonly string XstsUrl = ConfigurationManager.AppSettings["XstsUrl"];

        public async Task<XSTSTokenResponse> GetXToken(string uToken, byte[] pkey, string sandbox)
        {
            var authUri = XstsUrl;
            ECDsaCng proofKey = ProofKeyUtil.ProofKeyFromByteArray(pkey);

            using (proofKey)
            {
                var request = new XSTSRequest
                {
                    RelyingParty = "http://xboxlive.com",
                    TokenType = "JWT",
                    Properties = new PropertyBag
                    {
                        UserTokens = new string[] { uToken },
                        SandboxId = sandbox,
                    }
                };

                XSTSTokenResponse xToken = null;

                try
                {
                    using (HttpClient client = new HttpClient())
                    {
                        using (var authRequest = new HttpRequestMessage(HttpMethod.Post, authUri))
                        {
                            using (var postContent = new ByteArrayContent(request.SerializeToJsonByteArray()))
                            {
                                authRequest.Content = postContent;
                                authRequest.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                                authRequest.Headers.Add("x-xbl-contract-version", "1");
                                // Generate a signature
                                await SignatureUtility.SignRequest(client, authRequest, SignaturePolicy.XSTSSignaturePolicy, proofKey);

                                using (var response = await client.SendAsync(authRequest))
                                {
                                    var xstsJson = await response.Content.ReadAsStringAsync();
                                    xToken = xstsJson.DeserializeJson<XSTSTokenResponse>();
                                    xToken.message = response.ToString();
                                    Console.WriteLine(xstsJson);
                                }
                            }
                        }
                    }
                }
                catch (WebException)
                {
                }

                return xToken;
            }
        }
    }
}
