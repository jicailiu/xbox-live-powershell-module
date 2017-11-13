//-----------------------------------------------------------------------
// <copyright file="UserTokenRequest.cs" company="Microsoft">
//     Copyright (c) Microsoft. All rights reserved.
//     Internal use only.
// </copyright>
//-----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SessionHistoryViewer
{
    public class UserTokenRequest
    {
        public string rpsTicket;

        static readonly string XasuHost = ConfigurationManager.AppSettings["XasuHost"];
        static readonly string RpsSite = ConfigurationManager.AppSettings["RpsSite"];
        static readonly string Scope = ConfigurationManager.AppSettings["Scope"];
        static readonly string XstsUrl = ConfigurationManager.AppSettings["XstsUrl"];
        static readonly string AuthenticateUri = XasuHost + "/user/authenticate";

        public async Task<XASUTokenResponse> GetUToken(string rpsTicket, byte[] pkey)
        {

            ECDsaCng proofKey = ProofKeyUtil.ProofKeyFromByteArray(pkey);

            using (HttpClient client = new HttpClient())
            {

                using (proofKey)
                {

                    // Make an Authenticate Request
                    var request = new XASTokenRequest
                    {
                        TokenTypeValue = XASTokenType.JWT,
                        AuthMethod = XASAuthMethod.RPS,
                        RelyingParty = "http://auth.xboxlive.com",
                        SiteName = RpsSite,
                        RpsTicket = "d=" + rpsTicket,
                    };


                    request.Properties.ProofKey = new EccJsonWebKey(proofKey);

                    using (var authenticateRequest = new HttpRequestMessage(HttpMethod.Post, AuthenticateUri))
                    {
                        authenticateRequest.Headers.Add("x-xbl-contract-version", "0");
                        using (var postContent = new ByteArrayContent(request.SerializeToJsonByteArray()))
                        {
                            postContent.Headers.ContentType = new MediaTypeWithQualityHeaderValue("application/json");
                            authenticateRequest.Content = postContent;

                            // get a proofkey and generate a signature
                            await SignatureUtility.SignRequest(client, authenticateRequest, SignaturePolicy.XASUSignaturePolicy, proofKey);


                            using (var response = await client.SendAsync(authenticateRequest))
                            {
                                var authResponse = await response.Content.ReadAsStringAsync();
                                Console.WriteLine(authResponse);
                                return authResponse.DeserializeJson<XASUTokenResponse>();
                            }
                        }
                    }
                }
            }
        }

    }
}
