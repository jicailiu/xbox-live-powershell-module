//-----------------------------------------------------------------------
// <copyright file="SignatureUtility.cs" company="Microsoft">
//     Copyright (c) Microsoft. All rights reserved.
//     Internal use only.
// </copyright>
//-----------------------------------------------------------------------

namespace SessionHistoryViewer
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Specialized;
    using System.Linq;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security.Cryptography;
    using System.Threading.Tasks;

    public static class SignatureUtility
    {
        public static string GenerateSignature(this ECDsaCng ecdsa, SignaturePolicy policy, long timestamp, string method, Uri requestUri, NameValueCollection headers, byte[] content)
        {
            if (policy == null)
            {
                throw new ArgumentNullException("policy");
            }

            if (requestUri == null)
            {
                throw new ArgumentNullException("requestUri");
            }

            if (content == null)
            {
                throw new ArgumentNullException("content");
            }

            using (var signingContext = new SigningContext(CngAlgorithm.Sha256, ecdsa))
            {
                ProofKeyUtil.SignRequest(
                    signingContext,
                    policy,
                    timestamp,
                    method,
                    requestUri.GetComponents(UriComponents.PathAndQuery, UriFormat.SafeUnescaped),
                    headers,
                    content,
                    0,
                    content.Length);

                return ProofKeyUtil.CreateSignatureHeader(signingContext.GetSignature(), policy.Version, timestamp);
            }
        }


        public static async Task SignRequest(HttpClient httpClient, HttpRequestMessage requestMessage, SignaturePolicy policy, ECDsaCng ecdsa)
        {
            NameValueCollection headers = new NameValueCollection();
            byte[] content;

            // need to find the headers in the HttpClient, HttpRequestMessage, HttpRequestMessage.Content
            if (policy.ExtraHeaders != null && policy.ExtraHeaders.Length > 0)
            {
                foreach (var header in policy.ExtraHeaders)
                {
                    List<string> headerValue = new List<string>();

                    // check if the Client instance first
                    headerValue.AddRange(httpClient.DefaultRequestHeaders.SearchForHeader(header));

                    // check in the HttpRequestMessage next
                    headerValue.AddRange(requestMessage.Headers.SearchForHeader(header));

                    // check in on the content
                    if (requestMessage.Content != null)
                    {
                        headerValue.AddRange(requestMessage.Content.Headers.SearchForHeader(header));
                    }

                    headers.Add(header, string.Join(",", headerValue));
                }
            }

            // check in on the content
            if (requestMessage.Content != null)
            {
                content = await requestMessage.Content.ReadAsByteArrayAsync();
            }
            else
            {
                content = new byte[0];
            }

            // now we can generate the signature
            var signature = ecdsa.GenerateSignature(policy, DateTime.UtcNow.ToFileTimeUtc(), requestMessage.Method.ToString(), requestMessage.RequestUri, headers, content);
            requestMessage.Headers.Add("Signature", signature);
        }

        /// <summary>
        /// Search for Header in a HttpHeaders instance and return an empty set if it is not found
        /// </summary>
        /// <param name="headers">HttpHeaders instance</param>
        /// <param name="name">Name of the header</param>
        /// <returns>Header value</returns>
        public static IEnumerable<string> SearchForHeader(this HttpHeaders headers, string name)
        {
            IEnumerable<string> values;
            if (headers == null || string.IsNullOrEmpty(name) || !headers.TryGetValues(name, out values))
            {
                values = new string[0];
            }

            return values;
        }

        public static Dictionary<string, string> ToDictionary(this HttpHeaders headers)
        {
            return headers.ToDictionary(kvp => kvp.Key, kvp => string.Join(",", kvp.Value));
        }

    }
}