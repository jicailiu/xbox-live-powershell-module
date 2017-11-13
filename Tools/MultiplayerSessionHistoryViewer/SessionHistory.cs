﻿using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace SessionHistoryViewer
{
    public static class SessionHistory
    {
        private const int TimeoutInMilliseconds = 30000;
        private const int TakeSize = 100;
        private const string ContractVersion = "105";
        private const string AcceptLanguage = "en-us";
        public const long MaxChangeValue = 9007199254740992; // 2 ^ 53  (max json int size)
        private const string RequestRoot = "https://sessiondirectory.xboxlive.com";

        private static WebRequest CreateSessionHistoryPostRequest(string url, XSTSTokenResponse xtoken, byte[] postBytes)
        {
            WebRequest webRequest = CreateSessionHistoryGetRequest(url, xtoken);

            webRequest.Method = "POST";
            webRequest.ContentType = "application/json";
            webRequest.ContentLength = postBytes.Length;
            using (Stream newStream = webRequest.GetRequestStream())
            {
                newStream.Write(postBytes, 0, postBytes.Length);
            }

            return webRequest;
        }

        private static WebRequest CreateSessionHistoryGetRequest(string url, XSTSTokenResponse xtoken)
        {
            WebRequest webRequest = WebRequest.Create(url);
            webRequest.Method = "GET";
            webRequest.Headers["Authorization"] = "XBL3.0 x=" + xtoken.DisplayClaims.users[0].UserHash + ";" + xtoken.Token;
            webRequest.Headers["Accept-Language"] = AcceptLanguage;
            webRequest.Headers["X-Xbl-Contract-Version"] = ContractVersion;
            webRequest.Headers["X-Xbl-Group"] = "*";
            webRequest.Timeout = TimeoutInMilliseconds;

            return webRequest;
        }

        public static async Task<Tuple<HttpStatusCode, string>> RunSessionHistoryRequestAsync(WebRequest webRequest)
        {
            try
            {
                var webResponse = await webRequest.GetResponseAsync();

                HttpStatusCode statusCode = ((HttpWebResponse)webResponse).StatusCode;
                if (statusCode != HttpStatusCode.OK)
                {
                    return new Tuple<HttpStatusCode, string>(statusCode, ((HttpWebResponse)webResponse).StatusDescription);
                }

                using (var responseStream = webResponse.GetResponseStream())
                {
                    using (var streamReader = new StreamReader(responseStream))
                    {
                        var result = JsonConvert.DeserializeObject(streamReader.ReadToEnd());
                        return new Tuple<HttpStatusCode, string>(HttpStatusCode.OK, result.ToString());
                    }
                }
            }
            catch (WebException wex)
            {
                if (wex.Status == WebExceptionStatus.ProtocolError)
                {
                    var response = wex.Response as HttpWebResponse;
                    if (response != null)
                    {
                        return new Tuple<HttpStatusCode, string>(response.StatusCode, response.StatusDescription);
                    }
                }

                return new Tuple<HttpStatusCode, string>(HttpStatusCode.InternalServerError, "unknown service error");
            }
        }

        public static async Task<Tuple<HttpStatusCode, string>> GetSessionHistoryDocumentChangeAsync(
            string scid,
            string templateName,
            string sessionName,
            string branch,
            long changeNumber,
            XSTSTokenResponse xtoken)
        {
            string url = string.Format("{0}/serviceconfigs/{1}/sessiontemplates/{2}/sessions/{3}/branches/{4}/changes/{5}", RequestRoot, scid, templateName, sessionName, branch, changeNumber);

            WebRequest webRequest = CreateSessionHistoryGetRequest(url, xtoken);

            return await SessionHistory.RunSessionHistoryRequestAsync(webRequest);
        }

        public static async Task<Tuple<HttpStatusCode, string>> GetSessionHistoryDocumentDataAsync(
            string scid,
            string templateName,
            string sessionName, 
            string branch,
            XSTSTokenResponse xtoken)
        {
            string url = string.Format("{0}/serviceconfigs/{1}/sessiontemplates/{2}/sessions/{3}/branches/{4}/changes", RequestRoot, scid, templateName, sessionName, branch);

            WebRequest webRequest = CreateSessionHistoryGetRequest(url, xtoken);

            return await SessionHistory.RunSessionHistoryRequestAsync(webRequest);
        }

        public static async Task<Tuple<HttpStatusCode, string>> QuerySessionHistoryBranches(
            string scid,
            string templateName,
            string sessionName,
            XSTSTokenResponse xtoken)
        {
            string url = string.Format("{0}/serviceconfigs/{1}/sessiontemplates/{2}/sessions/{3}/branches", RequestRoot, scid, templateName, sessionName);

            WebRequest webRequest = CreateSessionHistoryGetRequest(url, xtoken);

            return await SessionHistory.RunSessionHistoryRequestAsync(webRequest);
        }

        public static async Task<Tuple<HttpStatusCode, string>> QuerySessionHistoryByGamertagAsync(
            string scid,
            string templateName,
            string gamertag,
            DateTime startAt,
            DateTime endAt,
            string continuationToken,
            XSTSTokenResponse xtoken)
        {
            string url = string.Format("{0}/serviceconfigs/{1}/sessiontemplates/{2}/query?take={3}", RequestRoot, scid, templateName, TakeSize);

            if (continuationToken != null)
            {
                url += string.Format("&continuationtoken={0}", continuationToken);
            }

            var postBody = new SessionHistoryQueryByGamertagRequest
            {
                gamertag = gamertag,
                startAt = startAt,
                endAt = endAt
            };

            return await SessionHistory.RunSessionHistoryRequestAsync(CreateSessionHistoryPostRequest(url, xtoken, postBody.SerializeToJsonByteArray()));
        }

        public static async Task<Tuple<HttpStatusCode, string>> QuerySessionHistoryByXuidAsync(
           string scid,
           string templateName,
           long xuid,
           DateTime startAt,
           DateTime endAt,
           string continuationToken,
           XSTSTokenResponse xtoken)
        {
            string url = string.Format("{0}/serviceconfigs/{1}/sessiontemplates/{2}/query?take={3}", RequestRoot, scid, templateName, TakeSize);

            if (continuationToken != null)
            {
                url += string.Format("&continuationtoken={0}", continuationToken);
            }

            var postBody = new SessionHistoryQueryByXuidRequest
            {
                xuid = xuid.ToString(),
                startAt = startAt,
                endAt = endAt
            };

            return await SessionHistory.RunSessionHistoryRequestAsync(CreateSessionHistoryPostRequest(url, xtoken, postBody.SerializeToJsonByteArray()));
        }

        public static async Task<Tuple<HttpStatusCode, string>> QuerySessionHistoryByCorrelationIdAsync(
           string scid,
           string templateName,
           string correlationId,
           XSTSTokenResponse xtoken)
        {
            string url = string.Format("{0}/serviceconfigs/{1}/sessiontemplates/{2}/query", RequestRoot, scid, templateName);

            var postBody = new SessionHistoryQueryByCorrelationIdRequest
            {
                correlationId = correlationId,
            };

            return await SessionHistory.RunSessionHistoryRequestAsync(CreateSessionHistoryPostRequest(url, xtoken, postBody.SerializeToJsonByteArray()));
        }
    }
}
