//-----------------------------------------------------------------------
// <copyright file="TokenManager.cs" company="Microsoft">
//     Copyright (c) Microsoft. All rights reserved.
//     Internal use only.
// </copyright>
//-----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SessionHistoryViewer
{
    enum TokenManagerResults
    {
        Ok = 0,
        IncorrectParameters,
        MsaFailure,
        XasuFailure,
        XstsFailure,
    }

    class TokenManager
    {
        public XASUTokenResponse uToken = null;
        public Dictionary<string, XSTSTokenResponse> xTokens = new Dictionary<string, XSTSTokenResponse>();
        public byte[] proofKey = ProofKeyUtil.Create().ToByteArray();
        public string rpsTicket = String.Empty;
        public string sandbox = String.Empty;
        public TokenManagerResults result = 0;
        public string message;

        public const string xblRelyingParty = "http://xboxlive.com";

        public TokenManager()
        {
        }

        public bool IsUserSignedIn()
        {
            return !(xTokens == null || !xTokens.ContainsKey(xblRelyingParty) || String.IsNullOrEmpty(xTokens[xblRelyingParty].Token) || DateTime.Parse(xTokens[xblRelyingParty].NotAfter) < DateTime.Now);
        }

        public async Task<XSTSTokenResponse> GetToken(string relyingParty)
        {
            if (String.IsNullOrEmpty(relyingParty))
            {
                result = TokenManagerResults.IncorrectParameters;
                message = "A valid relying party must be specified";
                return null;
            }

            if (String.IsNullOrEmpty(rpsTicket))
            {
                try
                {
                    var rps = new RpsTicketRequest();
                    rps.GetToken();
                    rps.Wait();
                    rpsTicket = rps.RpsTicket;
                    if (rpsTicket == null)
                    {
                        result = TokenManagerResults.MsaFailure;
                        message = "Could not authenticate to MSA.";
                        return null;
                    }
                }
                catch (Exception)
                {
                    result = TokenManagerResults.MsaFailure;
                    message = "Could not authenticate to MSA.";
                    return null;
                }
            }

            if (uToken == null || String.IsNullOrEmpty(uToken.Token) || (DateTime.Now > DateTime.Parse(uToken.NotAfter)))
            {
                try
                {
                    var xasu = new UserTokenRequest();
                    uToken = await xasu.GetUToken(rpsTicket, proofKey);
                    if (String.IsNullOrEmpty(uToken.Token))
                    {
                        result = TokenManagerResults.XasuFailure;
                        message = "Could not authenticate to XASU.";
                        return null;
                    }
                }
                catch (Exception)
                {
                    result = TokenManagerResults.XasuFailure;
                    message = "Could not authenticate to XASU.";
                    return null;
                }
            }

            if (xTokens == null || !xTokens.ContainsKey(relyingParty) || String.IsNullOrEmpty(xTokens[relyingParty].Token))
            {
                var xsts = new XTokenRequest();
                XSTSTokenResponse xtok = await xsts.GetXToken(uToken.Token, proofKey, sandbox);
                if (String.IsNullOrEmpty(xtok.Token))
                {
                    result = TokenManagerResults.XasuFailure;
                    message = "Token retrieval failed for relying party: " + relyingParty + "\r\n" + xtok.message;
                    return null;
                }

                xTokens[relyingParty] = xtok;
            }

            if (xTokens == null || !xTokens.ContainsKey(relyingParty) || String.IsNullOrEmpty(xTokens[relyingParty].Token))
            {
                result = TokenManagerResults.XstsFailure;
                message = "Token retrieval failed for relying party: " + relyingParty;
                return null;
            }
            else
            {
                return xTokens[relyingParty];
            }
        }

        internal void signout()
        {
            uToken = null;
            xTokens = new Dictionary<string, XSTSTokenResponse>();
            proofKey = ProofKeyUtil.Create().ToByteArray();
            rpsTicket = String.Empty;
            result = 0;
            message = String.Empty;

            var rps = new RpsTicketRequest();
            rps.SignOut();
            rps.Wait();
        }
    }
}
