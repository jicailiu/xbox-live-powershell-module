//-----------------------------------------------------------------------
// <copyright file="Contracts.cs" company="Microsoft">
//     Copyright (c) Microsoft. All rights reserved.
//     Internal use only.
// </copyright>
//-----------------------------------------------------------------------

using System;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Serialization;

namespace SessionHistoryViewer
{
    #region Contracts
    public enum XASTokenType
    {
        None,
        JWT,
    }

    public enum XASAuthMethod
    {
        None,
        RPS,
    }

    [DataContract]
    public class XSTSRequest
    {
        [DataMember(EmitDefaultValue = false)]
        public string RelyingParty { get; set; }

        [DataMember(EmitDefaultValue = false)]
        public string TokenType { get; set; }

        [DataMember]
        public PropertyBag Properties { get; set; }
    }

    [DataContract]
    public class PropertyBag
    {
        [DataMember(EmitDefaultValue = false)]
        public string AuthMethod { get; set; }

        [DataMember(EmitDefaultValue = false)]
        public string SiteName { get; set; }

        [DataMember(EmitDefaultValue = false)]
        public string RpsTicket { get; set; }

        [DataMember(EmitDefaultValue = false)]
        public string[] UserTokens { get; set; }

        [DataMember(EmitDefaultValue = false)]
        public string SandboxId { get; set; }

        [DataMember(EmitDefaultValue = false)]
        public EccJsonWebKey ProofKey { get; set; }
    }

    [DataContract]
    public class XASTokenRequest
    {
        #region Static Fields and Properties
        /// <summary>
        /// Only need one of these per AppDomain
        /// </summary>
        private static SHA256CryptoServiceProvider sha256 = new SHA256CryptoServiceProvider();
        #endregion
        #region Constants
        public const string SiteNameKey = "SiteName";
        public const string AuthmethodKey = "AuthMethod";
        public const string RpsTicketKey = "RpsTicket";
        public const string AuthorizationKey = "Authorization";
        #endregion

        #region Ctors
        public XASTokenRequest()
        {
            this.Properties = new PropertyBag();

        }
        #endregion


        #region DataMember Properties
        [DataMember(Name = "RelyingParty", Order = 0)]
        public string RelyingParty { get; set; }

        [DataMember(Name = "Properties", Order = 2)]
        public PropertyBag Properties { get; set; }

        [DataMember(Name = "TokenType", Order = 1)]
        public string TokenType { get; set; }
        #endregion
        #region Instance Properties
        public string SiteName
        {
            get
            {
                return this.Properties.SiteName;
            }

            set
            {
                this.Properties.SiteName = value;
            }
        }

        /// <summary>
        /// Gets or sets the Authentication method to be used with the request
        /// </summary>
        public XASAuthMethod? AuthMethod
        {
            get
            {
                return this.Properties.AuthMethod.ParseEnumValue<XASAuthMethod>();
            }

            set
            {
                this.Properties.AuthMethod = value.ToString();
            }
        }

        /// <summary>
        /// Gets or sets the RpsTicket for the request
        /// </summary>
        public string RpsTicket
        {
            get
            {
                return this.Properties.RpsTicket;
            }

            set
            {
                this.Properties.RpsTicket = value;
            }
        }


        public XASTokenType? TokenTypeValue
        {
            get
            {
                return this.TokenType.ParseEnumValue<XASTokenType>();
            }

            set
            {
                if (value.HasValue)
                {
                    this.TokenType = value.ToString();
                }
            }
        }
        #endregion

    }

    [DataContract]
    public class ProfileRequest
    {
        [DataMember(EmitDefaultValue = false)]
        public string[] UserIds { get; set; }

        [DataMember(EmitDefaultValue = false)]
        public string[] Settings { get; set; }
    }

    [DataContract]
    public class GTChangeRequest
    {
        [DataMember(EmitDefaultValue = false)]
        public string gamertag { get; set; }

        [DataMember(EmitDefaultValue = false)]
        public bool preview { get; set; }

        [DataMember(EmitDefaultValue = false)]
        public long reservationId { get; set; }
    }

    [DataContract]
    public class XSTSTokenResponse
    {
        [DataMember(Name = "IssueInstant", Order = 0)]
        public string IssueInstant { get; set; }

        [DataMember(Name = "NotAfter", Order = 1)]
        public string NotAfter { get; set; }

        [DataMember(Name = "Token", Order = 2)]
        public string Token { get; set; }

        [DataMember(Name = "DisplayClaims", Order = 3)]
        public XSTSDisplayClaims DisplayClaims { get; set; }

        public String message;
    }

    [DataContract]
    public class XSTSDisplayClaims
    {
        [DataMember(Name = "xui")]
        public UserDisplayClaims[] users { get; set; }
    }

    [DataContract]
    public class UserDisplayClaims
    {
        [DataMember(Name = "agg")]
        public string AgeGroup { get; set; }

        [DataMember(Name = "gtg")]
        public string Gamertag { get; set; }

        [DataMember(Name = "prv")]
        public string Privileges { get; set; }

        [DataMember(Name = "xid")]
        public string Xuid { get; set; }

        [DataMember(Name = "uhs")]
        public string UserHash { get; set; }

        [DataMember(Name = "uts")]
        public string UserTest { get; set; }
    }

    [DataContract]
    public class XASUTokenResponse
    {
        [DataMember(Name = "IssueInstant", Order = 0)]
        public string IssueInstant { get; set; }

        [DataMember(Name = "NotAfter", Order = 1)]
        public string NotAfter { get; set; }

        [DataMember(Name = "Token", Order = 2)]
        public string Token { get; set; }

        [DataMember(Name = "DisplayClaims", Order = 3)]
        public XasuDisplayClaims DisplayClaims { get; set; }
    }

    [DataContract]
    public class ProfileResponse
    {
        [DataMember(Name = "profileUsers")]
        public ProfileUser[] profileUsers { get; set; }
    }

    [DataContract]
    public class ProfileUser
    {
        [DataMember(Name = "id")]
        public string xuid { get; set; }

        [DataMember(Name = "isSponsoredUser")]
        public bool isSponsoredUser { get; set; }

        [DataMember(Name = "settings")]
        public NameValuePair[] settings { get; set; }
    }

    [DataContract]
    public class NameValuePair
    {
        [DataMember(Name = "id")]
        public string name { get; set; }

        [DataMember(Name = "value")]
        public string value { get; set; }
    }

    [DataContract]
    public class XasuDisplayClaims
    {
        [DataMember(Name = "xui")]
        public XuiClaims[] Claims { get; set; }
    }

    [DataContract]
    public class XuiClaims
    {
        [DataMember(Name = "uhs")]
        public string UserHash { get; set; }
    }


    [DataContract]
    public class XASUKeysResponse
    {
        private X509Certificate2 publicKeyCert;

        [DataMember]
        public string PublicKey { get; set; }

        public X509Certificate2 PublicKeyCert
        {
            get
            {
                if (publicKeyCert == null)
                {
                    publicKeyCert = new X509Certificate2();
                    publicKeyCert.Import(Convert.FromBase64String(this.PublicKey));
                }

                return publicKeyCert;
            }
        }
    }
    #endregion


    /// <summary>
    /// This specifies a signature policy.
    /// </summary>
    [Serializable]
    public class SignaturePolicy
    {
        /// <summary>
        /// Gets or sets the policy version.
        /// </summary>
        [XmlAttribute]
        public int Version { get; set; }

        /// <summary>
        /// Gets or sets the supported signing algorithms.
        /// </summary>
        [XmlArray]
        [XmlArrayItem(ElementName = "Algorithm")]
        public string[] SupportedAlgorithms { get; set; }

        /// <summary>
        /// Gets or sets the additional headers to include in the signature.
        /// Note that this list is ordered.
        /// </summary>
        [XmlArray]
        [XmlArrayItem(ElementName = "Header")]
        public string[] ExtraHeaders { get; set; }

        /// <summary>
        /// Gets or sets the maximum number of bytes from the body to include
        /// in the signature.
        /// </summary>
        [XmlElement]
        public long MaxBodyBytes { get; set; }

        /// <summary>
        /// Gets or sets the maximum clock skew.
        /// </summary>
        [XmlElement]
        public int ClockSkewSeconds { get; set; }

        public static SignaturePolicy XASUSignaturePolicy
        {
            get
            {
                return new SignaturePolicy
                {
                    ClockSkewSeconds = 15,
                    ExtraHeaders = new string[0],
                    MaxBodyBytes = Int64.MaxValue,
                    SupportedAlgorithms = new string[] { "ES256" },
                    Version = 1
                };
            }
        }

        public static SignaturePolicy XSTSSignaturePolicy
        {
            get
            {
                return new SignaturePolicy
                {
                    ClockSkewSeconds = 15,
                    ExtraHeaders = new string[0],
                    MaxBodyBytes = Int64.MaxValue,
                    SupportedAlgorithms = new string[] { "ES256" },
                    Version = 1
                };
            }
        }

        public static SignaturePolicy ProfileSignaturePolicy
        {
            get
            {
                return new SignaturePolicy
                {
                    ClockSkewSeconds = 15,
                    ExtraHeaders = new string[0],
                    MaxBodyBytes = Int64.MaxValue,
                    SupportedAlgorithms = new string[] { "ES256" },
                    Version = 1
                };
            }
        }

        public static SignaturePolicy accountsSignaturePolicy
        {
            get
            {
                return new SignaturePolicy
                {
                    ClockSkewSeconds = 15,
                    ExtraHeaders = new string[0],
                    MaxBodyBytes = Int64.MaxValue,
                    SupportedAlgorithms = new string[] { "ES256" },
                    Version = 1
                };
            }
        }
    }
}