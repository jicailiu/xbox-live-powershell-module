// -----------------------------------------------------------------------
//  <copyright file="EccJsonWebKey.cs" company="Microsoft">
//      Copyright (c) Microsoft. All rights reserved.
//      Internal use only.
//  </copyright>
// -----------------------------------------------------------------------

namespace SessionHistoryViewer
{
    using System;
    using System.Globalization;
    using System.Runtime.Serialization;
    using System.Security.Cryptography;

    /// <summary>
    /// Curve types supported by the EccJsonWebKey class.
    /// http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-08#section-5.2.1
    /// </summary>
    public enum EccJsonWebKeyCurveType
    {
        /// <summary>
        /// Curve type not set.
        /// </summary>
        None,

        /// <summary>
        /// 256 bit key
        /// </summary>
        P256,

        /// <summary>
        /// 384 bit key
        /// </summary>
        P384,

        /// <summary>
        /// 521 bit key
        /// </summary>
        P521
    };

    /// <summary>
    /// ECC key represented by two points X and Y. These are big endian 
    /// encoded unsigned integers represented as a base64 string.
    /// Follows the standard at: http://tools.ietf.org/html/draft-ietf-jose-json-web-key-08
    /// Provides the common key properties so that individual key types
    /// can derive from this class (such as RSA and ECC)
    /// </summary>
    [DataContract]
    public class EccJsonWebKey
    {
        private const string P256 = "P-256";
        private const string P384 = "P-384";
        private const string P521 = "P-521";
        private const int Ecc256PublicBlobMagic = 0x31534345; // "ECS1"
        private const int Ecc384PublicBlobMagic = 0x33534345; // "ECS3"
        private const int Ecc521PublicBlobMagic = 0x35534345; // "ECS5"
        private const char Base64PadCharacter = '=';
        private static string DoubleBase64PadCharacter = String.Format(CultureInfo.InvariantCulture, "{0}{0}", Base64PadCharacter);
        private const char Base64Character62 = '+';
        private const char Base64Character63 = '/';
        private const char Base64UrlCharacter62 = '-';
        private const char Base64UrlCharacter63 = '_';
        public const string ECDSASHA256 = "ES256";
        public const string ECDSASHA384 = "ES384";
        public const string ECDSASHA512 = "ES512";


        /// <summary>
        /// Algorithm family. This is required. Supported values can be found in JsonWebKeyAlgorithms
        /// </summary>
        [DataMember(Name = "kty")]
        public string KeyType { get; set; }

        /// <summary>
        /// Algorithm family. This is OPTIONAL. Supported values can be found in JsonWebAlgorithms.cs
        /// </summary>
        [DataMember(Name = "alg")]
        public string Algorithm { get; set; }

        /// <summary>
        /// Curve type of this key (implies key size)
        /// </summary>
        public EccJsonWebKeyCurveType CurveType { get; set; }

        [DataMember(Name = "crv")]
        public string CurveTypeValue
        {
            get
            {
                switch (this.CurveType)
                {
                    case EccJsonWebKeyCurveType.P256:
                        return P256;
                    case EccJsonWebKeyCurveType.P384:
                        return P384;
                    case EccJsonWebKeyCurveType.P521:
                        return P521;
                    default:
                        return null;
                }
            }
            set
            {
                EccJsonWebKeyCurveType parsedValue;
                if (Enum.TryParse<EccJsonWebKeyCurveType>(value.Replace("-", String.Empty), out parsedValue))
                {
                    this.CurveType = parsedValue;
                }
            }
        }

        [DataMember(Name = "x")]
        public string XCoordinate
        {
            get
            {
                return Encode(this.X);
            }
            set
            {
                this.X = DecodeBytes(value);
            }
        }

        [DataMember(Name = "y")]
        public string YCoordinate
        {
            get
            {
                return Encode(this.Y);
            }
            set
            {
                this.Y = DecodeBytes(value);
            }
        }

        /// <summary>
        /// X coordinate of the key
        /// </summary>
        public byte[] X { get; set; }

        /// <summary>
        /// Y coordinate of the key
        /// </summary>
        public byte[] Y { get; set; }

        /// <summary>
        /// Default constructor.
        /// </summary>
        public EccJsonWebKey()
        {
        }

        /// <summary>
        /// Initializes an ECC JWK based on an ECDsaCng object. 
        /// Extracts X, Y and curve type properties.
        /// </summary>
        /// <param name="ecdsa"></param>
        public EccJsonWebKey(ECDsaCng ecdsa)
        {
            byte[] x, y;
            EccJsonWebKeyCurveType curveType;

            ExtractEccParameters(ecdsa, out x, out y, out curveType);

            this.CurveType = curveType;
            this.X = x;
            this.Y = y;
            this.KeyType = "EC";
            switch (ecdsa.KeySize)
            {
                case 256:
                    this.Algorithm = ECDSASHA256;
                    break;
                case 384:
                    this.Algorithm = ECDSASHA384;
                    break;
                case 512:
                    this.Algorithm = ECDSASHA512;
                    break;
            }
        }

        public static void ExtractEccParameters(ECDsaCng ecdsa, out byte[] x, out byte[] y, out EccJsonWebKeyCurveType curveType)
        {
            byte[] cspBlob = ecdsa.Key.Export(CngKeyBlobFormat.EccPublicBlob);

            int magic = BitConverter.ToInt32(cspBlob, 0);
            curveType = Magic2CurveType(magic);

            // 4 skips the magic and is start of key length
            int keyLen = BitConverter.ToInt32(cspBlob, 4);

            x = new byte[keyLen];
            y = new byte[keyLen];

            // 8 skips the magic... and the length.
            Buffer.BlockCopy(cspBlob, 8, x, 0, keyLen);
            Buffer.BlockCopy(cspBlob, 8 + keyLen, y, 0, keyLen);
        }

        private static EccJsonWebKeyCurveType Magic2CurveType(int magic)
        {
            switch (magic)
            {
                case Ecc256PublicBlobMagic:
                    return EccJsonWebKeyCurveType.P256;
                case Ecc384PublicBlobMagic:
                    return EccJsonWebKeyCurveType.P384;
                case Ecc521PublicBlobMagic:
                    return EccJsonWebKeyCurveType.P521;
                default:
                    return EccJsonWebKeyCurveType.None;
            }
        }

        internal static byte[] DecodeBytes(string arg)
        {
            if (String.IsNullOrEmpty(arg))
            {
                throw new ArgumentNullException("arg");
            }

            string s = arg;
            s = s.Replace(Base64UrlCharacter62, Base64Character62); // 62nd char of encoding
            s = s.Replace(Base64UrlCharacter63, Base64Character63); // 63rd char of encoding
            switch (s.Length % 4) // Pad 
            {
                case 0:
                    break; // No pad chars in this case
                case 2:
                    s += DoubleBase64PadCharacter;
                    break; // Two pad chars
                case 3:
                    s += Base64PadCharacter;
                    break; // One pad char
                default:
                    throw new ArgumentException("Illegal base64url string!", "arg");
            }
            return Convert.FromBase64String(s); // Standard base64 decoder
        }

        internal static string Encode(byte[] arg)
        {
            if (arg == null)
            {
                throw new ArgumentNullException("arg");
            }

            string s = Convert.ToBase64String(arg);
            s = s.Split(Base64PadCharacter)[0]; // Remove any trailing padding
            s = s.Replace(Base64Character62, Base64UrlCharacter62); // 62nd char of encoding
            s = s.Replace(Base64Character63, Base64UrlCharacter63); // 63rd char of encoding

            return s;
        }
    }
}