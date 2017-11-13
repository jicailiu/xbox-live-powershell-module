// -----------------------------------------------------------------------
//  <copyright file="ProofKeyUtil.cs" company="Microsoft">
//      Copyright (c) Microsoft. All rights reserved.
//      Internal use only.
//  </copyright>
// -----------------------------------------------------------------------

namespace SessionHistoryViewer
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Specialized;
    using System.Security.Cryptography;

    /// <summary>
    /// A helper class for creating and validating proof key signatures.
    /// </summary>
    public static class ProofKeyUtil
    {
        private static readonly long MaxFileTime = DateTime.MaxValue.ToFileTimeUtc();

        /// <summary>
        /// Create's a ECDsaP256 ProofKey and exports the Public/Private Key Pair to a byte array
        /// </summary>
        /// <returns>Byte Array which can be converted to an ECDsaCng instance</returns>
        public static byte[] CreateProofKey()
        {
            using (var key = Create())
            {
                return key.ToByteArray();
            }
        }

        /// <summary>
        /// Create's a ECDsaP256 ProofKey
        /// </summary>
        /// <returns>ECDsaCng instance</returns>
        public static ECDsaCng Create()
        {
            CngKeyCreationParameters keyCreationParameters = new CngKeyCreationParameters();
            keyCreationParameters.ExportPolicy = CngExportPolicies.AllowPlaintextExport;
            keyCreationParameters.KeyUsage = CngKeyUsages.Signing;

            using (CngKey key = CngKey.Create(CngAlgorithm.ECDsaP256, null, keyCreationParameters))
            {
                return new ECDsaCng(key);
            }
        }

        /// <summary>
        /// Creates an ECdsaCng instance from a byte array
        /// </summary>
        /// <param name="exportedKey">byte array instance</param>
        /// <returns>ECdsaCng instance</returns>
        public static ECDsaCng ProofKeyFromByteArray(this byte[] exportedKey)
        {
            if (exportedKey == null)
            {
                throw new ArgumentNullException("exportedKey");
            }

            return new ECDsaCng(CngKey.Import(exportedKey, CngKeyBlobFormat.EccPrivateBlob));
        }

        /// <summary>
        /// Exports a ECDsaCng instance into a Public/Private key pair
        /// </summary>
        /// <param name="proofKey">ECDsaCng instance</param>
        /// <returns>Byte Array which can be converted to an ECDsaCng instance</returns>
        public static byte[] ToByteArray(this ECDsaCng proofKey)
        {
            if (proofKey == null)
            {
                throw new ArgumentNullException("proofKey");
            }

            return proofKey.Key.Export(CngKeyBlobFormat.EccPrivateBlob);
        }

        /// <summary>
        /// Creates the signature header value from the signature bytes, policy version, and timestamp.
        /// </summary>
        /// <param name="signature">The signature.</param>
        /// <param name="version">The policy version.</param>
        /// <param name="timestamp">The timestamp.</param>
        /// <returns>The signature header.</returns>
        public static string CreateSignatureHeader(byte[] signature, int version, long timestamp)
        {
            if (signature == null)
            {
                throw new ArgumentNullException("signature");
            }
            if (!IsValidFileTime(timestamp))
            {
                throw new ArgumentOutOfRangeException("timestamp", "Not a valid Windows file time.");
            }

            byte[] versionBytes = BitConverter.GetBytes(version);
            byte[] timestampBytes = BitConverter.GetBytes(timestamp);

            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(versionBytes);
                Array.Reverse(timestampBytes);
            }

            byte[] headerBytes = new byte[signature.Length + versionBytes.Length + timestampBytes.Length];
            Buffer.BlockCopy(versionBytes, 0, headerBytes, 0, versionBytes.Length);
            Buffer.BlockCopy(timestampBytes, 0, headerBytes, versionBytes.Length, timestampBytes.Length);
            Buffer.BlockCopy(signature, 0, headerBytes, versionBytes.Length + timestampBytes.Length, signature.Length);

            return Convert.ToBase64String(headerBytes);
        }

        /// <summary>
        /// Signs everything but the body. Note that even if there is no request body,
        /// a null byte still must be added. Use the other overload if you can load the
        /// request body into memory.
        /// </summary>
        /// <param name="context">The signing context.</param>
        /// <param name="policy">The signature policy.</param>
        /// <param name="timestamp">The timestamp.</param>
        /// <param name="method">The HTTP method (verb).</param>
        /// <param name="pathAndQuery">The path and query string of the request URL.</param>
        /// <param name="headers">The request headers.</param>
        public static void SignPrologue(
            SigningContext context,
            SignaturePolicy policy,
            long timestamp,
            string method,
            string pathAndQuery,
            NameValueCollection headers)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }
            if (policy == null)
            {
                throw new ArgumentNullException("policy");
            }
            if (!IsValidFileTime(timestamp))
            {
                throw new ArgumentOutOfRangeException("timestamp", "Not a valid Windows file time.");
            }
            if (string.IsNullOrEmpty(method))
            {
                throw new ArgumentNullException("method");
            }
            if (pathAndQuery == null)
            {
                throw new ArgumentNullException("pathAndQuery");
            }
            if (headers == null)
            {
                throw new ArgumentNullException("headers");
            }

            context.SignVersion(policy.Version);
            context.SignTimestamp(timestamp);
            context.SignElement(method.ToUpperInvariant());
            context.SignElement(pathAndQuery);
            ProofKeyUtil.SignHeaders(context, headers, policy);
        }

        /// <summary>
        /// Signs the entire request.
        /// </summary>
        /// <param name="context">The signing context.</param>
        /// <param name="policy">The signature policy.</param>
        /// <param name="timestamp">The timestamp.</param>
        /// <param name="method">The HTTP method (verb).</param>
        /// <param name="pathAndQuery">The path and query string of the request URL.</param>
        /// <param name="headers">The request headers.</param>
        /// <param name="body">The buffer containing the request body.</param>
        /// <param name="index">An offset into the buffer marking the start of request body.</param>
        /// <param name="count">The length in bytes of the request body in the buffer.</param>
        public static void SignRequest(
            SigningContext context,
            SignaturePolicy policy,
            long timestamp,
            string method,
            string pathAndQuery,
            NameValueCollection headers,
            byte[] body,
            int index,
            int count)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }
            if (policy == null)
            {
                throw new ArgumentNullException("policy");
            }
            if (!IsValidFileTime(timestamp))
            {
                throw new ArgumentOutOfRangeException("timestamp", "Not a valid Windows file time.");
            }
            if (string.IsNullOrEmpty(method))
            {
                throw new ArgumentNullException("method");
            }
            if (pathAndQuery == null)
            {
                throw new ArgumentNullException("pathAndQuery");
            }
            if (headers == null)
            {
                throw new ArgumentNullException("headers");
            }
            if (body == null)
            {
                throw new ArgumentNullException("body");
            }

            SignPrologue(
                context,
                policy,
                timestamp,
                method,
                pathAndQuery,
                headers);

            int numBytes = (int)Math.Min(count, policy.MaxBodyBytes);
            context.AddBytes(body, index, numBytes);
            context.AddNullByte();
        }

        /// <summary>
        /// Adds the headers to the signature calculation according to the 
        /// signature policy.
        /// </summary>
        /// <param name="context">The signing context.</param>
        /// <param name="headers">The collection containing the request headers.</param>
        /// <param name="policy">The signature policy.</param>
        public static void SignHeaders(SigningContext context, NameValueCollection headers, SignaturePolicy policy)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }
            if (policy == null)
            {
                throw new ArgumentNullException("policy");
            }
            if (headers == null)
            {
                throw new ArgumentNullException("headers");
            }

            context.SignElement(headers["Authorization"] ?? string.Empty);

            if (policy.ExtraHeaders == null || policy.ExtraHeaders.Length == 0)
            {
                return;
            }

            foreach (string header in policy.ExtraHeaders)
            {
                // If the header isn't present we treat it as an
                // empty string so that the null byte gets added.

                string headerValue = headers[header] ?? string.Empty;
                context.SignElement(headerValue);
            }
        }

        /// <summary>
        /// Checks if the timestamp is a valid Windows file time.
        /// </summary>
        /// <param name="timestamp">The timestamp.</param>
        /// <returns>True if valid, otherwise false.</returns>
        public static bool IsValidFileTime(long timestamp)
        {
            return timestamp >= 0 && timestamp <= MaxFileTime;
        }
    }
}