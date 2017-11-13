﻿// -----------------------------------------------------------------------
//  <copyright file="SigningContext.cs" company="Microsoft">
//      Copyright (c) Microsoft. All rights reserved.
//      Internal use only.
//  </copyright>
// -----------------------------------------------------------------------

namespace SessionHistoryViewer
{
    using System;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// An abstraction to provide a consistent interface for the different 
    /// signing algorithms. This class can be used for both creating and
    /// verifying signatures.
    /// </summary>
    public class SigningContext : IDisposable
    {
        private static readonly byte[] finalBlock = new byte[0];
        private static readonly byte[] nullByte = new byte[] { 0 };

        private readonly Func<byte[], byte[], bool> verifyHash;
        private readonly Func<byte[], byte[]> signHash;
        private readonly HashAlgorithm hashAlg;
        private readonly AsymmetricAlgorithm cryptoAlg;

        /// <summary>
        /// Creates a signing context using RSA and the supplied hashing algorithm.
        /// </summary>
        /// <param name="hashAlg">The hashing algorithm to use. This should be SHA256.</param>
        /// <param name="rsaAlg">The RSA provider.</param>
        public SigningContext(CngAlgorithm hashAlg, RSACryptoServiceProvider rsaAlg)
        {
            if (hashAlg == null)
            {
                throw new ArgumentNullException("hashAlg");
            }

            if (rsaAlg == null)
            {
                throw new ArgumentNullException("rsaAlg");
            }

            string hashAlgStr = hashAlg.Algorithm;
            this.verifyHash = (hash, sig) => rsaAlg.VerifyHash(hash, hashAlgStr, sig);
            this.signHash = (hash) => rsaAlg.SignHash(hash, hashAlgStr);
            this.cryptoAlg = rsaAlg;
            this.hashAlg = (HashAlgorithm)CryptoConfig.CreateFromName(hashAlg.Algorithm);
        }

        /// <summary>
        /// Creates a signing context using ECC and the supplied hashing algorithm.
        /// </summary>
        /// <param name="hashAlg">The hasing algorithm to use. This should be SHA256.</param>
        /// <param name="eccAlg">The ECC provider.</param>
        public SigningContext(CngAlgorithm hashAlg, ECDsaCng eccAlg)
        {
            if (hashAlg == null)
            {
                throw new ArgumentNullException("hashAlg");
            }

            if (eccAlg == null)
            {
                throw new ArgumentNullException("eccAlg");
            }

            eccAlg.HashAlgorithm = hashAlg;
            this.verifyHash = eccAlg.VerifyHash;
            this.signHash = eccAlg.SignHash;
            this.cryptoAlg = eccAlg;
            this.hashAlg = (HashAlgorithm)CryptoConfig.CreateFromName(hashAlg.Algorithm);
        }

        /// <summary>
        /// A generic method for adding bytes to the signature calculation.
        /// </summary>
        /// <param name="buffer">The buffer to add bytes from.</param>
        /// <param name="index">The start index into the buffer.</param>
        /// <param name="count">The number of bytes to take from the buffer.</param>
        public void AddBytes(byte[] buffer, int index, int count)
        {
            this.hashAlg.TransformBlock(buffer, index, count, null, 0);
        }

        /// <summary>
        /// Adds a null (0x00) byte to the signature calculation.
        /// </summary>
        public void AddNullByte()
        {
            this.hashAlg.TransformBlock(nullByte, 0, 1, null, 0);
        }

        /// <summary>
        /// Adds the signature policy version to the signature calculation.
        /// This function will handle the conversion to big-endian and add
        /// the trailing null byte to the signature calculation.
        /// </summary>
        /// <param name="version">The policy version.</param>
        public void SignVersion(int version)
        {
            byte[] bytes = BitConverter.GetBytes(version);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }

            this.AddBytes(bytes, 0, bytes.Length);
            this.AddNullByte();
        }

        /// <summary>
        /// Adds the Windows file time to the signature calculation.
        /// This function will handle the conversion to big-endian and add
        /// the trailing null byte to the signature calculation.
        /// </summary>
        /// <param name="timestamp">The Windows file time.</param>
        public void SignTimestamp(long timestamp)
        {
            byte[] bytes = BitConverter.GetBytes(timestamp);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }

            this.AddBytes(bytes, 0, bytes.Length);
            this.AddNullByte();
        }

        /// <summary>
        /// Adds a string element to the signature calculation. This is used
        /// for adding text elements like the HTTP method, URI elements, and
        /// HTTP headers.
        /// This function will add the trailing null byte to the signature calculation.
        /// </summary>
        /// <param name="element"></param>
        public void SignElement(string element)
        {
            byte[] buffer = Encoding.ASCII.GetBytes(element);
            this.AddBytes(buffer, 0, buffer.Length);
            this.AddNullByte();
        }

        /// <summary>
        /// Verifies the signature matches.
        /// </summary>
        /// <param name="sig">The signature to verify against.</param>
        /// <returns>True if the signature matches. False otherwise.</returns>
        public bool VerifyHash(byte[] sig)
        {
            if (sig == null)
            {
                throw new ArgumentNullException("sig");
            }

            this.hashAlg.TransformFinalBlock(finalBlock, 0, 0);

            return this.verifyHash(this.hashAlg.Hash, sig);
        }

        /// <summary>
        /// Calculates the final signature.
        /// </summary>
        /// <returns>The calculated signature.</returns>
        public byte[] GetSignature()
        {
            this.hashAlg.TransformFinalBlock(finalBlock, 0, 0);
            return this.signHash(this.hashAlg.Hash);
        }

        /// <summary>
        /// Part of the IDisposable implementation.
        /// </summary>
        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes the hashAlg and cryptoAlg objects.
        /// </summary>
        /// <param name="disposing"></param>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                this.hashAlg.Dispose();
                this.cryptoAlg.Dispose();
            }
        }
    }
}