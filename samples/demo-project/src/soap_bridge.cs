// Deliberately weak sample for the Periperi demo. Never use in production.

using System;
using System.Security.Cryptography;

namespace Demo.Legacy
{
    public static class SoapSigner
    {
        public static byte[] SignEnvelope(byte[] envelope, DSA dsa)
        {
            using (SHA384 sha384 = SHA384.Create())
            {
                return dsa.CreateSignature(sha384.ComputeHash(envelope));
            }
        }

        public static byte[] Seal(byte[] payload)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(1024))
            {
                return rsa.Encrypt(payload, false);
            }
        }
    }
}
