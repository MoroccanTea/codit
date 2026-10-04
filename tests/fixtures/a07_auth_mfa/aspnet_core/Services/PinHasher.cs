using System;
using System.Security.Cryptography;

namespace Acme.Identity.Services
{
    public static class PinHasher
    {
        public static byte[] HashLegacy(string password, byte[] salt)
        {
            // codit-expect: CWE-916 PBKDF2 with only 1,000 iterations
            using var kdf = new Rfc2898DeriveBytes(password, salt, 1000);
            return kdf.GetBytes(32);
        }

        public static byte[] Hash(string password, byte[] salt)
        {
            // codit-safe: CWE-916 PBKDF2-SHA256 with 600,000 iterations
            return Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000, HashAlgorithmName.SHA256, 32);
        }
    }
}
