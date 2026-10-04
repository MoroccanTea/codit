using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

namespace Acme.Payments.Services
{
    public class CardTokenizer
    {
        private readonly byte[] _dataKey;

        public CardTokenizer(IKeyVault vault)
        {
            // codit-safe: CWE-321 key fetched from Key Vault at runtime
            _dataKey = vault.GetSecretBytes("card-tokenizer-key");
        }

        public byte[] EncryptLegacy(byte[] plain)
        {
            using var aes = Aes.Create();
            // codit-expect: CWE-321 AES key hard-coded as a string literal
            aes.Key = Encoding.UTF8.GetBytes("ThisIsASecretKey1234567890123456");
            aes.Padding = PaddingMode.PKCS7;



            // codit-expect: CWE-327 ECB mode
            aes.Mode = CipherMode.ECB;
            return aes.CreateEncryptor().TransformFinalBlock(plain, 0, plain.Length);
        }

        public byte[] Encrypt(byte[] plain)
        {
            var nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
            var tag = new byte[AesGcm.TagByteSizes.MaxSize];
            var ct = new byte[plain.Length];
            // codit-safe: CWE-327 AES-GCM with a random nonce
            using var gcm = new AesGcm(_dataKey, tag.Length);
            gcm.Encrypt(nonce, plain, ct, tag);
            var output = new byte[nonce.Length + tag.Length + ct.Length];
            Buffer.BlockCopy(nonce, 0, output, 0, nonce.Length);
            Buffer.BlockCopy(tag, 0, output, nonce.Length, tag.Length);
            Buffer.BlockCopy(ct, 0, output, nonce.Length + tag.Length, ct.Length);
            return output;
        }

        public RSA LegacySigningKey()
        {
            // codit-expect: CWE-326 1024-bit RSA key
            return new RSACryptoServiceProvider(1024);
        }



        public RSA SigningKey()
        {
            // codit-safe: CWE-326 3072-bit RSA key
            return RSA.Create(3072);
        }

        public HttpClient LegacyAcquirerClient()
        {
            var handler = new HttpClientHandler
            {
                // codit-expect: CWE-295 every server certificate accepted
                ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
            };
            return new HttpClient(handler);
        }



        public HttpClient AcquirerClient()
        {
            // codit-safe: CWE-295 default handler validates the chain and host name
            return new HttpClient(new HttpClientHandler()) { Timeout = TimeSpan.FromSeconds(10) };
        }
    }

    public interface IKeyVault
    {
        byte[] GetSecretBytes(string name);
    }
}
