using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace BouncyCastleExample
{
    internal static class RSA_Helper
    {
        #region IBufferedCipher

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="xmlPublicKey">公钥(XML格式字符串)</param>
        /// <param name="toEncrypt">要加密的数据</param>
        /// <returns> 加密后的数据 </returns>
        public static byte[] EncryptIBC(byte[] toEncrypt, string xmlPublicKey)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(xmlPublicKey);
                var cipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1PADDING");
                cipher.Init(true, DotNetUtilities.GetRsaPublicKey(rsa));
                byte[] outBytes = cipher.DoFinal(toEncrypt);
                return outBytes;
            }
        }

        /// <summary>
        /// 私钥加密(严禁使用！)
        /// </summary>
        /// <param name="xmlPrivateKey">私钥(XML格式字符串)</param>
        /// <param name="toEncrypt">要加密的数据</param>
        /// <returns> 加密后的数据 </returns>
        /// <remarks>仅适用于验证理论上的可行性</remarks>
        [Obsolete(error: false, message: "You should never use it, because it must be wrong!")]
        public static byte[] EncryptWithPrivateKeyIBC(byte[] toEncrypt, string xmlPrivateKey)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(xmlPrivateKey);
                var cipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1PADDING");
                cipher.Init(true, DotNetUtilities.GetRsaKeyPair(rsa).Private);
                byte[] outBytes = cipher.DoFinal(toEncrypt);
                return outBytes;
            }
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="xmlPrivateKey">私钥(XML格式字符串)</param>
        /// <param name="toDecrypt">要解密数据</param>
        /// <returns>解密后的数据</returns>
        public static byte[] DecryptIBC(byte[] toDecrypt, string xmlPrivateKey)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(xmlPrivateKey);
                var cipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1PADDING");
                cipher.Init(false, DotNetUtilities.GetRsaKeyPair(rsa).Private);
                byte[] outBytes = cipher.DoFinal(toDecrypt);
                return outBytes;
            }
        }

        /// <summary>
        /// 公钥解密(严禁使用！)
        /// </summary>
        /// <param name="xmlPublicKey">公钥(XML格式字符串)</param>
        /// <param name="toDecrypt">要解密数据</param>
        /// <returns>解密后的数据</returns>
        /// <remarks>仅适用于验证理论上的可行性</remarks>
        [Obsolete(error: false, message: "You should never use it, because it must be wrong!")]
        public static byte[] DecryptWithPublicKeyIBC(byte[] toDecrypt, string xmlPublicKey)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(xmlPublicKey);
                var cipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1PADDING");
                cipher.Init(false, DotNetUtilities.GetRsaPublicKey(rsa));
                byte[] outBytes = cipher.DoFinal(toDecrypt);
                return outBytes;
            }
        }

        #endregion


        #region IAsymmetricBlockCipher

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="xmlPublicKey">公钥(XML格式字符串)</param>
        /// <param name="toEncrypt">要加密的数据</param>
        /// <returns> 加密后的数据 </returns>
        public static byte[] EncryptIABC(byte[] toEncrypt, string xmlPublicKey)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(xmlPublicKey);
                var encryptEngine = new Pkcs1Encoding(new RsaEngine());
                encryptEngine.Init(true, DotNetUtilities.GetRsaPublicKey(rsa));
                var encrypted = encryptEngine.ProcessBlock(toEncrypt, 0, toEncrypt.Length);
                return encrypted;
            }
        }

        /// <summary>
        /// 私钥加密(严禁使用！)
        /// </summary>
        /// <param name="xmlPrivateKey">私钥(XML格式字符串)</param>
        /// <param name="toEncrypt">要加密的数据</param>
        /// <returns> 加密后的数据 </returns>
        /// <remarks>仅适用于验证理论上的可行性</remarks>
        [Obsolete(error: false, message: "You should never use it, because it must be wrong!")]
        public static byte[] EncryptWithPrivateKeyIABC(byte[] toEncrypt, string xmlPrivateKey)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(xmlPrivateKey);
                var encryptEngine = new Pkcs1Encoding(new RsaEngine());
                encryptEngine.Init(true, DotNetUtilities.GetKeyPair(rsa).Private);
                var encrypted = encryptEngine.ProcessBlock(toEncrypt, 0, toEncrypt.Length);
                return encrypted;
            }
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="xmlPrivateKey">私钥(XML格式字符串)</param>
        /// <param name="toDecrypt">要解密数据</param>
        /// <returns>解密后的数据</returns>
        public static byte[] DecryptIABC(byte[] toDecrypt, string xmlPrivateKey)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(xmlPrivateKey);
                var decryptEngine = new Pkcs1Encoding(new RsaEngine());
                decryptEngine.Init(false, DotNetUtilities.GetKeyPair(rsa).Private);
                var decrypted = decryptEngine.ProcessBlock(toDecrypt, 0, toDecrypt.Length);
                return decrypted;
            }
        }

        /// <summary>
        /// 公钥解密(严禁使用！)
        /// </summary>
        /// <param name="xmlPublicKey">公钥(XML格式字符串)</param>
        /// <param name="toDecrypt">要解密数据</param>
        /// <returns>解密后的数据</returns>
        /// <remarks>仅适用于验证理论上的可行性</remarks>
        [Obsolete(error: false, message: "You should never use it, because it must be wrong!")]
        public static byte[] DecryptWithPublicKeyIABC(byte[] toDecrypt, string xmlPublicKey)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(xmlPublicKey);
                var decryptEngine = new Pkcs1Encoding(new RsaEngine());
                decryptEngine.Init(false, DotNetUtilities.GetRsaPublicKey(rsa));
                var decrypted = decryptEngine.ProcessBlock(toDecrypt, 0, toDecrypt.Length);
                return decrypted;
            }
        }

        #endregion


        #region HelperMethods

        /// <summary>
        /// 产生密钥
        /// </summary>
        /// <param name="xmlPrivateKey">私钥</param>
        /// <param name="xmlPublicKey">公钥</param>
        public static void CreateKeysOnly(out string xmlPrivateKey, out string xmlPublicKey)
        {
            using (var rsa = CreateKeys(out xmlPrivateKey, out xmlPublicKey)) { }
        }

        /// <summary>
        /// 产生密钥
        /// </summary>
        /// <param name="xmlPrivateKey">私钥</param>
        /// <param name="xmlPublicKey">公钥</param>
        public static RSACryptoServiceProvider CreateKeys(out string xmlPrivateKey, out string xmlPublicKey)
        {
            var rsa = new RSACryptoServiceProvider();
            xmlPrivateKey = rsa.ToXmlString(true);
            xmlPublicKey = rsa.ToXmlString(false);
            return rsa;
        }

        #endregion
    }
}
