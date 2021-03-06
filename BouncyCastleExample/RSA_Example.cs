﻿using System;
using System.Collections.Generic;
using System.Text;

namespace BouncyCastleExample
{
    class RSA_Example
    {
        public static void Test()
        {
            string priKey, pubKey;
            RSA_Helper.CreateKeysOnly(out priKey, out pubKey);

            var maxLenth = (1024 / 8 - 11);//the maximum message length is 117 bytes.
            for (int i = 1; i <= maxLenth; i++)
            {
                var randomBytes = new byte[i];
                new Random().NextBytes(randomBytes);
                byte[] encData, decData;


                encData = RSA_Helper.EncryptIABC(randomBytes, pubKey);
                decData = RSA_Helper.DecryptIABC(encData, priKey);
                CheckEquals(randomBytes, decData);


                encData = RSA_Helper.EncryptIBC(randomBytes, pubKey);
                decData = RSA_Helper.DecryptIBC(encData, priKey);
                CheckEquals(randomBytes, decData);
            }
        }

        /// <summary>
        /// 检查两个数组是否一致
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        public static void CheckEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                throw new Exception();

            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i])
                    throw new Exception();
        }
    }
}
