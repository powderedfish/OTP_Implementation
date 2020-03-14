using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Wiry.Base32;
using System.Security.Cryptography;

namespace OTP_Implementation
{
    /// <summary>
    /// HOTP implementation
    /// </summary>
    class RFC4226
    {

        private const int NUMBER_DIGITS = 6;
        public static int  Counter {get;set;}

        public static bool Verified(string key, string inputCode)
        {
            long timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            byte[] byteMsg = new byte[8];

            long currentCounter = Counter++;

            for (int i = 1; i <= byteMsg.Length; i++)
            {
                byteMsg[byteMsg.Length - i] = (byte)(currentCounter & 0xff);
                currentCounter = currentCounter >> 8;
            }


            byte[] byteKey = Base32Encoding.Standard.ToBytes(key);

            HMACSHA1 hmacsha1 = new HMACSHA1(byteKey);

            byte[] hashResult = hmacsha1.ComputeHash(byteMsg);

            int offset = hashResult[hashResult.Length - 1] & 0xf;

            int result = (hashResult[offset] & 0x7f) << 24 |
                         (hashResult[offset + 1] & 0xff) << 16 |
                         (hashResult[offset + 2] & 0xff) << 8 |
                         (hashResult[offset + 3] & 0xff);

            //show 6 digits of code only
            string code = (result % Math.Pow(10, NUMBER_DIGITS)).ToString();
            hmacsha1.Dispose();

            //add 0's if less than 6 digits
            while (code.Length < NUMBER_DIGITS)
            {
                code = "0" + code;
            }
            return code.Equals(inputCode);
        }
    }
}
