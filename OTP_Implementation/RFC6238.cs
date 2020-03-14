using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Wiry.Base32;

namespace OTP_Implementation
{
    /// <summary>
    /// TOTP implementation
    /// </summary>
    public class RFC6238
    {
        private const int NUMBER_DIGITS = 6;

        /// <summary>
        /// getting secret key
        /// </summary>
        /// <returns></returns>
        public static string GenerateSecret()
        {
            //hardcode the secret
            byte[] byteStr = Encoding.ASCII.GetBytes("YourSecret");
            return  Base32Encoding.Standard.GetString(byteStr);
        }
        
        /// <summary>
        /// verified the authenticator code
        /// </summary>
        /// <param name="key">base32 key</param>
        /// <param name="inputCode">input from google authenticator</param>
        /// <returns></returns>
        public static bool Verified(string key, string inputCode)
        {
            long timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            //30 sec
            long timeBase = timestamp / 30;

            byte[] byteMsg = new byte[8];

            for(int i = 1; i <= byteMsg.Length; i++)
            {
                byteMsg[byteMsg.Length - i] = (byte)(timeBase & 0xff);
                timeBase = timeBase >> 8;
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
            while(code.Length < NUMBER_DIGITS)
            {
                code = "0" + code;
            }
            return code.Equals(inputCode);
        }

    }
}
