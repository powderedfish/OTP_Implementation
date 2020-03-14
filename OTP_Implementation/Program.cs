#define TOTP
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OTP_Implementation
{
    class Program
    {

        const int WINDOW_SIZE = 50;
        static void Main(string[] args)
        {
            //key = "LFXXK4STMVRXEZLU" hardcoded
            string key = RFC6238.GenerateSecret();


            while (true)
            {

                string input =Console.ReadLine();
#if TOTP
                Console.WriteLine(RFC6238.Verified(key, input));
#elif HOTP
                bool output = false;
                for (int i = 0; i < WINDOW_SIZE; i++)
                {
                    if (RFC4226.Verified(key, input))
                    {
                        output = true;
                        break;
                    }
                }
                Console.WriteLine(output);
#endif
            }
        }
    }
}
