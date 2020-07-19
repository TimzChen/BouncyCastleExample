using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace BouncyCastleExample
{
    public class Program
    {
        static void Main(string[] args)
        {
            Parallel.For(0, 100, i => { RSA_Sample.Test(); });
            Console.Read();
        }
    }
}
