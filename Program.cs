using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace nutcracker
{
    internal class Program
    {
        /// <summary>
        /// The goal of this program is to be intentionally cracked. Because every run
        /// is dynamic, every session is not the same, the password always changes. Use
        /// assembly to either crack the password during runtime or jmp to access granted!
        /// </summary>
        const int MAXTIME = 15;

        /// <summary>
        /// Timer delayed, 15 seocnds max till session expires
        /// </summary>
        public static Stopwatch sw = new Stopwatch();
        
        /// <summary>
        /// Main, Entry Point
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {            
            do
            {
                // Papers please!
                Console.Write($"Password: ");

                //Validation
                if (FlagGranted(TypedHash(Console.ReadLine()), GenDynamicSessionHash()))
                {
                    Console.WriteLine("Access Granted! Press [Enter] to exit...");
                    Console.ReadLine();
                    Environment.Exit(0);
                }
                else
                    Console.WriteLine("Access Failed!");

            } while (TimerIsRunning());
        }

        /// <summary>
        /// Compute a sha256 from readable password
        /// </summary>
        /// <param name="temp"></param>
        /// <returns></returns>
        static string TypedHash(string temp)
        {
            StringBuilder sb = new StringBuilder();

            var crypt = new SHA256Managed();
            byte[] nbArray = crypt.ComputeHash(Encoding.ASCII.GetBytes(temp));

            foreach (byte b in nbArray)
            {
                sb.Append(b.ToString("x2"));
            }

            return sb.ToString();
        }

        /// <summary>
        /// Timer is running, dont let that 'stop' you!
        /// </summary>
        /// <returns></returns>
        static bool TimerIsRunning()
        {
            if (!sw.IsRunning)
                sw.Start();

            if (sw.Elapsed.TotalSeconds >= MAXTIME)
            {
                sw.Stop();
                return false;
            }

            return true;
        }

        /// <summary>
        /// Dynamic session generate hash everytime the program is run.
        /// Hash is not always the same, however, hashes will be unique
        /// each day to the 'month', 'day', 'year', 'hour','minute', and 'second'
        /// </summary>
        /// <returns></returns>
        static string GenDynamicSessionHash()
        {
            var session = string.Empty;
            try
            {
                foreach (var p in Process.GetProcesses())
                {
                    // Refresh, check for Ptr == 0
                    p.Refresh();                    
                    if (p.ProcessName.Contains("nutcracker"))
                    {
                        if (p.MainWindowHandle != IntPtr.Zero)
                        {                            
                            session = StringCleanup(p.StartTime.ToString());                            
                        }
                    }
                }
            } catch (Exception ex)
            {
                // Nullify access errors
            }

            return TypedHash(session);
        }

        /// <summary>
        /// Cleanup before hashing 
        /// </summary>
        /// <param name="prune"></param>
        /// <returns></returns>
        static string StringCleanup(string prune)
        {
            string pattern = @"[\W]";
            prune = Regex.Replace(prune, pattern, string.Empty);
            return prune;
        }

        /// <summary>
        /// Ultimately determines the outcome of users key against system key
        /// </summary>
        /// <param name="ukey"></param>
        /// <param name="skey"></param>
        /// <returns></returns>
        static bool FlagGranted(string ukey, string skey)
        {
            return ukey == skey;
        }
    }
}
