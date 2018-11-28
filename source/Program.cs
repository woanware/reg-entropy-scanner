using System;
using System.Collections.Generic;
using CsvHelper;
using static Registry.Cells.VkCellRecord;
using System.Text.RegularExpressions;
using System.Reflection;
using Registry.Other;
using Fclp;
using System.IO;

namespace regentropyscanner
{
    /// <summary>
    /// 
    /// </summary>
    internal class ApplicationArguments
    {
        public int MinLength { get; set; }
        public string Output { get; set; }
        public string Input { get; set; }
        public bool Dump { get; set; }
    }

    /// <summary>
    /// 
    /// </summary>
    class Program
    {
        #region Member Variables
        private static FluentCommandLineParser<ApplicationArguments> fclp;
        #endregion

        /// <summary>
        /// 
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            if (ProcessCommandLine(args) == false)
            {
                return;
            }

            if (CheckCommandLine() == false)
            {
                return;
            }

            using (FileStream fileStream = new FileStream(Path.Combine(fclp.Object.Output, "reg-entropy-scanner.tsv"), FileMode.Create, FileAccess.Write))
            using (StreamWriter streamWriter = new StreamWriter(fileStream))
            using (CsvWriter cw = new CsvHelper.CsvWriter(streamWriter))
            {
                cw.Configuration.Delimiter = "\t";
                // Write out the file headers
                cw.WriteField("File");
                cw.WriteField("Key");
                cw.WriteField("ValueName");
                cw.WriteField("ValueType");
                cw.WriteField("Entropy");
                cw.WriteField("Bin File");
                cw.WriteField("Data");
                cw.WriteField("Data (ASCII)");
                cw.NextRecord();

                FileAttributes fa = File.GetAttributes(fclp.Object.Input);
                if ((fa & FileAttributes.Directory) == FileAttributes.Directory)
                {
                    DirectoryInfo d = new DirectoryInfo(fclp.Object.Input);
                    foreach (var file in d.GetFiles("*"))
                    {
                        ProcessFile(cw, file.FullName);
                    }
                }
                else
                {
                    ProcessFile(cw, fclp.Object.Input);
                }               
            }          
        }

        /// <summary>
        /// 
        /// </summary>
        private static bool ProcessCommandLine(string[] args)
        {
            fclp = new FluentCommandLineParser<ApplicationArguments>
            {
                IsCaseSensitive = false
            };

            fclp.Setup(arg => arg.Input)
               .As('i')
               .Required()
               .WithDescription("Input file or folder to process");

            fclp.Setup(arg => arg.Output)
                .As('o')
                .Required()
                .WithDescription("Output directory for analysis results");

            fclp.Setup(arg => arg.MinLength)
                .As('m')
                .SetDefault(10)
                .WithDescription("Minimum length of data (defaults to 10)");

            var header =
               $"{Assembly.GetExecutingAssembly().GetName().Name} v{Assembly.GetExecutingAssembly().GetName().Version.ToString(3)}" +
               "\r\n\r\nAuthor: Mark Woan / woanware (markwoan@gmail.com)" +
               "\r\nhttps://github.com/woanware/reg-entropy-scanner";        

            // Sets up the parser to execute the callback when -? or --help is supplied
            fclp.SetupHelp("?", "help")
                .WithHeader(header)
                .Callback(text => Console.WriteLine(text));

            var result = fclp.Parse(args);

            if (result.HelpCalled)
            {
                return false;
            }

            if (result.HasErrors)
            {
                Console.WriteLine("");
                Console.WriteLine(result.ErrorText);
                fclp.HelpOption.ShowHelp(fclp.Options);
                return false;
            }

            return true;
        }

        /// <summary>
        /// Performs some basic command line parameter checking
        /// </summary>
        /// <returns></returns>
        private static bool CheckCommandLine()
        {
            FileAttributes fa = File.GetAttributes(fclp.Object.Input);
            if ((fa & FileAttributes.Directory) == FileAttributes.Directory)
            {
                if (Directory.Exists(fclp.Object.Input) == false)
                {
                    Console.WriteLine("Input directory (-i) does not exist");
                    return false;
                }
            }
            else
            {
                if (File.Exists(fclp.Object.Input) == false)
                {
                    Console.WriteLine("Input file (-i) does not exist");
                    return false;
                }
            }               

            if (Directory.Exists(fclp.Object.Output) == false)
            {
                Console.WriteLine("Output directory (-o) does not exist");
                return false;
            }

            return true;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="cw"></param>
        /// <param name="filePath"></param>
        private static void ProcessFile(CsvWriter cw, string filePath)
        {
            try
            {
                var registryHive = new Registry.RegistryHive(filePath);
                registryHive.RecoverDeleted = true;
                if (registryHive.ParseHive() == false)
                {
                    Console.WriteLine("Error parsing file: " + filePath);
                    return;
                }

                CheckKey(cw, Path.GetFileName(filePath), registryHive.Root);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error parsing file (" + ex.Message + "): " + filePath);
            }            
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="rk"></param>
        private static void CheckKey(CsvWriter cw, string fileName, Registry.Abstractions.RegistryKey rk)
        {
            foreach (var sk in rk.SubKeys)
            {
                CheckValues(cw, fileName, sk);
                CheckKey(cw, fileName, sk);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="rk"></param>
        private static void CheckValues(CsvWriter cw, string fileName, Registry.Abstractions.RegistryKey rk)
        {
            foreach (var val in rk.Values)
            {
                switch (val.VkRecord.DataType)
                {
                    case DataTypeEnum.RegDword:
                    case DataTypeEnum.RegDwordBigEndian:
                    case DataTypeEnum.RegFileTime:
                    case DataTypeEnum.RegQword:
                    case DataTypeEnum.RegLink:
                    case DataTypeEnum.RegExpandSz:
                        continue;
                }

                if (val.ValueDataRaw.Length < fclp.Object.MinLength)
                {
                    continue;
                }

                cw.WriteField(fileName);
                cw.WriteField(Helpers.StripRootKeyNameFromKeyPath(rk.KeyPath));
                cw.WriteField(val.ValueName);
                cw.WriteField(val.ValueType);
                cw.WriteField(EntropyShannon(val.ValueDataRaw));

                if (val.VkRecord.DataType != DataTypeEnum.RegSz)
                {                  
                    if (val.VkRecord.DataType == DataTypeEnum.RegBinary)
                    {
                        WriteFile(cw, fileName, val.ValueDataRaw);
                    }
                    else
                    {
                        cw.WriteField("");
                    }

                    cw.WriteField(val.ValueData);
                    cw.WriteField(TrimNonAscii(System.Text.Encoding.ASCII.GetString(val.ValueDataRaw)));
                }
                else
                {                    
                    cw.WriteField("");
                    cw.WriteField(val.ValueData);
                    cw.WriteField("");
                }
                
                cw.NextRecord();               
            }
        }

        private static void WriteFile(CsvWriter cw, string fileName, byte[] data)
        {
            try
            {
                Guid g = Guid.NewGuid();
                File.WriteAllBytes(Path.Combine(fclp.Object.Output, fileName + g.ToString() + ".bin"), data);
                cw.WriteField(fileName + "-" + g.ToString() + ".bin");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error writing .bin file: " + ex.Message);

            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
		private static float EntropyShannon(byte[] data)
        {
            float logbase = 256f; 

            var dict = new Dictionary<UInt32, int>();
            for (int i = 0; i < data.Length; i++)
            {
                byte d = data[i];
                if (!dict.ContainsKey(d))
                {
                    dict.Add(d, 1);
                }                   
                else
                {
                    dict[d] += 1;
                }                    
            }
           
            float ientr = 0.0f;
            int len = data.Length;
            foreach (var val in dict.Values)
            {
                var prop = (float)val / len;
                if (prop == 0)
                {
                    continue;
                }
                ientr -= prop * (float)Math.Log(prop, logbase);
            }

            //Console.WriteLine("Entropy: " + ientr);
            return ientr;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        private static string TrimNonAscii(string value)
        {
            string pattern = "[^ -~]+";
            Regex reg_exp = new Regex(pattern);
            return reg_exp.Replace(value, "");
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="filename"></param>
        /// <returns></returns>
        private static string GetSafeFilename(string filename)
        {

            return string.Join("_", filename.Split(Path.GetInvalidFileNameChars())).Replace(",", "").Replace(" ", "");

        }
    }
}
