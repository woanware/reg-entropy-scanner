using Registry;
using System;
using System.Collections.Generic;
using CsvHelper;
using static Registry.Cells.VkCellRecord;
using System.IO;
using CommandLine;
using System.Text.RegularExpressions;
using System.Reflection;
using Registry.Other;

namespace regentropyscanner
{  
    /// <summary>
    /// 
    /// </summary>
    class Program
    {
        #region Member Variables
        private static Options options;
        #endregion

        /// <summary>
        /// 
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            AssemblyName assemblyName = assembly.GetName();

            Console.WriteLine(Environment.NewLine + "reg-entropy-scanner v" + assemblyName.Version.ToString(3) + Environment.NewLine);

            options = new Options();
            if (CommandLine.Parser.Default.ParseArguments(args, options) == false)
            {
                return;
            }

            CheckCommandLine();

            using (FileStream fileStream = new FileStream(Path.Combine(options.Output, "reg-entropy-scanner.tsv"), FileMode.Create, FileAccess.Write))
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

                FileAttributes fa = File.GetAttributes(options.Input);
                if ((fa & FileAttributes.Directory) == FileAttributes.Directory)
                {
                    DirectoryInfo d = new DirectoryInfo(options.Input);
                    foreach (var file in d.GetFiles("*"))
                    {
                        ProcessFile(cw, file.FullName);
                    }
                }
                else
                {
                    ProcessFile(cw, options.Input);
                }               
            }          
        }

        /// <summary>
        /// Performs some basic command line parameter checking
        /// </summary>
        /// <returns></returns>
        private static bool CheckCommandLine()
        {
            if (options.Input.Length == 0)
            {
                Console.WriteLine("Input parameter (-i) not supplied (file or directory)");
                return false;
            }

            FileAttributes fa = File.GetAttributes(options.Input);
            if ((fa & FileAttributes.Directory) == FileAttributes.Directory)
            {
                if (Directory.Exists(options.Input) == false)
                {
                    Console.WriteLine("Input directory (-i) does not exist");
                    return false;
                }
            }
            else
            {
                if (File.Exists(options.Input) == false)
                {
                    Console.WriteLine("Input file (-i) does not exist");
                    return false;
                }
            }
                

            if (options.Output.Length == 0)
            {
                Console.WriteLine("Output parameter (-o) not supplied (file or directory)");
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
                var registryHive = new RegistryHive(filePath);
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

                if (val.ValueDataRaw.Length < 100)
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
                File.WriteAllBytes(Path.Combine(options.Output, fileName + g.ToString() + ".bin"), data);
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
