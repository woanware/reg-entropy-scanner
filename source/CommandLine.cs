using CommandLine;

namespace regentropyscanner
{
    class Options
    {
        [Option('d', "dump", Required = false, DefaultValue = false, HelpText = "Dump values to files")]
        public bool File { get; set; }

        [Option('i', "Input", Required = true, DefaultValue = "", HelpText = "Input (file or folder)")]
        public string Input { get; set; }

        [Option('o', "Output", Required = true, DefaultValue = "", HelpText = "Output FOLDER")]
        public string Output { get; set; }
    }
}
