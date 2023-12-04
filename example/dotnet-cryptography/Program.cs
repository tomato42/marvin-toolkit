using System.CommandLine;
using System.Diagnostics;
using System.Security.Cryptography;

var inputOption = new Option<FileInfo>(name: "-i", description: "File with the ciphertexts to decrypt.")  { IsRequired = true };
var outputOption = new Option<FileInfo>(name: "-o", description: "File to write the timing data to.")  { IsRequired = true };
var keyOption = new Option<FileInfo>(name: "-k", description: "The private key to use for decryption.")  { IsRequired = true };
var sizeOption = new Option<int>(name: "-n", description: "Size of individual ciphertexts for decryption.")  { IsRequired = true };

var rootCommand = new RootCommand();
rootCommand.AddOption(inputOption);
rootCommand.AddOption(outputOption);
rootCommand.AddOption(keyOption);
rootCommand.AddOption(sizeOption);

rootCommand.SetHandler((FileInfo inputFile, FileInfo outputFile, FileInfo keyFile, int size) =>
{
    using FileStream input = inputFile.OpenRead();

    using RSA rsa = RSA.Create();
    var paddingMode = RSAEncryptionPadding.Pkcs1;
    rsa.ImportFromPem(File.ReadAllText(keyFile.FullName));

    using StreamWriter output = new StreamWriter(outputFile.FullName);
    output.WriteLine("raw times");

    byte[] data = new byte[size];
    while (true)
    {
        int n = input.Read(data);
        if (n == 0)
        {
            break;
        }

        if (n != size)
        {
            throw new InvalidOperationException($"The input file '{inputFile.FullName}' length is not a multiple of '{size}'.");
        }

        long startTime = Stopwatch.GetTimestamp();
        try
        {
            rsa.Decrypt(data, paddingMode);
        }
        catch
        { }
        TimeSpan elapedTime = Stopwatch.GetElapsedTime(startTime);

        output.WriteLine((long)elapedTime.TotalNanoseconds);
    }
}, inputOption, outputOption, keyOption, sizeOption);

return rootCommand.Invoke(args);
