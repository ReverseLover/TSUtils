using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;

namespace PakTool
{
    public struct TableEntry
    {
        public const int MaxNameLength = 32;

        public string Name;
        public uint Offset;
        public uint Info; // Length for files, DataOffset for dirs

        public TableEntry(string name, uint offset, uint info)
        {
            Name = name;
            Offset = offset;
            Info = info;
        }
    }

    public static class PakArchive
    {
        private const string Magic = "PACK";
        private const int HeaderSize = 8;
        private const int EntrySize = 40;
        private const int BufferSize = 1024 * 1024; // 1MB buffer
        
        // HSE obfuscation with SIMD acceleration
        private static void TransformHseInPlace(Span<byte> data)
        {
            if (!Vector.IsHardwareAccelerated || data.Length < Vector<byte>.Count)
            {
                for (int i = 0; i < data.Length; i++)
                    data[i] = unchecked((byte)(-data[i]));
                return;
            }

            var vectors = MemoryMarshal.Cast<byte, Vector<byte>>(data);
            for (int i = 0; i < vectors.Length; i++)
            {
                vectors[i] = Vector<byte>.Zero - vectors[i];
            }

            int consumed = vectors.Length * Vector<byte>.Count;
            for (int i = consumed; i < data.Length; i++)
                data[i] = unchecked((byte)(-data[i]));
        }

        private static string EnsureExtension(string path, string extensionWithDot)
        {
            if (string.IsNullOrWhiteSpace(extensionWithDot) || !extensionWithDot.StartsWith('.'))
                throw new ArgumentException("Extension must start with '.'", nameof(extensionWithDot));

            return Path.ChangeExtension(path, extensionWithDot);
        }

        private static void TransformFile(string inputFile, string outputFile)
        {
            string inputFullPath = Path.GetFullPath(inputFile);
            string outputFullPath = Path.GetFullPath(outputFile);

            if (string.Equals(inputFullPath, outputFullPath, StringComparison.OrdinalIgnoreCase))
            {
                string tempFile = Path.Combine(
                    Path.GetDirectoryName(outputFullPath) ?? "",
                    Path.GetFileName(outputFullPath) + ".tmp");
                TransformFile(inputFullPath, tempFile);
                File.Move(tempFile, outputFullPath, overwrite: true);
                return;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(outputFullPath) ?? "");

            using var inFs = new FileStream(inputFullPath, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize, FileOptions.SequentialScan);
            using var outFs = new FileStream(outputFullPath, FileMode.Create, FileAccess.Write, FileShare.None, BufferSize);

            byte[] buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
            try
            {
                int read;
                while ((read = inFs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    TransformHseInPlace(buffer.AsSpan(0, read));
                    outFs.Write(buffer, 0, read);
                }
            }
            finally { ArrayPool<byte>.Shared.Return(buffer); }
        }

        public static string DecryptHse(string inputHseFile, string? outputPngFile = null)
        {
            string inputFullPath = Path.GetFullPath(inputHseFile);
            string outputFullPath = Path.GetFullPath(outputPngFile ?? EnsureExtension(inputFullPath, ".png"));
            outputFullPath = EnsureExtension(outputFullPath, ".png");

            TransformFile(inputFullPath, outputFullPath);
            return outputFullPath;
        }

        public static string EncryptPng(string inputPngFile, string? outputHseFile = null)
        {
            string inputFullPath = Path.GetFullPath(inputPngFile);
            string outputFullPath = Path.GetFullPath(outputHseFile ?? EnsureExtension(inputFullPath, ".hse"));
            outputFullPath = EnsureExtension(outputFullPath, ".hse");

            TransformFile(inputFullPath, outputFullPath);
            return outputFullPath;
        }

        internal static void ValidateName(string name)
        {
            if (string.IsNullOrEmpty(name)) return;
            if (name.Length >= TableEntry.MaxNameLength)
                throw new NotSupportedException($"Filename '{name}' is too long ({name.Length} chars). Format limit is {TableEntry.MaxNameLength - 1}.");
            
            foreach (char c in name)
            {
                if (c > 127)
                    throw new NotSupportedException($"Filename '{name}' contains non-ASCII characters, which are not supported.");
            }
        }

        #region Extraction

        private struct FileToExtract
        {
            public string FullPath;
            public long ArchiveOffset;
            public uint Size;
        }

        public static void Extract(string archivePath, string outputDir)
        {
            Console.WriteLine($"Extracting files from {archivePath} to {outputDir}");
            outputDir = Path.GetFullPath(outputDir);
            if (!outputDir.EndsWith(Path.DirectorySeparatorChar) && !outputDir.EndsWith(Path.AltDirectorySeparatorChar))
                outputDir += Path.DirectorySeparatorChar;

            using var fs = new FileStream(archivePath, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize, FileOptions.SequentialScan);
            
            Span<byte> magicBytes = stackalloc byte[4];
            fs.ReadExactly(magicBytes);
            if (Encoding.ASCII.GetString(magicBytes) != Magic)
                throw new InvalidDataException("Invalid PACK header.");

            Span<byte> headerBuf = stackalloc byte[4];
            fs.ReadExactly(headerBuf);
            uint rootDataOffset = BinaryPrimitives.ReadUInt32LittleEndian(headerBuf);

            uint rootTableOffset = HeaderSize;
            var filesToExtract = new List<FileToExtract>();
            
            byte[] buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
            try
            {
                CollectFiles(fs, rootTableOffset, rootDataOffset, outputDir, filesToExtract, buffer);

                filesToExtract.Sort((a, b) => a.ArchiveOffset.CompareTo(b.ArchiveOffset));

                var createdDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var file in filesToExtract)
                {
                    if (!file.FullPath.StartsWith(outputDir, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException($"Potentially malicious path: {file.FullPath}");

                    string? parentDir = Path.GetDirectoryName(file.FullPath);
                    if (parentDir != null && createdDirs.Add(parentDir))
                        Directory.CreateDirectory(parentDir);

                    ExtractFileSequential(fs, file, buffer);
                }
            }
            finally { ArrayPool<byte>.Shared.Return(buffer); }
        }

        private static void CollectFiles(FileStream fs, uint tableOffset, uint dataOffset, string currentPath, List<FileToExtract> files, byte[] buffer)
        {
            fs.Position = tableOffset;
            Span<byte> countBuf = stackalloc byte[4];
            
            fs.ReadExactly(countBuf);
            uint dirCount = BinaryPrimitives.ReadUInt32LittleEndian(countBuf);
            var subDirs = new List<TableEntry>((int)dirCount);
            if (dirCount > 0)
            {
                int bytesToRead = checked((int)dirCount * EntrySize);
                byte[] activeBuffer = buffer;
                bool rented = false;
                if (bytesToRead > buffer.Length)
                {
                    activeBuffer = ArrayPool<byte>.Shared.Rent(bytesToRead);
                    rented = true;
                }
                try
                {
                    var span = activeBuffer.AsSpan(0, bytesToRead);
                    fs.ReadExactly(span);
                    for (int i = 0; i < (int)dirCount; i++)
                        subDirs.Add(ReadEntryFromSpan(span.Slice(i * EntrySize, EntrySize)));
                }
                finally { if (rented) ArrayPool<byte>.Shared.Return(activeBuffer); }
            }

            fs.ReadExactly(countBuf);
            uint fileCount = BinaryPrimitives.ReadUInt32LittleEndian(countBuf);
            if (fileCount > 0)
            {
                int bytesToRead = checked((int)fileCount * EntrySize);
                byte[] activeBuffer = buffer;
                bool rented = false;
                if (bytesToRead > buffer.Length)
                {
                    activeBuffer = ArrayPool<byte>.Shared.Rent(bytesToRead);
                    rented = true;
                }
                try
                {
                    var span = activeBuffer.AsSpan(0, bytesToRead);
                    fs.ReadExactly(span);
                    for (int i = 0; i < (int)fileCount; i++)
                    {
                        var entry = ReadEntryFromSpan(span.Slice(i * EntrySize, EntrySize));
                        files.Add(new FileToExtract {
                            FullPath = Path.GetFullPath(Path.Combine(currentPath, entry.Name)),
                            ArchiveOffset = (long)dataOffset + entry.Offset,
                            Size = entry.Info
                        });
                    }
                }
                finally { if (rented) ArrayPool<byte>.Shared.Return(activeBuffer); }
            }

            foreach (var dir in subDirs)
                CollectFiles(fs, dir.Offset, dir.Info, Path.Combine(currentPath, dir.Name), files, buffer);
        }

        private static void ExtractFileSequential(FileStream fs, FileToExtract file, byte[] buffer)
        {
            if (fs.Position != file.ArchiveOffset) fs.Seek(file.ArchiveOffset, SeekOrigin.Begin);

            using var outFs = new FileStream(file.FullPath, FileMode.Create, FileAccess.Write, FileShare.None, BufferSize);
            
            uint remaining = file.Size;
            while (remaining > 0)
            {
                int toRead = (int)Math.Min((long)remaining, (long)buffer.Length);
                int read = fs.Read(buffer, 0, toRead);
                if (read == 0) throw new EndOfStreamException("Unexpected end of stream.");

                outFs.Write(buffer, 0, read);
                remaining -= (uint)read;
            }
        }

        private static TableEntry ReadEntryFromSpan(ReadOnlySpan<byte> span)
        {
            var nameSpan = span.Slice(0, 32);
            int nullPos = nameSpan.IndexOf((byte)0);
            string name = Encoding.ASCII.GetString(nullPos == -1 ? nameSpan : nameSpan.Slice(0, nullPos));
            return new TableEntry { 
                Name = name, 
                Offset = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(32, 4)), 
                Info = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(36, 4)) 
            };
        }

        #endregion

        #region Packing

        private class PakDirectory {
            public string Name = "";
            public string FullPath = "";
            public List<PakDirectory> SubDirs = new();
            public List<PakFile> Files = new();
            public uint TableOffset, DataOffset;
        }

        private class PakFile {
            public string Name = "", FullPath = "";
            public uint Size;
        }

        public static void Pack(string inputDir, string outputPak)
        {
            Console.WriteLine($"Packing {inputDir} into {outputPak}");
            var root = ScanDirectory(inputDir);
            uint currentDataOffset = CalculateOffsets(root, HeaderSize);
            AssignDataOffsets(root, currentDataOffset);

            using var fs = new FileStream(outputPak, FileMode.Create, FileAccess.Write, FileShare.None, BufferSize);
            Span<byte> header = stackalloc byte[8];
            Encoding.ASCII.GetBytes(Magic).CopyTo(header);
            BinaryPrimitives.WriteUInt32LittleEndian(header[4..], currentDataOffset);
            fs.Write(header);

            byte[] buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
            try 
            { 
                WriteTables(fs, root, buffer);
                WriteData(fs, root, buffer); 
            }
            finally { ArrayPool<byte>.Shared.Return(buffer); }
        }

        private static PakDirectory ScanDirectory(string path, string name = "")
        {
            ValidateName(name);
            var node = new PakDirectory { Name = name, FullPath = path };
            var di = new DirectoryInfo(path);
            var items = di.GetFileSystemInfos();
            Array.Sort(items, (a, b) => string.Compare(a.Name, b.Name, StringComparison.Ordinal));

            foreach (var item in items)
            {
                if (item is DirectoryInfo subDi) node.SubDirs.Add(ScanDirectory(subDi.FullName, subDi.Name));
                else if (item is FileInfo fi) {
                    ValidateName(fi.Name);
                    if (fi.Length > uint.MaxValue) throw new NotSupportedException($"File '{fi.Name}' exceeds 4GB.");
                    node.Files.Add(new PakFile { Name = fi.Name, FullPath = fi.FullName, Size = (uint)fi.Length });
                }
            }
            return node;
        }

        private static uint CalculateOffsets(PakDirectory node, uint tableOffset)
        {
            node.TableOffset = tableOffset;
            ulong nextOffset = (ulong)tableOffset + 8 + ((uint)(node.SubDirs.Count + node.Files.Count) * EntrySize);
            if (nextOffset > uint.MaxValue) throw new NotSupportedException("Table section exceeds 4GB.");
            
            uint nextTableOffset = (uint)nextOffset;
            foreach (var subDir in node.SubDirs) nextTableOffset = CalculateOffsets(subDir, nextTableOffset);
            return nextTableOffset;
        }

        private static uint AssignDataOffsets(PakDirectory node, uint currentDataOffset)
        {
            node.DataOffset = currentDataOffset;
            ulong offset = currentDataOffset;
            foreach (var file in node.Files) {
                offset += file.Size;
                if (offset > uint.MaxValue) throw new NotSupportedException("Data section exceeds 4GB.");
            }
            uint nextDataOffset = (uint)offset;
            foreach (var subDir in node.SubDirs) nextDataOffset = AssignDataOffsets(subDir, nextDataOffset);
            return nextDataOffset;
        }

        private static void WriteTables(FileStream fs, PakDirectory node, byte[] buffer)
        {
            if (fs.Position != node.TableOffset) fs.Seek(node.TableOffset, SeekOrigin.Begin);
            int tableSize = 4 + (node.SubDirs.Count * EntrySize) + 4 + (node.Files.Count * EntrySize);
            
            byte[] activeBuffer = buffer;
            bool rented = false;
            if (tableSize > buffer.Length)
            {
                activeBuffer = ArrayPool<byte>.Shared.Rent(tableSize);
                rented = true;
            }

            try {
                var span = activeBuffer.AsSpan(0, tableSize);
                BinaryPrimitives.WriteUInt32LittleEndian(span[..4], (uint)node.SubDirs.Count);
                int pos = 4;
                foreach (var subDir in node.SubDirs) {
                    PrepareEntry(span.Slice(pos, EntrySize), subDir.Name, subDir.TableOffset, subDir.DataOffset);
                    pos += EntrySize;
                }
                BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(pos, 4), (uint)node.Files.Count);
                pos += 4;
                uint relOffset = 0;
                foreach (var file in node.Files) {
                    PrepareEntry(span.Slice(pos, EntrySize), file.Name, relOffset, file.Size);
                    pos += EntrySize;
                    relOffset += file.Size;
                }
                fs.Write(span);
            } finally { if (rented) ArrayPool<byte>.Shared.Return(activeBuffer); }

            foreach (var subDir in node.SubDirs) WriteTables(fs, subDir, buffer);
        }

        private static void PrepareEntry(Span<byte> span, string name, uint offset, uint info)
        {
            span[..TableEntry.MaxNameLength].Clear();
            Encoding.ASCII.GetBytes(name, span[..TableEntry.MaxNameLength]);
            BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(32, 4), offset);
            BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(36, 4), info);
        }

        private static void WriteData(FileStream fs, PakDirectory node, byte[] buffer)
        {
            foreach (var file in node.Files)
            {
                using var inFs = new FileStream(file.FullPath, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize);

                int read;
                while ((read = inFs.Read(buffer.AsSpan())) > 0)
                {
                    var chunk = buffer.AsSpan(0, read);
                    fs.Write(chunk);
                }
            }

            foreach (var subDir in node.SubDirs)
                WriteData(fs, subDir, buffer);
        }

        #endregion
    }
    
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                PrintUsage();
                return;
            }

            string command = args[0].ToLowerInvariant();
            string input = Path.GetFullPath(args[1]);
            string? output = args.Length > 2 ? Path.GetFullPath(args[2]) : null;

            try
            {
                if (command == "extract")
                {
                    output ??= Path.Combine(Path.GetDirectoryName(input) ?? "", Path.GetFileNameWithoutExtension(input));
                    PakArchive.Extract(input, output);
                }
                else if (command == "pack")
                {
                    output ??= input.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + ".pak";
                    PakArchive.Pack(input, output);
                }
                else if (command == "decrypt")
                {
                    PakArchive.DecryptHse(input, output);
                }
                else if (command == "encrypt")
                {
                    PakArchive.EncryptPng(input, output);
                }
                else
                {
                    PrintUsage();
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error: {ex.Message}");
                Console.ResetColor();
            }
        }

        static void PrintUsage()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  PakTool extract <input.pak> [output_dir]");
            Console.WriteLine("  PakTool pack <input_dir> [output.pak]");
            Console.WriteLine("  PakTool decrypt <input.hse> [output.png]");
            Console.WriteLine("  PakTool encrypt <input.png> [output.hse]");
        }
    }
}