import cmd
from systems.encoding_system import EncodingSystem
from systems.compression_system import CompressionSystem

class PsiONIUMShell(cmd.Cmd):
    intro = "Welcome to the pSIONIUM Shell. Type 'help' for a list of commands."
    prompt = "pSIONIUM> "

    def __init__(self):
        super().__init__()
        self.encoding_system = EncodingSystem()
        self.compression_system = CompressionSystem()

    def do_encode(self, arg):
        """
        Encode a file.
        Usage: encode <file> [--type=<encoding_type>]
        """
        args = arg.split()
        if len(args) < 1:
            print("Error: Missing file path.")
            return

        file_path = args[0]
        encoding_type = "dynamic"  # Default encoding type
        if len(args) > 1 and args[1].startswith("--type="):
            encoding_type = args[1].split("=")[1]

        try:
            with open(file_path, 'rb') as file:
                data = file.read()

            encoded_data = self.encoding_system.process(data)
            output_path = file_path + ".encoded"
            with open(output_path, 'w') as output_file:
                output_file.write(encoded_data)

            print(f"File encoded successfully: {output_path}")
        except Exception as e:
            print(f"Error during encoding: {e}")

    def do_decode(self, arg):
        """
        Decode a file.
        Usage: decode <file> [--type=<encoding_type>]
        """
        args = arg.split()
        if len(args) < 1:
            print("Error: Missing file path.")
            return

        file_path = args[0]
        encoding_type = "dynamic"  # Default encoding type
        if len(args) > 1 and args[1].startswith("--type="):
            encoding_type = args[1].split("=")[1]

        try:
            with open(file_path, 'r') as file:
                encoded_data = file.read()

            decoded_data = self.encoding_system.reverse_process(encoded_data)
            output_path = file_path.replace(".encoded", ".decoded")
            with open(output_path, 'wb') as output_file:
                output_file.write(decoded_data)

            print(f"File decoded successfully: {output_path}")
        except Exception as e:
            print(f"Error during decoding: {e}")

    def do_compress(self, arg):
        """
        Compress a file.
        Usage: compress <file> [--algorithm=<compression_algorithm>]
        """
        args = arg.split()
        if len(args) < 1:
            print("Error: Missing file path.")
            return

        file_path = args[0]
        algorithm = "gzip"  # Default compression algorithm
        if len(args) > 1 and args[1].startswith("--algorithm="):
            algorithm = args[1].split("=")[1]

        try:
            with open(file_path, 'rb') as file:
                data = file.read()

            compressed_data = self.compression_system.process(data)
            output_path = file_path + ".compressed"
            with open(output_path, 'wb') as output_file:
                output_file.write(compressed_data)

            print(f"File compressed successfully: {output_path}")
        except Exception as e:
            print(f"Error during compression: {e}")

    def do_decompress(self, arg):
        """
        Decompress a file.
        Usage: decompress <file> [--algorithm=<compression_algorithm>]
        """
        args = arg.split()
        if len(args) < 1:
            print("Error: Missing file path.")
            return

        file_path = args[0]
        algorithm = "gzip"  # Default compression algorithm
        if len(args) > 1 and args[1].startswith("--algorithm="):
            algorithm = args[1].split("=")[1]

        try:
            with open(file_path, 'rb') as file:
                compressed_data = file.read()

            decompressed_data = self.compression_system.reverse_process(compressed_data)
            output_path = file_path.replace(".compressed", ".decompressed")
            with open(output_path, 'wb') as output_file:
                output_file.write(decompressed_data)

            print(f"File decompressed successfully: {output_path}")
        except Exception as e:
            print(f"Error during decompression: {e}")

    def do_exit(self, arg):
        """
        Exit the pSIONIUM shell.
        Usage: exit
        """
        print("Exiting pSIONIUM shell. Goodbye!")
        return True

    def do_quit(self, arg):
        """
        Exit the pSIONIUM shell.
        Usage: quit
        """
        return self.do_exit(arg)

    def do_help(self, arg):
        """
        Show help for available commands.
        Usage: help [command]
        """
        super().do_help(arg)

if __name__ == "__main__":
    PsiONIUMShell().cmdloop()