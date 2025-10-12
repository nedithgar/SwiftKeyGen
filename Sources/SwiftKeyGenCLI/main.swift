import Foundation
import SwiftKeyGen

struct SwiftKeyGenCLI {
    // Update this value when publishing a new release (match the git tag)
    private static let version = "0.1.1"

    static func main() {
        let arguments = CommandLine.arguments
        
        if arguments.count < 2 {
            printUsage()
            exit(1)
        }
        
        let command = arguments[1]
        
        switch command {
        case "convert":
            handleConvert(Array(arguments.dropFirst(2)))
        case "export":
            handleExport(Array(arguments.dropFirst(2)))
        case "generate":
            handleGenerate(Array(arguments.dropFirst(2)))
        case "version", "--version", "-V":
            printVersion()
            exit(0)
        case "help", "-h", "--help":
            printUsage()
        default:
            print("Unknown command: \(command)")
            printUsage()
            exit(1)
        }
    }
    
    static func printUsage() {
        print("""
        SwiftKeyGen - SSH Key Generation and Conversion Tool
        Version: \(version)
        
        Usage:
            swiftkeygen <command> [options]
        
        Commands:
            generate    Generate a new SSH key pair
            convert     Convert key between formats
            export      Export key to stdout or file
            version     Show the swiftkeygen tool version
            
        Examples:
            # Generate new Ed25519 key
            swiftkeygen generate -t ed25519 -f ~/.ssh/id_ed25519
            
            # Convert OpenSSH to RFC4716
            swiftkeygen convert -f openssh -t rfc4716 ~/.ssh/id_ed25519.pub
            
            # Export key to stdout
            swiftkeygen export - < key.pub
            
        For more help on a specific command:
            swiftkeygen <command> --help
        """)
    }

    static func printVersion() {
        print("swiftkeygen version \(version)")
    }
    
    static func handleConvert(_ args: [String]) {
        var fromFormat: String?
        var toFormat: String?
        var inputFile: String?
        var outputFile: String?
        
        var i = 0
        while i < args.count {
            switch args[i] {
            case "-f", "--from":
                i += 1
                if i < args.count {
                    fromFormat = args[i]
                }
            case "-t", "--to":
                i += 1
                if i < args.count {
                    toFormat = args[i]
                }
            case "-o", "--output":
                i += 1
                if i < args.count {
                    outputFile = args[i]
                }
            case "--help", "-h":
                printConvertHelp()
                exit(0)
            default:
                if !args[i].starts(with: "-") && inputFile == nil {
                    inputFile = args[i]
                }
            }
            i += 1
        }
        
        guard let from = fromFormat, let to = toFormat else {
            print("Error: Both --from and --to formats are required")
            printConvertHelp()
            exit(1)
        }
        
        let input = inputFile ?? "-"
        let output = outputFile ?? "-"
        
        do {
            let keyData: Data
            if input == "-" {
                keyData = FileHandle.standardInput.readDataToEndOfFile()
            } else {
                keyData = try Data(contentsOf: URL(fileURLWithPath: input))
            }
            
            let options = KeyConversionManager.ConversionOptions(
                toFormat: parseFormat(to),
                fromFormat: parseFormat(from),
                input: input,
                output: output
            )
            
            // If reading from stdin, write to a temporary file first
            if input == "-" {
                let tempFile = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
                try keyData.write(to: tempFile)
                
                var modifiedOptions = options
                modifiedOptions.input = tempFile.path
                
                try KeyConversionManager.convertKey(options: modifiedOptions)
                
                try? FileManager.default.removeItem(at: tempFile)
            } else {
                // Use the file directly
                try KeyConversionManager.convertKey(options: options)
            }
        } catch let error as SSHKeyError {
            print("Error: \(error.localizedDescription)")
            exit(1)
        } catch {
            print("Error: \(error.localizedDescription)")
            exit(1)
        }
    }
    
    static func handleExport(_ args: [String]) {
        guard let inputFile = args.first else {
            print("Error: Input file required")
            printExportHelp()
            exit(1)
        }
        
        do {
            let keyData: Data
            if inputFile == "-" {
                keyData = FileHandle.standardInput.readDataToEndOfFile()
            } else {
                keyData = try Data(contentsOf: URL(fileURLWithPath: inputFile))
            }
            
            FileHandle.standardOutput.write(keyData)
        } catch let error as SSHKeyError {
            print("Error: \(error.localizedDescription)")
            exit(1)
        } catch {
            print("Error: \(error.localizedDescription)")
            exit(1)
        }
    }
    
    static func handleGenerate(_ args: [String]) {
        var keyType = "rsa"
        var keySize = 3072  // Default to 3072 for RSA to match OpenSSH
        var outputFile: String?
        var passphrase: String?
        var comment: String?
        var cipher: String?
        
        var i = 0
        while i < args.count {
            switch args[i] {
            case "-t", "--type":
                i += 1
                if i < args.count {
                    keyType = args[i]
                }
            case "-b", "--bits":
                i += 1
                if i < args.count, let size = Int(args[i]) {
                    keySize = size
                }
            case "-f", "--file":
                i += 1
                if i < args.count {
                    outputFile = args[i]
                }
            case "-N", "--passphrase":
                i += 1
                if i < args.count {
                    passphrase = args[i]
                }
            case "-C", "--comment":
                i += 1
                if i < args.count {
                    comment = args[i]
                }
            case "-Z", "--cipher":
                i += 1
                if i < args.count {
                    cipher = args[i]
                }
            case "--help", "-h":
                printGenerateHelp()
                exit(0)
            default:
                break
            }
            i += 1
        }
        
        guard let output = outputFile else {
            print("Error: Output file required (-f)")
            printGenerateHelp()
            exit(1)
        }
        
        do {
            let key: any SSHKey
            
            switch keyType.lowercased() {
            case "rsa":
                key = try RSAKeyGenerator.generate(bits: keySize, comment: comment)
            case "ed25519":
                key = try Ed25519KeyGenerator.generate(comment: comment)
            case "ecdsa":
                key = try ECDSAKeyGenerator.generateP256(comment: comment)
            default:
                print("Error: Unsupported key type: \(keyType)")
                exit(1)
            }
            
            // Write private key with passphrase
            let privateKeyData = try OpenSSHPrivateKey.serialize(
                key: key,
                passphrase: passphrase,
                comment: key.comment,
                cipher: cipher
            )
            
            try privateKeyData.write(to: URL(fileURLWithPath: output))
            
            // Set proper permissions for private key
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: output)
            
            // Write public key
            let publicKeyPath = output + ".pub"
            let publicKeyString = key.publicKeyString()
            try publicKeyString.write(toFile: publicKeyPath, atomically: true, encoding: .utf8)
            
            // Set proper permissions for public key
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: publicKeyPath)
            
            print("Your identification has been saved in \(output)")
            print("Your public key has been saved in \(output).pub")
            
            let fingerprint = key.fingerprint(hash: .sha256, format: .base64)
            let randomArt = RandomArt.generate(for: key)
            
            print("The key fingerprint is:")
            print(fingerprint)
            print("The key's randomart image is:")
            print(randomArt)
        } catch let error as SSHKeyError {
            print("Error: \(error.localizedDescription)")
            exit(1)
        } catch {
            print("Error: \(error.localizedDescription)")
            exit(1)
        }
    }
    
    static func parseFormat(_ format: String) -> KeyFormat {
        switch format.lowercased() {
        case "openssh":
            return .openssh
        case "rfc4716":
            return .rfc4716
        case "pem":
            return .pem
        case "pkcs8":
            return .pkcs8
        default:
            print("Error: Unknown format: \(format)")
            exit(1)
        }
    }
    
    static func printConvertHelp() {
        print("""
        Convert key between formats
        
        Usage:
            swiftkeygen convert -f <from-format> -t <to-format> [input] [-o output]
        
        Options:
            -f, --from <format>     Source format (openssh, rfc4716, pem, pkcs8)
            -t, --to <format>       Target format (openssh, rfc4716)
            -o, --output <file>     Output file (default: stdout)
            
        If input is not specified or is "-", reads from stdin.
        If output is not specified or is "-", writes to stdout.
        
        Examples:
            # Convert OpenSSH to RFC4716
            swiftkeygen convert -f openssh -t rfc4716 ~/.ssh/id_ed25519.pub
            
            # Convert from stdin to stdout
            cat key.pub | swiftkeygen convert -f openssh -t rfc4716 -
        """)
    }
    
    static func printExportHelp() {
        print("""
        Export key to stdout
        
        Usage:
            swiftkeygen export <input>
        
        If input is "-", reads from stdin.
        
        Example:
            swiftkeygen export ~/.ssh/id_ed25519.pub
        """)
    }
    
    static func printGenerateHelp() {
        print("""
        Generate new SSH key pair
        
        Usage:
            swiftkeygen generate -t <type> -f <file> [options]
        
        Options:
            -t, --type <type>       Key type (rsa, ed25519, ecdsa)
            -b, --bits <size>       Key size in bits (RSA: 1024-16384, default: 3072)
            -f, --file <path>       Output file path
            -N, --passphrase <pass> Passphrase for key encryption
            -C, --comment <text>    Key comment
            -Z, --cipher <cipher>   Cipher for private key encryption
            
        Examples:
            # Generate RSA key
            swiftkeygen generate -t rsa -b 4096 -f ~/.ssh/id_rsa
            
            # Generate Ed25519 key with passphrase
            swiftkeygen generate -t ed25519 -f ~/.ssh/id_ed25519 -N "mypassphrase"
            
            # Generate key with specific cipher
            swiftkeygen generate -t ed25519 -f ~/.ssh/id_ed25519 -N pass -Z aes128-ctr
        
        Supported ciphers:
            aes128-ctr, aes192-ctr, aes256-ctr (default)
            aes128-cbc, aes192-cbc, aes256-cbc
            aes128-gcm@openssh.com, aes256-gcm@openssh.com
            3des-cbc
            chacha20-poly1305@openssh.com
        """)
    }
}

SwiftKeyGenCLI.main()