import Foundation
import Testing

/// Shared helpers for CLI and cross-tool integration tests.
///
/// - Location: Kept next to `Tags.swift` for easy discovery and reuse.
/// - Goals: Minimize boilerplate in tests that invoke external tools (our
///   `swiftkeygen` or the system `ssh-keygen`), manage temporary files, and
///   compare outputs for behavioral parity.
enum IntegrationTestSupporter {
    // MARK: - Temporary Directories
    /// Create a temporary directory, pass it to `body`, and clean it up.
    /// The directory is removed after `body` returns, even if it throws.
    @discardableResult
    static func withTemporaryDirectory(prefix: String = "swiftkeygen-tests",
                                       _ body: (URL) throws -> Void) throws -> URL {
        let base = FileManager.default.temporaryDirectory
        let dir = base.appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try body(dir)
        return dir
    }

    /// Write UTF-8 text to a file and set POSIX permissions (default `0600`).
    static func write(_ text: String, to url: URL, permissions: Int = 0o600) throws {
        try text.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: permissions], ofItemAtPath: url.path)
    }

    /// Write raw `Data` to a file and set POSIX permissions (default `0600`).
    static func write(_ data: Data, to url: URL, permissions: Int = 0o600) throws {
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: permissions], ofItemAtPath: url.path)
    }

    /// Change POSIX permissions of a file or directory.
    static func chmod(_ url: URL, permissions: Int) throws {
        try FileManager.default.setAttributes([.posixPermissions: permissions], ofItemAtPath: url.path)
    }

    // MARK: - Process Execution
    struct CommandResult {
        let status: Int32
        let stdout: String
        let stderr: String

        var succeeded: Bool { status == 0 }
        var failed: Bool { status != 0 }
    }

    /// Run an external command and capture stdout/stderr.
    /// - Parameters:
    ///   - executable: Absolute path of the binary to run.
    ///   - arguments: Process arguments.
    ///   - input: Optional stdin data.
    ///   - environment: Extra environment variables (merged with current env).
    ///   - workingDirectory: Optional working directory.
    ///   - timeout: Optional timeout in seconds; if exceeded, the process is terminated.
    /// - Returns: `CommandResult` with exit status and captured output.
    static func run(_ executable: URL,
                    arguments: [String],
                    input: Data? = nil,
                    environment: [String: String] = [:],
                    workingDirectory: URL? = nil,
                    timeout: TimeInterval? = nil) throws -> CommandResult {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments

        var env = ProcessInfo.processInfo.environment
        environment.forEach { env[$0.key] = $0.value }
        process.environment = env

        if let workingDirectory {
            process.currentDirectoryURL = workingDirectory
        }

        let out = Pipe()
        let err = Pipe()
        process.standardOutput = out
        process.standardError = err

        if let input {
            let stdin = Pipe()
            process.standardInput = stdin
            // Write input after launch
            try process.run()
            stdin.fileHandleForWriting.write(input)
            stdin.fileHandleForWriting.closeFile()
        } else {
            try process.run()
        }

        if let timeout, timeout > 0 {
            // Basic timeout: poll until exit or deadline, then terminate.
            let deadline = Date().addingTimeInterval(timeout)
            while process.isRunning && Date() < deadline {
                Thread.sleep(forTimeInterval: 0.01)
            }
            if process.isRunning {
                process.terminate()
            }
        }

        process.waitUntilExit()

        let outData = out.fileHandleForReading.readDataToEndOfFile()
        let errData = err.fileHandleForReading.readDataToEndOfFile()
        let stdout = String(data: outData, encoding: .utf8) ?? ""
        let stderr = String(data: errData, encoding: .utf8) ?? ""
        return CommandResult(status: process.terminationStatus, stdout: stdout, stderr: stderr)
    }

    // MARK: - ssh-keygen Helpers
    /// Absolute path to the system `ssh-keygen`.
    static var sshKeygenURL: URL? {
        let path = "/usr/bin/ssh-keygen"
        return FileManager.default.isExecutableFile(atPath: path) ? URL(fileURLWithPath: path) : nil
    }

    /// Run the system `ssh-keygen` with provided arguments.
    static func runSSHKeygen(_ arguments: [String],
                             input: Data? = nil,
                             workingDirectory: URL? = nil,
                             timeout: TimeInterval? = nil) throws -> CommandResult {
        let url = try #require(Self.sshKeygenURL, "ssh-keygen not found at /usr/bin/ssh-keygen")
        return try run(url, arguments: arguments, input: input, environment: [:], workingDirectory: workingDirectory, timeout: timeout)
    }

    // MARK: - swiftkeygen Helpers
    /// Resolve the built `swiftkeygen` executable.
    ///
    /// Strategy:
    /// 1. `SWIFTKEYGEN_BIN` environment variable (if set)
    /// 2. `.build/debug/swiftkeygen` under the package root
    /// 3. `.build/release/swiftkeygen` under the package root
    /// 4. First match of `.build/*/swiftkeygen`
    static func resolveSwiftKeygenURL() -> URL? {
        let env = ProcessInfo.processInfo.environment
        if let override = env["SWIFTKEYGEN_BIN"], FileManager.default.isExecutableFile(atPath: override) {
            return URL(fileURLWithPath: override)
        }

        guard let root = findPackageRoot(startingAt: URL(fileURLWithPath: #filePath)) else { return nil }
        let fm = FileManager.default

        let candidates = [
            root.appendingPathComponent(".build/debug/swiftkeygen"),
            root.appendingPathComponent(".build/release/swiftkeygen")
        ]
        for url in candidates where fm.isExecutableFile(atPath: url.path) { return url }

        // Fallback: scan .build/*/swiftkeygen
        let buildDir = root.appendingPathComponent(".build")
        if let enumerator = fm.enumerator(at: buildDir, includingPropertiesForKeys: [.isExecutableKey], options: [.skipsHiddenFiles]) {
            for case let fileURL as URL in enumerator {
                if fileURL.lastPathComponent == "swiftkeygen", fm.isExecutableFile(atPath: fileURL.path) {
                    return fileURL
                }
            }
        }
        return nil
    }

    /// Run the built `swiftkeygen` with provided arguments. If the binary
    /// cannot be located, the test is short-circuited via `#require`.
    static func runSwiftKeygen(_ arguments: [String],
                               input: Data? = nil,
                               workingDirectory: URL? = nil,
                               timeout: TimeInterval? = nil) throws -> CommandResult {
        let url = try #require(resolveSwiftKeygenURL(), "swiftkeygen binary not found. Build it first with `swift build --product swiftkeygen`. You can also set SWIFTKEYGEN_BIN to an absolute path.")
        // Ensure stable, non-interactive behavior for passphrase prompts.
        let env: [String: String] = [
            "SSH_ASKPASS": "/usr/bin/false",
            "DISPLAY": "",
        ]
        return try run(url, arguments: arguments, input: input, environment: env, workingDirectory: workingDirectory, timeout: timeout)
    }

    // MARK: - Utilities
    /// Normalize an OpenSSH public key line to the canonical `[type] [base64]` form (drop trailing comment).
    static func normalizeOpenSSHPublicKey(_ line: String) -> String {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = trimmed.split(separator: " ")
        guard parts.count >= 2 else { return trimmed }
        return parts.prefix(2).joined(separator: " ")
    }

    /// Walk up from a file location to find the package root containing `Package.swift`.
    private static func findPackageRoot(startingAt fileURL: URL) -> URL? {
        var dir = fileURL.deletingLastPathComponent()
        let fm = FileManager.default
        while dir.pathComponents.count > 1 {
            let manifest = dir.appendingPathComponent("Package.swift")
            if fm.fileExists(atPath: manifest.path) { return dir }
            dir.deleteLastPathComponent()
        }
        return nil
    }
}
