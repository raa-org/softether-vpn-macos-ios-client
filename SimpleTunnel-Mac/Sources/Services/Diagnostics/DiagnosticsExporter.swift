import Foundation
import AppKit
import OSLog

protocol DiagnosticsExporter {
    func exportDiagnostics(to destinationURL: URL) throws
}

final class DiagnosticsExporterImpl: DiagnosticsExporter {
    
    let extLogSubsystem: String = {
        guard let value = Bundle.main.object(forInfoDictionaryKey: "LOG_SUBSYSTEM_EXT") as? String, !value.isEmpty else {
            preconditionFailure("Missing or empty LOG_SUBSYSTEM_EXT in Info.plist. Provide a valid name for log subsystem ext.")
        }
        return value
    }()

    func exportDiagnostics(to destinationURL: URL) throws {
        let fileManager = FileManager.default

        let tempDir = try fileManager.url(for: .itemReplacementDirectory, in: .userDomainMask, appropriateFor: destinationURL, create: true)

        let stagingDir = fileManager.temporaryDirectory .appendingPathComponent("SoftEtherVPN-Diag-\(UUID().uuidString)", isDirectory: true)
        try fileManager.createDirectory(at: stagingDir, withIntermediateDirectories: true, attributes: nil)

        let uuid = UUID().uuidString
        let tempZipURL = tempDir.appendingPathComponent("SoftEtherVPN-Diagnostics-\(uuid).zip")

        defer {
            try? fileManager.removeItem(at: stagingDir)
            try? fileManager.removeItem(at: tempZipURL)
            try? fileManager.removeItem(at: tempDir)
        }

        try stageAppLogs(into: stagingDir)

        let versionsFileURL = stagingDir.appendingPathComponent("versions.txt")
        try writeVersionsFile(to: versionsFileURL)

        let unifiedLogURL = stagingDir.appendingPathComponent("unified.log")
        collectUnifiedLogs(to: unifiedLogURL, subsystem: extLogSubsystem)

        try runProcess("/usr/bin/zip", ["-r", "-q", tempZipURL.path, "."], currentDirectory: stagingDir)
        try copyReplacingIfNeeded(from: tempZipURL, to: destinationURL)
    }

    // MARK: - Private helpers

    private func stageAppLogs(into stagingDir: URL) throws {
        let fileManager = FileManager.default

        if let currentLogURL = LoggerService.currentLogFileURL() {
            let destURL = stagingDir.appendingPathComponent(currentLogURL.lastPathComponent)
            try copyReplacingIfNeeded(from: currentLogURL, to: destURL)
        } else {
            let out = stagingDir.appendingPathComponent("app.log")
            try Data("app.log location is not configured\n".utf8).write(to: out, options: [.atomic])
        }

        let archives = LoggerService.fileRotationURLs(maxRotations: 2)
        for archiveURL in archives {
            let destURL = stagingDir.appendingPathComponent(archiveURL.lastPathComponent)
            if fileManager.fileExists(atPath: archiveURL.path) {
                try copyReplacingIfNeeded(from: archiveURL, to: destURL)
            }
        }
    }

    private func writeVersionsFile(to url: URL) throws {
        var versions = "Host Version:\n"
        versions += AppInfo.hostVersionText + "\n\n"
        versions += "App Extension Version:\n"
        versions += AppInfo.extensionVersionText + "\n"
        try versions.write(to: url, atomically: true, encoding: .utf8)
    }

    // MARK: - Unified logs

    private func collectUnifiedLogs(to outFile: URL, subsystem: String, lastMinutes: Int = 120) {
        let fm = FileManager.default
        fm.createFile(atPath: outFile.path, contents: nil, attributes: nil)

        func appendLine(_ text: String) {
            guard let data = (text + "\n").data(using: .utf8) else { return }
            guard let h = try? FileHandle(forWritingTo: outFile) else { return }
            defer { _ = try? h.close() }
            _ = try? h.seekToEnd()
            _ = try? h.write(contentsOf: data)
        }

        @discardableResult
        func runLogShow(args: [String], label: String) -> Int32 {
            appendLine("===== log show (\(label)) =====")
            appendLine("args: /usr/bin/log " + args.joined(separator: " "))
            appendLine("timestamp: \(ISO8601DateFormatter().string(from: Date()))")
            appendLine("----- output -----")

            guard let outHandle = try? FileHandle(forWritingTo: outFile) else {
                appendLine("ERROR: can't open unified.log for writing")
                return 1
            }
            defer {
                try? outHandle.close()
            }
            _ = try? outHandle.seekToEnd()

            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/log")
            p.arguments = args
            p.standardOutput = outHandle
            p.standardError = outHandle

            do {
                try p.run()
                p.waitUntilExit()
            } catch {
                appendLine("\nERROR: failed to run /usr/bin/log: \(error.localizedDescription)\n")
                return 1
            }

            appendLine("\n----- exit: \(p.terminationStatus) -----\n")
            return p.terminationStatus
        }

        let predicate = "(subsystem == \"\(subsystem)\")"
        let baseArgs = ["show", "--last", "\(lastMinutes)m", "--style", "syslog", "--info", "--debug"]

        var code = runLogShow(args: baseArgs + ["--predicate", predicate], label: "predicate=subsystem")
        if code == 0 {
            return
        }

        if code == 64 {
            code = runLogShow(args: ["show", "--last", "\(lastMinutes)m", "--style", "syslog", "--info", "--predicate", predicate], label: "predicate=subsystem (no --debug)")
            if code == 0 {
                return
            }
        }

        let fallbackMinutes = min(lastMinutes, 20)
        _ = runLogShow(args: ["show", "--last", "\(fallbackMinutes)m", "--style", "syslog", "--info", "--debug"], label: "NO predicate fallback (\(fallbackMinutes)m)")
    }

    // MARK: - Process + FS helpers

    private func runProcess(_ launchPath: String, _ args: [String], currentDirectory: URL? = nil) throws {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: launchPath)
        p.arguments = args
        if let currentDirectory { p.currentDirectoryURL = currentDirectory }

        try p.run()
        p.waitUntilExit()

        if p.terminationStatus != 0 {
            throw NSError(
                domain: "DiagnosticsExporterImpl",
                code: Int(p.terminationStatus),
                userInfo: [NSLocalizedDescriptionKey: "\(launchPath) exited with code \(p.terminationStatus)"]
            )
        }
    }

    private func copyReplacingIfNeeded(from src: URL, to dst: URL) throws {
        let fm = FileManager.default
        if fm.fileExists(atPath: dst.path) {
            try fm.removeItem(at: dst)
        }
        try fm.copyItem(at: src, to: dst)
    }
}

