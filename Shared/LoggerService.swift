import Foundation
import OSLog

/// Centralized logging service that writes both to Unified Logging (os.Logger)
/// and to a rotating file in the App Group (or app container if no App Group provided).
public enum LoggerService {
    // Singleton
    private static let shared = Storage()

    // MARK: - Public configuration

    /// Configure the logger with an optional App Group ID.
    /// If provided and available, logs will be written to the shared App Group container.
    /// Otherwise, logs will be written to the app's Application Support directory.
    public static func configure(appGroupID: String? = nil, subsystem: String, fileName: String, maxFileBytes: Int = 5_000_000, maxRotations: Int = 2) {
        shared.configure(appGroupID: appGroupID, subsystem: subsystem, fileName: fileName, maxFileBytes: maxFileBytes, maxRotations: maxRotations)
    }

    public static func configureHostApp(appGroupID: String) {
        configure(appGroupID: appGroupID, subsystem: requiredPlistString("LOG_SUBSYSTEM_APP"), fileName: "app.log")
    }

    public static func configureSystemExtension(appGroupID: String) {
        configure(appGroupID: appGroupID, subsystem: requiredPlistString("LOG_SUBSYSTEM_EXT"), fileName: "extension.log")
    }

    /// Returns the current log file URL if configured.
    static func currentLogFileURL() -> URL? {
        return shared.currentLogFileURL
    }

    /// Returns the rotated log file URLs according to the internal rotation scheme.
    /// For a current file like `app.log`, this will return existing files such as
    /// `app.log.1`, `app.log.2`, ... up to the provided `maxRotations` or the
    /// configured maximum, whichever is smaller.
    static func fileRotationURLs(maxRotations: Int) -> [URL] {
        guard let current = shared.currentLogFileURL else { return [] }
        let fm = FileManager.default
        let basePath = current.path

        // Use the lesser of requested maxRotations and configured max.
        let limit = max(0, min(maxRotations, shared.maxRotations))
        guard limit > 0 else { return [] }

        var urls: [URL] = []
        for i in 1...limit {
            let rotatedPath = basePath + ".\(i)"
            if fm.fileExists(atPath: rotatedPath) {
                urls.append(URL(fileURLWithPath: rotatedPath))
            }
        }
        return urls
    }

    /// Factory for os.Logger with category, so you can still use native Logger APIs.
    static func categoryLogger(_ category: String) -> Logger {
        return Logger(subsystem: shared.subsystem, category: category)
    }

    /// Convenience categorized loggers
    public static var vpnapp: Logger { categoryLogger("vpnapp") }
    public static var vpnext: Logger { categoryLogger("vpnext") }
    public static var oidc: Logger { categoryLogger("oidc") }
    public static var dhcp: Logger { categoryLogger("dhcp") }
    public static var arp: Logger { categoryLogger("arp") }

    /// Write a line to the file log (in addition to using os.Logger in your code).
    /// Use this when you want to guarantee the text is in the exportable file.
    public static func file(_ level: OSLogType = .default, _ message: String) {
        shared.writeToFile(level: level, message: message)
    }
    
    // MARK: - Private
    
    private static func requiredPlistString(_ key: String) -> String {
        guard let value = Bundle.main.object(forInfoDictionaryKey: key) as? String, !value.isEmpty else {
            preconditionFailure("Missing or empty \(key) in Info.plist.")
        }
        return value
    }

    // MARK: - Internal storage

    private final class Storage {
        
        static var defaultSubsystem: String {
            return Bundle.main.bundleIdentifier ?? "com.example.app"
        }
        
        // Configuration
        var subsystem: String = defaultSubsystem
        var maxFileBytes: Int = 5_000_000
        var maxRotations: Int = 2


        // File destinations
        private(set) var currentLogFileURL: URL?
        private var fileHandle: FileHandle?

        // Queue for file I/O
        private let queue = DispatchQueue(label: "LoggerService.FileQueue", qos: .utility)

        // Date formatter for file lines
        private lazy var dateFormatter: DateFormatter = {
            let df = DateFormatter()
            df.locale = Locale(identifier: "en_US_POSIX")
            df.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
            return df
        }()

        // MARK: API

        func configure(appGroupID: String?, subsystem: String, fileName: String, maxFileBytes: Int, maxRotations: Int) {
            self.subsystem = subsystem
            self.maxFileBytes = maxFileBytes
            self.maxRotations = max(0, maxRotations)

            let baseDir = resolveBaseDirectory(appGroupID: appGroupID)
            let logsDir = baseDir.appendingPathComponent("Library/Logs/SoftEtherVPN", isDirectory: true)

            try? FileManager.default.createDirectory(at: logsDir, withIntermediateDirectories: true, attributes: nil)

            let fileURL = logsDir.appendingPathComponent(fileName)
            self.currentLogFileURL = fileURL

            queue.sync {
                self.fileHandle?.closeFile()
                self.fileHandle = nil

                if !FileManager.default.fileExists(atPath: fileURL.path) {
                    FileManager.default.createFile(atPath: fileURL.path, contents: nil)
                }

                do {
                    let handle = try FileHandle(forWritingTo: fileURL)
                    try handle.seekToEnd()
                    self.fileHandle = handle
                } catch {
                    // If we can't open, leave fileHandle nil; file logging will be disabled silently.
                    self.fileHandle = nil
                }
            }

            // Write a header
            writeToFile(level: .info, message: "Logger configured. Subsystem=\(subsystem), file=\(fileURL.path)")
        }

        func writeToFile(level: OSLogType, message: String) {
            guard let fileURL = currentLogFileURL else {
                return
            }

            queue.async {
                self.rotateIfNeeded(fileURL: fileURL)

                guard let handle = self.fileHandle else {
                    return
                }
                
                let ts = self.dateFormatter.string(from: Date())
                let levelStr: String
                switch level {
                case .debug: levelStr = "DEBUG"
                case .info: levelStr = "INFO"
                case .error: levelStr = "ERROR"
                case .fault: levelStr = "FAULT"
                case .default: levelStr = "LOG"
                default: levelStr = "LOG"
                }

                let line = "[\(ts)] [\(levelStr)] \(message)\n"
                if let data = line.data(using: .utf8) {
                    do {
                        try handle.seekToEnd()
                        try handle.write(contentsOf: data)
                    } catch {
                        // If writing fails, try reopening once
                        do {
                            let newHandle = try FileHandle(forWritingTo: fileURL)
                            try newHandle.seekToEnd()
                            try newHandle.write(contentsOf: data)
                            self.fileHandle = newHandle
                        } catch {
                            // give up silently
                        }
                    }
                }
            }
        }

        // MARK: Helpers

        private func resolveBaseDirectory(appGroupID: String?) -> URL {
            if let groupID = appGroupID,
               let groupURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: groupID) {
                return groupURL
            }

            do {
                return try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
            } catch {
                return URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            }
        }

        private func rotateIfNeeded(fileURL: URL) {
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: fileURL.path),
                  let size = attrs[.size] as? NSNumber else {
                return
            }

            guard size.intValue >= maxFileBytes else { return }

            // Close current handle before rotation
            fileHandle?.closeFile()
            fileHandle = nil

            // Perform rotation: app.log.(maxRotations) ... app.log.1
            let path = fileURL.path
            let fm = FileManager.default

            if maxRotations > 0 {
                for i in stride(from: maxRotations, through: 1, by: -1) {
                    let older = path + ".\(i)"
                    let newer = (i == 1) ? path : path + ".\(i - 1)"
                    if fm.fileExists(atPath: newer) {
                        // remove oldest if exists
                        if i == maxRotations, fm.fileExists(atPath: older) {
                            try? fm.removeItem(atPath: older)
                        }
                        try? fm.moveItem(atPath: newer, toPath: older)
                    }
                }
                // Move current to .1
                try? fm.moveItem(atPath: path, toPath: path + ".1")
            } else {
                // No rotations, just truncate
                try? fm.removeItem(atPath: path)
            }

            // Create fresh file and reopen
            fm.createFile(atPath: path, contents: nil)
            do {
                let handle = try FileHandle(forWritingTo: fileURL)
                try handle.seekToEnd()
                fileHandle = handle
            } catch {
                fileHandle = nil
            }
        }
    }
}

extension Logger {
    
    @inline(__always)
    public func debugIfDebugBuild(_ message: String) {
#if DEBUG
        self.debug("\(message, privacy: .public)")
#endif
    }
    
    public func both(_ level: OSLogType = .default, _ message: String) {
        
        if level == .debug {
#if DEBUG
            self.debug("\(message, privacy: .public)")
            LoggerService.file(level, message)
#endif
            return
        }
        
        switch level {
            
        case .info:  self.info("\(message, privacy: .public)")
            
        case .error: self.error("\(message, privacy: .public)")
            
        case .fault: self.fault("\(message, privacy: .public)")
            
        default:     self.log("\(message, privacy: .public)")
            
        }
        
        LoggerService.file(level, message)
        
    }

    /// Splits large dumps into multiple log entries sized by UTF-8 bytes to avoid Unified Logging truncation.
    public func bothDump(_ level: OSLogType = .default, _ message: String, maxUTF8BytesPerEntry: Int = 700, tag: String? = nil)
    {
        if level == .debug {
#if DEBUG
            self.debug("\(message, privacy: .public)")
            LoggerService.file(level, message)
#endif
            return
        }
        
        let token: String = tag ?? String(UUID().uuidString.prefix(8))

        let normalized = message
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")

        // Stream-like: do not build a huge array unless you need [i/n].
        var index = 0

        for lineSub in normalized.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(lineSub)

            let chunks = line._chunkedByUTF8Bytes(maxBytes: maxUTF8BytesPerEntry)
            if chunks.isEmpty {
                index += 1
                self.both(level, "[\(token)] [\(index)]")
                continue
            }

            for chunk in chunks {
                index += 1
                self.both(level, "[\(token)] [\(index)] \(chunk)")
            }
        }

        // If message was empty, still emit one entry.
        if normalized.isEmpty {
            self.both(level, "[\(token)] [1]")
        }
    }
}

private extension String {

    func _chunkedByUTF8Bytes(maxBytes: Int) -> [String] {
        guard maxBytes > 0 else { return [self] }
        guard !self.isEmpty else { return [] }

        var result: [String] = []
        result.reserveCapacity((self.utf8.count / maxBytes) + 1)

        var current = ""
        current.reserveCapacity(min(self.count, maxBytes))

        var currentBytes = 0

        for ch in self {
            let s = String(ch)
            let b = s.utf8.count

            if currentBytes + b > maxBytes, !current.isEmpty {
                result.append(current)
                current = ""
                currentBytes = 0
            }

            current.append(contentsOf: s)
            currentBytes += b
        }

        if !current.isEmpty {
            result.append(current)
        }

        return result
    }
}

