//
//  ProfileConfigLoader.swift
//  SimpleTunnel
//
import Foundation

enum ProfileConfigError: LocalizedError {
    case missingFile
    case emptyProfiles
    case emptyProfileName
    case duplicateProfileNames([String])

    var errorDescription: String? {
        switch self {
        case .missingFile:
            return "profiles.json not found in Application Support."
        case .emptyProfiles:
            return "profiles.json contains no profiles."
        case .emptyProfileName:
            return "profiles.json contains empty profile_name."
        case .duplicateProfileNames(let names):
            return "profiles.json contains duplicate profile_name values: \(names.joined(separator: ", "))."
        }
    }
}

enum ProfileConfigLoader {

    // MARK: - Paths

    private static func profilesDirectoryURL() throws -> URL {
        let fileManager = FileManager.default
        let appSupportUrl = try fileManager.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)

        let directory = appSupportUrl
            .appendingPathComponent("SoftEtherVPN", isDirectory: true)
            .appendingPathComponent("config", isDirectory: true)

        if !fileManager.fileExists(atPath: directory.path) {
            try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        }

        return directory
    }
    
    static func profilesFileURL() throws -> URL {
        try profilesDirectoryURL().appendingPathComponent("profiles.json", isDirectory: false)
    }

    // MARK: - Public API
    
    static func loadProfiles() throws -> [VPNProfile] {
        do {
            return try loadFromApplicationSupport()
        } catch ProfileConfigError.missingFile {
            throw ProfileConfigError.missingFile
        }
    }

    static func loadFromApplicationSupport() throws -> [VPNProfile] {
        let url = try profilesFileURL()
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw ProfileConfigError.missingFile
        }

        return try load(from: url)
    }
    
    // MARK: - Common loader + validation
    
    private static func load(from url: URL) throws -> [VPNProfile] {
        let data = try Data(contentsOf: url)
        let decoded = try JSONDecoder().decode(ProfilesFile.self, from: data)

        let profiles = decoded.profiles
        guard !profiles.isEmpty else {
            throw ProfileConfigError.emptyProfiles
        }

        let trimmedNames = profiles.map { $0.name.trimmingCharacters(in: .whitespacesAndNewlines) }
        guard !trimmedNames.contains(where: { $0.isEmpty }) else {
            throw ProfileConfigError.emptyProfileName
        }

        var counts: [String: Int] = [:]
        for n in trimmedNames {
            counts[n, default: 0] += 1
        }
        let duplicates = counts.filter { $0.value > 1 }.map { $0.key }.sorted()
        guard duplicates.isEmpty else {
            throw ProfileConfigError.duplicateProfileNames(duplicates)
        }

        return profiles
    }
}
