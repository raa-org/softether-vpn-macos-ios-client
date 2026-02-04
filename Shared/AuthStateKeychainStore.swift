import Foundation
import Security
import CryptoKit
import AppAuthCore

enum AuthStateKeychainError: Error {
    case archiveFailed
    case unarchiveFailed
    case keychainError(OSStatus)
}

struct AuthStateKeychainStore {
    private static let accessGroup: String = {
        guard let value = Bundle.main.object(forInfoDictionaryKey: "KEYCHAIN_ACCESS_GROUP") as? String, !value.isEmpty else {
            preconditionFailure("Missing or empty KEYCHAIN_ACCESS_GROUP in Info.plist. Provide a valid access group string.")
        }
        return value
    }()
    
    private static let oidcAccountPrefix = "SoftEtherVPNOidc"
    private static let service = "SoftEtherVPN"

    private static let legacyAccount = "SoftEtherVPNOidc"
    
    // MARK: - Key (profile + issuer + clientId)

    static func stateKey(profileName: String, issuerUrl: String, clientId: String) -> String {
        let material = "\(profileName)|\(issuerUrl)|\(clientId)"
        let digest = SHA256.hash(data: Data(material.utf8))
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        
        return "\(oidcAccountPrefix).\(hex.prefix(32))"
    }

    // MARK: - Public API
    
    static func save(_ state: OIDAuthState, key: String) throws {
        let data: Data
        do {
            data = try NSKeyedArchiver.archivedData(withRootObject: state, requiringSecureCoding: true)
        } catch {
            throw AuthStateKeychainError.archiveFailed
        }

        let query = baseQuery(account: key)
        let updateAttrs: [String: Any] = [kSecValueData as String: data]

        let status = SecItemUpdate(query as CFDictionary, updateAttrs as CFDictionary)
            switch status {
            case errSecSuccess:
                return

            case errSecItemNotFound:
                var addQuery = query
                addQuery[kSecValueData as String] = data
                addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
                
                let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
                
                guard addStatus == errSecSuccess else {
                    throw AuthStateKeychainError.keychainError(addStatus)
                }
                return

            default:
                throw AuthStateKeychainError.keychainError(status)
            }
    }

    static func load(key: String) throws -> OIDAuthState? {
        var query = baseQuery(account: key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw AuthStateKeychainError.keychainError(status)
        }
        guard let data = item as? Data else {
            throw AuthStateKeychainError.unarchiveFailed
        }

        do {
            if let state = try NSKeyedUnarchiver.unarchivedObject(ofClass: OIDAuthState.self, from: data) {
                return state
            }
            throw AuthStateKeychainError.unarchiveFailed
        } catch {
            throw AuthStateKeychainError.unarchiveFailed
        }
    }

    static func clear(key: String) {
        let query = baseQuery(account: key)
        SecItemDelete(query as CFDictionary)
    }
    
    static func clearAllAuthStates() throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        if !accessGroup.isEmpty {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecItemNotFound {
            return
        }
        guard status == errSecSuccess else {
            throw AuthStateKeychainError.keychainError(status)
        }

        guard let items = result as? [[String: Any]] else {
            return
        }

        for item in items {
            guard let account = item[kSecAttrAccount as String] as? String else {
                continue
            }

            if account == legacyAccount || account.hasPrefix("\(oidcAccountPrefix).") {
                var delQuery: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String: service,
                    kSecAttrAccount as String: account
                ]
                if !accessGroup.isEmpty {
                    delQuery[kSecAttrAccessGroup as String] = accessGroup
                }
                SecItemDelete(delQuery as CFDictionary)
            }
        }
    }

    static func clearLegacyIfPresent() {
        let query = baseQuery(account: legacyAccount)
        SecItemDelete(query as CFDictionary)
    }
    
    // MARK: - Internals

    private static func baseQuery(account: String) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]

        if !accessGroup.isEmpty {
            q[kSecAttrAccessGroup as String] = accessGroup
        }

        return q
    }
}
