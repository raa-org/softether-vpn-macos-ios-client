//
//  SoftEtherAuthMethod.swift
//  SimpleTunnel

import Foundation

public enum SoftEtherAuthMethod {
    case usernamePassword(UsernamePasswordCredentials)
    case usernameJWT(JWTCredentials)
}

public struct UsernamePasswordCredentials {
    public let username: String
    public let password: String
}

public struct JWTCredentials {
    public let username: String
    public let jwt: String
}

public extension SoftEtherAuthMethod {
    
    init?(options: [String: NSObject]) {
        
        if let jwt = options["id_token"] as? String {
            self.init(jwt: jwt)
            return
        }
        
        if let username = options["username"] as? String,
           let password = options["password"] as? String {
            
            let credentials = UsernamePasswordCredentials(username: username, password: password)
            self = .usernamePassword(credentials)
            return
        }
        
        return nil
    }
    
    init?(jwt: String) {
        
        if let usernameFromJWT = Self.extractUsername(fromJWT: jwt) {
            let credentials = JWTCredentials(username: usernameFromJWT, jwt: jwt)
            self = .usernameJWT(credentials)
            return
        }
        
        return nil
    }
    
    // MARK: - JWT helpers
    
    private static func extractUsername(fromJWT jwt: String) -> String? {
        guard let payload = decodeJWTPayload(jwt) else {
            return nil
        }
        
        if let email = payload["email"] as? String, !email.isEmpty {
            return email
        }
        
        if let preferred = payload["preferred_username"] as? String, !preferred.isEmpty {
            return preferred
        }
        
        return nil
    }
    
    private static func decodeJWTPayload(_ jwt: String) -> [String: Any]? {
        let parts = jwt.split(separator: ".")
        guard parts.count >= 2 else { return nil }
        
        let payloadPart = String(parts[1])
        
        guard let payloadData = base64UrlDecode(payloadPart) else {
            return nil
        }
        
        do {
            let json = try JSONSerialization.jsonObject(with: payloadData, options: [])
            return json as? [String: Any]
        } catch {
            return nil
        }
    }
    
    private static func base64UrlDecode(_ string: String) -> Data? {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        
        let remainder = base64.count % 4
        if remainder > 0 {
            base64.append(String(repeating: "=", count: 4 - remainder))
        }
        
        return Data(base64Encoded: base64)
    }
}
