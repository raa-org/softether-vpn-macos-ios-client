//
//  VPNProfile.swift
//  SimpleTunnel
//

import Foundation

struct ProfilesFile: Codable {
    let profiles: [VPNProfile]
}

struct VPNProfile: Codable, Hashable, Identifiable {
    var id: String { name }
    
    let name: String
    let seHost: String
    let sePort: Int
    let seHub: String
    let oidcConfig: OIDCConfig

    enum CodingKeys: String, CodingKey {
        case name = "profile_name"
        case seHost = "se_host"
        case sePort = "se_port"
        case seHub = "se_hub"
        case oidcConfig = "oidc"
    }
}

struct OIDCConfig: Codable, Hashable {
    let issuerUrl: String
    let clientId: String
    let redirectUri: String
    let scopes: [String]
    
    enum CodingKeys: String, CodingKey {
        case issuerUrl = "issuer_url"
        case clientId = "client_id"
        case redirectUri = "redirect_uri"
        case scopes = "scopes"
    }
}

