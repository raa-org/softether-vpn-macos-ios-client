//
//  VPNConfiguration.swift
//  SimpleTunnel

import Foundation

enum VPNConfiguration {
    
    static let systemExtensionBundleID: String = {
            guard let value = Bundle.main.object(forInfoDictionaryKey: "BUNDLE_ID_EXT") as? String,
                  !value.isEmpty else {
                preconditionFailure("Missing or empty BUNDLE_ID_EXT in Info.plist.")
            }
            return value
        }()
    
    static let systemExtensionBundleIDWithSuffix = systemExtensionBundleID + ".systemextension"
    
    static let defaultDisplayName = "SoftEther VPN"

    static func displayName(for profileName: String?) -> String {
        guard let profileName, !profileName.isEmpty else {
            return defaultDisplayName
        }
        
        return "\(defaultDisplayName) for \(profileName)"
    }

    static func makeProviderConfigurationDictionary(profile: VPNProfile) -> [String: Any] {
        return [
            "profile_name": profile.name,
            
            "se_host": profile.seHost,
            "se_port": profile.sePort,
            "se_hub": profile.seHub,
            
            "oidc": [
                "issuer_url": profile.oidcConfig.issuerUrl,
                "client_id": profile.oidcConfig.clientId,
                "redirect_uri": profile.oidcConfig.redirectUri,
                "scopes": profile.oidcConfig.scopes
            ]
        ]
    }
}
