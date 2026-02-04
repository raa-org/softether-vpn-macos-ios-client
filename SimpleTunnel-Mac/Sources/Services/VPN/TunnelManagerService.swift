//
//  TunnelManagerService.swift
//  SimpleTunnel
//

import Foundation
import SystemExtensions
import NetworkExtension
import OSLog

final class VPNSystemExtensionManager: NSObject, OSSystemExtensionRequestDelegate {
    
    private static let logger = LoggerService.vpnapp
    
    static let shared = VPNSystemExtensionManager()
    
    // MARK: - System Extension lifecycle
    
    func activateIfNeeded() {
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: VPNConfiguration.systemExtensionBundleID,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }
    
    // MARK: - OSSystemExtensionRequestDelegate
    
    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        Self.logger.both(.info, "System Extension activation finished with result: \(result.rawValue)")
    }
    
    func request(_ request: OSSystemExtensionRequest,
                 didFailWithError error: Error) {
        Self.logger.both(.error, "System Extension activation failed: \(error.localizedDescription)")
    }
    
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Self.logger.both(.info, "System Extension needs user approval in System Settings → Privacy & Security")
    }
    
    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }
    
    // MARK: - Async Public API

    @MainActor
    func loadExistingManager() async throws -> NETunnelProviderManager? {
        
        let managers = try await loadAllManagers()

        let ourManagers = managers.filter { manager in
            guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol else {
                return false
            }
            return proto.providerBundleIdentifier == VPNConfiguration.systemExtensionBundleID
        }

        return ourManagers.first
    }

    @MainActor
    func loadOrCreateManager(for profile: VPNProfile) async throws -> NETunnelProviderManager {
        Self.logger.both(.info, "Loading NETunnelProviderManager from preferences (async)...")

        let managers = try await loadAllManagers()

        let ourManagers = managers.filter { manager in
            guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol else {
                return false
            }
            return proto.providerBundleIdentifier == VPNConfiguration.systemExtensionBundleID
        }

        let keeper = ourManagers.first ?? NETunnelProviderManager()

        if ourManagers.isEmpty {
            Self.logger.both(.info, "No existing manager for our extension. Creating a new NETunnelProviderManager...")
        } else {
            Self.logger.both(.info, "Found \(ourManagers.count) existing manager(s). Using the first one as keeper.")
        }

        // Remove extras
        for extra in ourManagers.dropFirst() {
            do {
                try await extra.removeFromPreferences()
                Self.logger.both(.info, "Extra manager removed successfully.")
            } catch {
                Self.logger.both(.error, "Failed to remove extra manager: \(error.localizedDescription)")
            }
        }

        Self.logger.both(.info, "Applying active profile: \(profile.name)")
        apply(profile: profile, to: keeper)

        Self.logger.both(.info, "Saving keeper manager configuration (async)…")
        try await keeper.saveToPreferences()
        try await keeper.loadFromPreferences()

        return keeper
    }
    
    // MARK: - Private
    
    /// Loads ALL managers from preferences using the native async API.
    @MainActor
    private func loadAllManagers() async throws -> [NETunnelProviderManager] {
        return try await NETunnelProviderManager.loadAllFromPreferences()
    }

    
    private func apply(profile: VPNProfile, to manager: NETunnelProviderManager) {
        let proto = (manager.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = VPNConfiguration.systemExtensionBundleID

        let configDictionary = VPNConfiguration.makeProviderConfigurationDictionary(profile: profile)

        let serverAddress = formatServerAddress(host: profile.seHost, port: profile.sePort)
        proto.serverAddress = serverAddress
        proto.providerConfiguration = configDictionary

        manager.protocolConfiguration = proto

        let displayName = VPNConfiguration.displayName(for: profile.name)
        manager.localizedDescription = displayName
        manager.isEnabled = true

        Self.logger.both(.debug, "Applied provider configuration: bundleID=\(VPNConfiguration.systemExtensionBundleID), displayName=\(displayName)")
        Self.logger.both(.debug, "SoftEther server: host=\(profile.seHost), port=\(profile.sePort), serverAddress=\(serverAddress)")
    }

    // MARK: - Utils
    
    private func formatServerAddress(host: String, port: Int?) -> String {
        guard let port, port > 0 else {
            Self.logger.both(.debug, "Formatting server address without port: \(host)")
            return host
        }
        let isIPv6 = host.contains(":")
        let address = isIPv6 ? "[\(host)]:\(port)" : "\(host):\(port)"
        Self.logger.both(.debug, "Formatting server address: host=\(host), port=\(port) -> \(address)")
        return address
    }
}

