//
//  VPNViewModel.swift
//  SimpleTunnel

import Foundation
import NetworkExtension
import Combine
import AppKit
import OSLog

@MainActor
final class VPNViewModel: ObservableObject {
    
    enum VPNStatusIndicator {
        case connected
        case inProgress
        case disconnected
    }
    
    struct Toast: Identifiable, Equatable {
        let id = UUID()
        let kind: ToastView.Kind
        let text: String
        let duration: TimeInterval
    }
    
    // MARK: - Published state
    
    @Published var windowTitle: String = VPNConfiguration.defaultDisplayName
    
    @Published var profiles: [VPNProfile] = []
    @Published var selectedProfileName: String = ""
    
    @Published var statusIndicator: VPNStatusIndicator = .disconnected
    @Published var statusText: String = "Unknow"
    @Published var buttonTitle: String = "Connect"
    
    @Published var hasProfile: Bool = false
    @Published var isBusy: Bool = false

    var canLogout: Bool {
        guard let profile = selectedProfile() else {
            return false
        }
        
        guard oidcManager.isLoggedIn(profileName: profile.name, oidcConfig: profile.oidcConfig) else {
            return false
        }
        
        guard let manager = tunnelProviderManager else {
            return false
        }

        let status = manager.connection.status
        switch status {
        case .invalid, .disconnected:
            return true
        default:
            return false
        }
    }
    
    // MARK: - Published message
    
    @Published var toast: Toast? = nil
    private var toastDismissTask: Task<Void, Never>? = nil

    func showToast(_ text: String, kind: ToastView.Kind = .info, duration: TimeInterval = 2.5) {
        toastDismissTask?.cancel()
        toast = Toast(kind: kind, text: text, duration: duration)

        toastDismissTask = Task { @MainActor [weak self] in
            guard let self else {
                return
            }
            try? await Task.sleep(nanoseconds: UInt64(duration * 1_000_000_000))
            if !Task.isCancelled {
                self.toast = nil
            }
        }
    }

    // MARK: - Private
    
    private var tunnelProviderManager: NETunnelProviderManager?
    private let tunnelService = VPNSystemExtensionManager.shared
    
    private let diagnosticsExporter = DiagnosticsExporterImpl()
    
    private let oidcManager = OIDCManager()
    private var cancellables = Set<AnyCancellable>()
    
    private static let logger = LoggerService.vpnapp
    
    // MARK: - Init
    
    init() {
        NotificationCenter.default.publisher(for: .NEVPNStatusDidChange)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                self?.updateUI()
            }
            .store(in: &cancellables)
        
        do {
            let loaded = try ProfileConfigLoader.loadProfiles()
            applyLoadedProfiles(loaded)
        } catch {
            hasProfile = false
            statusText = "No configuration"
            if case ProfileConfigError.missingFile = error,
               let url = try? ProfileConfigLoader.profilesFileURL() {
                VPNViewModel.logger.both(.error, "Config load failed: \(error.localizedDescription). Expected at: \(url.path)")
            } else {
                VPNViewModel.logger.both(.error, "Config load failed: \(error.localizedDescription)")
            }
            return
        }
        
        Task { [weak self] in
            guard let self else { return }
            do {
                self.tunnelProviderManager = try await self.tunnelService.loadExistingManager()
            } catch {
                VPNViewModel.logger.both(.error, "Manager load error: \(error.localizedDescription)")
            }

            self.syncSelectedProfileFromManagerIfPossible()
            self.updateUI()
        }
    }
    
    private func managerProfileName(_ manager: NETunnelProviderManager) -> String? {
        guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol else {
            return nil
        }
        guard let dict = proto.providerConfiguration else {
            return nil
        }
        return dict["profile_name"] as? String
    }
    
    private func selectedProfile() -> VPNProfile? {
        if !selectedProfileName.isEmpty,
           let p = profiles.first(where: { $0.name == selectedProfileName }) {
            return p
        }
        return profiles.first
    }
    
    // MARK: - Public API for View
    
    func importConfig(from pickedURL: URL) throws {
        let fileManager = FileManager.default
        let destination = try ProfileConfigLoader.profilesFileURL()
        let backupURL = destination.appendingPathExtension("backup")

        if fileManager.fileExists(atPath: backupURL.path) {
            try? fileManager.removeItem(at: backupURL)
        }
        if fileManager.fileExists(atPath: destination.path) {
            try fileManager.moveItem(at: destination, to: backupURL)
        }

        do {
            if fileManager.fileExists(atPath: destination.path) {
                try fileManager.removeItem(at: destination)
            }
            try fileManager.copyItem(at: pickedURL, to: destination)

            let loaded = try ProfileConfigLoader.loadProfiles()
            applyLoadedProfiles(loaded)

            syncSelectedProfileFromManagerIfPossible()
            updateUI()
            if fileManager.fileExists(atPath: backupURL.path) {
                try? fileManager.removeItem(at: backupURL)
            }

            VPNViewModel.logger.both(.info, "Config imported successfully from \(pickedURL.path)")

        } catch {
            if fileManager.fileExists(atPath: backupURL.path) {
                try? fileManager.moveItem(at: backupURL, to: destination)
            }

            VPNViewModel.logger.both(.error, "Config import failed: \(error.localizedDescription)")
            throw error
        }
    }
    
    @MainActor
    func selectProfileName(_ name: String) {
        guard name != selectedProfileName else {
            return
        }
        
        if let manager = tunnelProviderManager,
           let session = manager.connection as? NETunnelProviderSession {
            switch session.status {
            case .connected, .connecting, .reasserting, .disconnecting:
                showToast("Disconnect first to change profile.", kind: .info)
                return
            default:
                break
            }
        }
        
        Task { [weak self] in
            
            guard let self else {
                return
            }
            
            do {
                guard let profile = self.profiles.first(where: { $0.name == name }) else {
                    return
                }

                let updated = try await self.tunnelService.loadOrCreateManager(for: profile)
                self.tunnelProviderManager = updated

                self.selectedProfileName = name
                self.windowTitle = VPNConfiguration.displayName(for: name)

                self.updateUI()
            } catch {
                self.showToast("Apply profile failed: \(error.localizedDescription)", kind: .error)
            }
        }
    }
    
    @MainActor
    func toggleTunnel() async {
        guard !isBusy else {
            return
        }
        
        isBusy = true
        defer {
            self.isBusy = false
        }

        do {
            let manager = try await self.ensureManagerMatchesSelectedProfileIfSafe()

            guard let session = manager.connection as? NETunnelProviderSession else {
                self.showToast("No NE Tunnel Provider Session", kind: .error)
                return
            }
            
            await self.toggle(session: session)
            self.updateUI()
        } catch {
            VPNViewModel.logger.both(.error, "Toggle failed: \(error.localizedDescription)")
            self.showToast("Toggle failed: \(error.localizedDescription)", kind: .error)
        }
    }
    
    func logout() {
        guard let profile = selectedProfile() else {
            VPNViewModel.logger.both(.error, "No selected profile")
            showToast("Profile is not selected.", kind: .error)
            return
        }
        
        if let manager = tunnelProviderManager {
            let status = manager.connection.status
            guard status == .invalid || status == .disconnected else {
                VPNViewModel.logger.both(.info, "Logout requested but VPN status is \(status.rawValue)")
                return
            }
        }
        
        oidcManager.logout(profileName: profile.name, oidcConfig: profile.oidcConfig)
        VPNViewModel.logger.both(.info, "User logged out")
        showToast("Logged out successfully.", kind: .success)
    }
    
    func showAppLogInFinder() {
        if let url = LoggerService.currentLogFileURL() {
            NSWorkspace.shared.activateFileViewerSelecting([url])
        }
    }

    func exportDiagnosticsZip() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.zip]
        panel.nameFieldStringValue = "SoftEtherVPN-Diagnostics.zip"
        panel.canCreateDirectories = true

        guard panel.runModal() == .OK, let outURL = panel.url else {
            return
        }

        Task { @MainActor in
            let got = outURL.startAccessingSecurityScopedResource()
            defer {
                if got {
                    outURL.stopAccessingSecurityScopedResource()
                }
            }

            do {
                try diagnosticsExporter.exportDiagnostics(to: outURL)
                NSWorkspace.shared.activateFileViewerSelecting([outURL])
                
                VPNViewModel.logger.both(.info, "Export diagnostics success.")
                showToast("Diagnostics exported.", kind: .success)
            } catch {
                VPNViewModel.logger.both(.error, "Export diagnostics failed: \(error.localizedDescription)")
                showToast("Export failed: \(error.localizedDescription)", kind: .error)
            }
        }
    }

    // MARK: - UI state
    
    private func updateUI() {
        hasProfile = !profiles.isEmpty
        
        guard let manager = tunnelProviderManager else {
            buttonTitle = "Connect"
            statusIndicator = .disconnected
            statusText = "Disconnected"
            return
        }
        
        hasProfile = true
        let status = manager.connection.status
        VPNViewModel.logger.debugIfDebugBuild("VPN status from NE: \(status.rawValue)")
        
        switch status {
            
        case .invalid, .disconnected:
            buttonTitle = "Connect"
            statusIndicator = .disconnected
            break
            
        case .connecting, .reasserting, .disconnecting:
            buttonTitle = "Disconnect"
            statusIndicator = .inProgress
            break
            
        case .connected:
            requestDHCPInfoOnce()
            buttonTitle = "Disconnect"
            statusIndicator = .connected
            break
            
        @unknown default:
            buttonTitle = "Connect"
            statusIndicator = .disconnected
            break
        }
        
        statusText = status.rawValue
    }

    // MARK: -
    
    @MainActor
    private func toggle(session: NETunnelProviderSession) async {
        switch session.status {
        case .invalid, .disconnected:
            VPNViewModel.logger.both(.info, "Connecting VPN…")
            await connect(session: session)
            break

        case .connected:
            VPNViewModel.logger.both(.info, "Disconnecting VPN…")
            disconnect(session: session)
            break

        case .connecting, .reasserting, .disconnecting:
            VPNViewModel.logger.both(.info, "Already in progress…")
            disconnect(session: session)
            break

        @unknown default:
            break
        }
    }

    private func connect(session: NETunnelProviderSession) async {
        guard let window = NSApp.keyWindow ?? NSApp.mainWindow ?? NSApp.windows.first else {
            VPNViewModel.logger.both(.error, "No window to present OIDC")
            return
        }
        
        guard let profile = selectedProfile() else {
            VPNViewModel.logger.both(.error, "No selected profile")
            showToast("Profile is not selected.", kind: .error)
            return
        }
        
        do {
            var optionsWithAuthData = [String: NSObject]()
            
            let tokens = try await oidcManager.ensureValidTokens(oidcConfig: profile.oidcConfig, profileName: profile.name, presentingWindow: window)
            if let idToken = tokens.idToken {
                optionsWithAuthData["id_token"] = idToken as NSString
            }
            
            do {
                VPNViewModel.logger.both(.info, "Starting VPN tunnel")
                try session.startVPNTunnel(options: optionsWithAuthData)
            } catch {
                VPNViewModel.logger.both(.error, "Failed to start VPN: \(error.localizedDescription)")
                showToast("Something went wrong.", kind: .error)
            }
            
        } catch OIDCError.userCancelled {
            VPNViewModel.logger.both(.info, "Login cancelled")
        } catch {
            VPNViewModel.logger.both(.error, "OIDC error: \(error.localizedDescription)")
        }
    }
    
    private func disconnect(session: NETunnelProviderSession) {
        VPNViewModel.logger.both(.info, "Stopping VPN…")
        session.stopVPNTunnel()
        updateUI()
    }
    
    private func applyLoadedProfiles(_ loaded: [VPNProfile]) {
        profiles = loaded
        hasProfile = !loaded.isEmpty

        if let first = loaded.first {
            selectedProfileName = first.name
        } else {
            selectedProfileName = ""
        }

        windowTitle = VPNConfiguration.displayName(for: selectedProfileName)

        if hasProfile {
            statusText = "Disconnected"
        } else {
            statusText = "No configuration"
        }
    }
    
    @MainActor
    private func ensureManagerMatchesSelectedProfileIfSafe() async throws -> NETunnelProviderManager {
        guard let profile = selectedProfile() else {
            throw NSError(domain: "VPNViewModel", code: 1, userInfo: [NSLocalizedDescriptionKey: "No profile selected"])
        }

        if let existing = tunnelProviderManager,
           let session = existing.connection as? NETunnelProviderSession {

            switch session.status {
            case .connected, .connecting, .reasserting, .disconnecting:
                return existing
            default:
                break
            }

            let currentManagerProfileName = managerProfileName(existing)
            if currentManagerProfileName == profile.name {
                return existing
            }
        }

        let updated = try await tunnelService.loadOrCreateManager(for: profile)
        tunnelProviderManager = updated
        windowTitle = VPNConfiguration.displayName(for: profile.name)
        return updated
    }
    
    @MainActor
    private func syncSelectedProfileFromManagerIfPossible() {
        guard let manager = tunnelProviderManager else {
            return
        }
        guard let name = managerProfileName(manager) else {
            return
        }
        guard profiles.contains(where: { $0.name == name }) else {
            return
        }

        selectedProfileName = name
        windowTitle = VPNConfiguration.displayName(for: name)
    }

    // MARK: - DHCP info
    
    private func requestDHCPInfoOnce() {

        guard let session = tunnelProviderManager?.connection as? NETunnelProviderSession else {
            VPNViewModel.logger.both(.error, "Can't send request for DHCP info. There isn't connection for tunnel provider manager.")
            return
        }

        let cmd = Data("dhcp_status".utf8)

        do {
            VPNViewModel.logger.both(.info, "Sending DHCP status message.")
            try session.sendProviderMessage(cmd) { [weak self] reply in
                guard let self else {
                    return
                }

                if let reply = reply {
                    VPNViewModel.logger.both(.info, "Received DHCP status reply.")
                    self.handleIncomingMessage(reply)
                } else {
                    VPNViewModel.logger.both(.error, "Received empty DHCP status reply.")
                }
            }
        } catch {
            VPNViewModel.logger.both(.error, "Failed to send provider message: \(error.localizedDescription)")
        }
    }
    
    private func handleIncomingMessage(_ data: Data) {
        guard let wrapper = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let type = wrapper["type"] as? String,
              let payload = wrapper["payload"] as? [String: Any]
        else {
            return
        }

        if type == "dhcp_info" {
            if let assignedIP = payload["assigned_ip"] as? String {
                VPNViewModel.logger.both(.info, "Assigned IP: \(assignedIP)")
            }
            else {
                VPNViewModel.logger.both(.error, "Empty assigned ip field in reply")
            }
        }
    }
}
