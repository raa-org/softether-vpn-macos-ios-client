//
//  PacketTunnelProvider.swift
//  PacketTunnel-System-Mac

import NetworkExtension
#if os(iOS)
#elseif os(macOS)
import SimpleTunnelServicesMac
#endif
import OSLog
import AppAuthCore

// MARK: - Structured errors

enum PacketTunnelError: Error {
    case providerConfigMissing
    case invalidProviderConfiguration(underlying: Error)
    case auth(AuthError)
    case sessionConnectFailed(underlying: Error)
    case handshakeFailed(underlying: Error)
    case dhcpFailed(underlying: Error)
    case neSettingsApplyFailed(underlying: Error)
    case unknown(underlying: Error)
}

extension PacketTunnelError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .providerConfigMissing:
            return "No providerConfiguration"
        case .invalidProviderConfiguration(let underlying):
            return "Invalid provider configuration: \(underlying.localizedDescription)"
        case .auth(let authError):
            return authError.errorDescription
        case .sessionConnectFailed(let underlying):
            return "SoftEther session failed on connecting: \(underlying.localizedDescription)"
        case .handshakeFailed(let underlying):
            return "SoftEther session failed on handshaking: \(underlying.localizedDescription)"
        case .dhcpFailed(let underlying):
            return "SoftEther session failed on obtaining assigned IP: \(underlying.localizedDescription)"
        case .neSettingsApplyFailed(let underlying):
            return "Failed to apply Network Extension settings: \(underlying.localizedDescription)"
        case .unknown(let underlying):
            return underlying.localizedDescription
        }
    }
}

extension PacketTunnelError {
    enum AuthError: Error {
        case badOptionsNoCredentials
        case keychainStateMissing
        case keychainLoadFailed(underlying: Error)
        case oidcAction(underlying: Error)
        case idTokenMissing
        case buildAuthFromIDTokenFailed
    }
}

extension PacketTunnelError.AuthError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .badOptionsNoCredentials:
            return "Bad options: no credentials provided"
        case .keychainStateMissing:
            return "No OIDC auth state in Keychain"
        case .keychainLoadFailed(let underlying):
            return "Failed to load OIDC state from Keychain: \(underlying.localizedDescription)"
        case .oidcAction(let underlying):
            return "OIDC performAction error: \(underlying.localizedDescription)"
        case .idTokenMissing:
            return "No id_token from OIDC"
        case .buildAuthFromIDTokenFailed:
            return "Failed to build SoftEtherAuthMethod from id_token"
        }
    }
}

/// A packet tunnel provider object.
class PacketTunnelProvider: NEPacketTunnelProvider {

	// MARK: Properties
    let appGroupID: String = {
        guard let value = Bundle.main.object(forInfoDictionaryKey: "APP_GROUP_ID") as? String, !value.isEmpty else {
            preconditionFailure("Missing or empty APP_GROUP_ID in Info.plist. Provide a valid App Group identifier.")
        }
        return value
    }()


    private var softEtherSession: SoftEtherSession?
    private static let logger = LoggerService.vpnext
    
	// MARK: NEPacketTunnelProvider

	/// Begin the process of establishing the tunnel.
    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        // Initialize shared file logging for the extension as well
        LoggerService.configureSystemExtension(appGroupID: appGroupID)

        guard let protocolConfiguration = (protocolConfiguration as? NETunnelProviderProtocol),
              let providerConfiguration  = protocolConfiguration.providerConfiguration else {
            
            let err = PacketTunnelError.providerConfigMissing
            PacketTunnelProvider.logger.both(.error, "Start tunnel failed: \(err.localizedDescription)")
            return completionHandler(err)
        }
        
        // Resolve auth either from options or Keychain
        getAuthFromOptionOrFromKeychain(options: options, providerConfiguration: providerConfiguration) { authResult in
            switch authResult {
            case .failure(let error):
                PacketTunnelProvider.logger.both(.error, "Start tunnel failed: no auth credentials. \(error.localizedDescription)")
                completionHandler(error)
                return
                
            case .success(let auth):
                do {
                    let softEtherConfiguration = try SoftEtherClientConfiguration(from: providerConfiguration)
                    
                    let session = SoftEtherSession(provider: self, configuration: softEtherConfiguration)
                    self.softEtherSession = session
                    
                    let handleFail: (PacketTunnelError) -> Void = { error in
                        PacketTunnelProvider.logger.both(.error, error.localizedDescription)
                        self.softEtherSession?.stop()
                        completionHandler(error)
                    }
                    
                    session.connect { result in
                        switch result {
                            
                        case .failure(let error):
                            handleFail(.sessionConnectFailed(underlying: error))
                            
                        case .success:
                            PacketTunnelProvider.logger.both(.info, "Soft Ether session connected successfully.")
                            
                            session.handshake(using: auth) { result in
                                switch result {
                                    
                                case .failure(let error):
                                    handleFail(.handshakeFailed(underlying: error))
                                    
                                case .success(let softEtherSessionParams):
                                    PacketTunnelProvider.logger.both(.info, "Soft Ether session made handshake successfully. Session name is \(softEtherSessionParams.sessionName), connection name is \(softEtherSessionParams.connectionName).")
                                    PacketTunnelProvider.logger.bothDump(.info, softEtherSessionParams.description)
                                    
                                    session.obtainIPviaDHCP { result in
                                        switch result {
                                            
                                        case .failure(let error):
                                            handleFail(.dhcpFailed(underlying: error))
                                            
                                        case .success(let softEtherNetworkParameters):
                                            PacketTunnelProvider.logger.both(.info, "Soft Ether session obtained assigned IP successfully.")
                                            self.applySettingsFrom(Configuration: softEtherConfiguration, NetworkParameters: softEtherNetworkParameters) { error in
                                                if let error {
                                                    handleFail(.neSettingsApplyFailed(underlying: error))
                                                } else {
                                                    PacketTunnelProvider.logger.both(.info, "Soft Ether session set NE settings successfully.")
                                                    session.startTunneling()
                                                    completionHandler(nil)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } catch {
                    let err = PacketTunnelError.invalidProviderConfiguration(underlying: error)
                    PacketTunnelProvider.logger.both(.error, "Failed to parse provider configuration. \(err.localizedDescription)")
                    return completionHandler(err)
                }
            }
        }
    }
            
    
    /// Begin the process of stopping the tunnel.
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        softEtherSession?.stop()
        softEtherSession = nil
        completionHandler()
    }

        
    /// Applies DHCP settings to the utun interface.
    /// On success, invokes completion(nil).
    /// On failure, invokes completion(error).
    private func applySettingsFrom(Configuration clientConfiguration:SoftEtherClientConfiguration, NetworkParameters networkParameters: SoftEtherNetworkParameters, completion: @escaping (Error?) -> Void)
    {
        let remoteAddress = clientConfiguration.host
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)

        let neIPv4Settings = NEIPv4Settings(addresses: [networkParameters.clientIPv4], subnetMasks: [networkParameters.subnetMask])
        
        neIPv4Settings.router = networkParameters.gatewayIPv4
        
        // full-tunnel route
        neIPv4Settings.includedRoutes = [ NEIPv4Route.default() ]

        settings.ipv4Settings = neIPv4Settings

        // DNS
        let neDNSSettings = NEDNSSettings(servers: networkParameters.dnsServers)
        neDNSSettings.matchDomains = [""]   // apply to all domains
        
        settings.dnsSettings = neDNSSettings
        
        settings.mtu = NSNumber(value: networkParameters.mtu)

        self.setTunnelNetworkSettings(settings) { error in
            completion(error)
            
            // Debug info
            if let dns = settings.dnsSettings {
                let serversJoined = dns.servers.joined(separator: ", ")
                let domainsJoined = dns.matchDomains?.joined(separator: ", ") ?? "nil"
                PacketTunnelProvider.logger.both(.debug, "DNS applied: \(serversJoined)  matchDomains=\(domainsJoined)")
            } else {
                PacketTunnelProvider.logger.both(.debug, "No DNS applied")
            }

            if let ipv4 = settings.ipv4Settings {
                let routes = (ipv4.includedRoutes ?? []).map { "\($0.destinationAddress)/\($0.destinationSubnetMask)" }.joined(separator: ", ")
                let addressesJoined = ipv4.addresses.joined(separator: ", ")
                PacketTunnelProvider.logger.both(.debug, "IPv4 applied: addresses=\(addressesJoined) routes=\(routes)")
            }

            if let mtu = settings.mtu {
                PacketTunnelProvider.logger.both(.debug, "MTU applied: \(mtu)")
            }
        }
    }
    
    // MARK: - Silent auth
    
    private func getAuthFromOptionOrFromKeychain(options: [String: NSObject]?, providerConfiguration: [String: Any], completion: @escaping (Result<SoftEtherAuthMethod, PacketTunnelError>) -> Void) {
        
        if let options = options {
            if let auth = SoftEtherAuthMethod(options: options) {
                completion(.success(auth))
            } else {
                completion(.failure(.auth(.badOptionsNoCredentials)))
            }
        } else {
            makeAuthFromKeychainSilently(providerConfiguration: providerConfiguration) { result in
                switch result {
                case .success(let auth):
                    completion(.success(auth))
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        }
    }
    
    private func makeAuthFromKeychainSilently(providerConfiguration: [String: Any], completion: @escaping (Result<SoftEtherAuthMethod, PacketTunnelError>) -> Void) {
        do {
            guard
                let profileName = providerConfiguration["profile_name"] as? String,
                let oidc = providerConfiguration["oidc"] as? [String: Any],
                let issuerUrl = oidc["issuer_url"] as? String,
                let clientId  = oidc["client_id"] as? String
            else {
                struct ConfigParseError: LocalizedError {
                    let errorDescription: String? = "providerConfiguration missing profile_name/oidc/issuer_url/client_id"
                }
                completion(.failure(.invalidProviderConfiguration(underlying: ConfigParseError())))
                return
            }
            
            let key = AuthStateKeychainStore.stateKey(profileName: profileName, issuerUrl: issuerUrl, clientId: clientId)

            guard let state = try AuthStateKeychainStore.load(key: key) else {
                completion(.failure(.auth(.keychainStateMissing)))
                return
            }

            state.performAction { _, idToken, error in
                if let error {
                    completion(.failure(.auth(.oidcAction(underlying: error))))
                    return
                }

                guard let idToken, !idToken.isEmpty else {
                    completion(.failure(.auth(.idTokenMissing)))
                    return
                }

                if let auth = SoftEtherAuthMethod(jwt: idToken) {
                    completion(.success(auth))
                } else {
                    completion(.failure(.auth(.buildAuthFromIDTokenFailed)))
                }
            }

        } catch {
            completion(.failure(.auth(.keychainLoadFailed(underlying: error))))
        }
    }
    
    // MARK: - Handle App messages
    
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        PacketTunnelProvider.logger.both(.info, "Extenstion received app message.")
        
        guard let cmd = String(data: messageData, encoding: .utf8) else {
            completionHandler?(nil)
            return
        }
        
        guard let softEtherSession = self.softEtherSession else {
            PacketTunnelProvider.logger.both(.debug, "No active SoftEtherSession")
            completionHandler?(nil)
            return
        }
        
        guard let networkParameters = softEtherSession.networkParameters else {
            PacketTunnelProvider.logger.both(.debug, "No network parameters yet")
            completionHandler?(nil)
            return
        }

        if cmd == "dhcp_status" {
            let payload: [String: Any] = [
                "assigned_ip": networkParameters.clientIPv4,
                "subnet_mask": networkParameters.subnetMask,
                "gateway": networkParameters.gatewayIPv4,
                "dns": networkParameters.dnsServers,
                "mtu": networkParameters.mtu
            ]

            let message: [String: Any] = [
                "type": "dhcp_info",
                "payload": payload
            ]

            do {
                let data = try JSONSerialization.data(withJSONObject: message, options: [])
                completionHandler?(data)
            } catch {
                PacketTunnelProvider.logger.both(.error, "Failed to encode dhcp_info message: \(error.localizedDescription)")
                completionHandler?(nil)
            }
            return
        }

        completionHandler?(nil)
    }
    
    override func sleep(completionHandler: @escaping () -> Void) {
        PacketTunnelProvider.logger.both(.info, "System going to sleep. Stopping SoftEther session.")
            
        softEtherSession?.stop()
        softEtherSession = nil

        completionHandler()
    }
    
    override func wake() {
        // Add code here to wake up.
    }
}
