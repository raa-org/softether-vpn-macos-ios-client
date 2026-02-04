//
//  SoftEtherConfiguration.swift
//  SimpleTunnel

public struct SoftEtherClientConfiguration {
    
    public let host: String
    public let port: UInt16
    public let hubName: String
    
    public let enabledUDPAcceleration = true

    public init(host: String, port: UInt16, hubName: String, username: String? = nil, password: String? = nil) {
        self.host = host
        self.port = port
        self.hubName = hubName
    }
    
    // MARK: - Parse from Provider config
    
    public init(from providerConfig: [String: Any]) throws {

        guard let host = providerConfig["se_host"] as? String else {
            throw SoftEtherError("Missing host in provider config")
        }
        guard let port = providerConfig["se_port"] as? Int else {
            throw SoftEtherError("Missing port in provider config")
        }
        guard let hub = providerConfig["se_hub"] as? String else {
            throw SoftEtherError("Missing hub in provider config")
        }

        self.host = host
        self.port = UInt16(port)
        self.hubName = hub
    }
}
