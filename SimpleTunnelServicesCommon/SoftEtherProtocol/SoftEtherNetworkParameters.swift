//
//  SoftEtherNetworkParameters.swift
//  SimpleTunnel

public struct SoftEtherNetworkParameters {
    public let clientIPv4: String
    public let subnetMask: String
    public let gatewayIPv4: String
    public let mtu: Int
    public let dnsServers: [String]
    
    public init(clientIPv4: String, subnetMask: String, gatewayIPv4: String, mtu: Int = 1400, dnsServers: [String]) {
        self.clientIPv4 = clientIPv4
        self.subnetMask = subnetMask
        self.gatewayIPv4 = gatewayIPv4
        self.mtu = mtu
        self.dnsServers = dnsServers
    }
    
    public var description: String {
        var description = "SoftEtherNetworkParameters {\n"
        description += "  clientIPv4: \(clientIPv4)\n"
        description += "  subnetMask: \(subnetMask)\n"
        description += "  gatewayIPv4: \(gatewayIPv4)\n"
        description += "  mtu: \(mtu)\n"
        
        if dnsServers.isEmpty {
            description += "  dnsServers: []\n"
        } else {
            description += "  dnsServers: [\(dnsServers.joined(separator: ", "))]\n"
        }

        description += "}"
        return description
    }
}
