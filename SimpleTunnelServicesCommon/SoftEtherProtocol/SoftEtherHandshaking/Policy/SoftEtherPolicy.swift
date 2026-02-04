//
//  SoftEtherPolicy.swift
//  SimpleTunnel

public struct SoftEtherPolicy {
    // Ver 2.0
    var Access: Bool = false
    var DHCPFilter: Bool = false
    var DHCPNoServer: Bool = false
    var DHCPForce: Bool = false
    var NoBridge: Bool = false
    var NoRouting: Bool = false
    var CheckMac: Bool = false
    var CheckIP: Bool = false
    var ArpDhcpOnly: Bool = false
    var PrivacyFilter: Bool = false
    var NoServer: Bool = false
    var NoBroadcastLimiter: Bool = false
    var MonitorPort: Bool = false
    var MaxConnection: UInt32 = 0
    var TimeOut: UInt32 = 0
    var MaxMac: UInt32 = 0
    var MaxIP: UInt32 = 0
    var MaxUpload: UInt32 = 0
    var MaxDownload: UInt32 = 0
    var FixPassword: Bool = false
    var MultiLogins: UInt32 = 0
    var NoQoS: Bool = false

    // Ver 3.0
    var RSandRAFilter: Bool = false
    var RAFilter: Bool = false
    var DHCPv6Filter: Bool = false
    var DHCPv6NoServer: Bool = false
    var NoRoutingV6: Bool = false
    var CheckIPv6: Bool = false
    var NoServerV6: Bool = false
    var MaxIPv6: UInt32 = 0
    var NoSavePassword: Bool = false
    var AutoDisconnect: UInt32 = 0
    var FilterIPv4: Bool = false
    var FilterIPv6: Bool = false
    var FilterNonIP: Bool = false
    var NoIPv6DefaultRouterInRA: Bool = false
    var NoIPv6DefaultRouterInRAWhenIPv6: Bool = false
    var VLanId: UInt32 = 0

    var Ver3: Bool = false
    
    public var description: String {
        var lines: [String] = []
        
        lines.append("SoftEtherPolicy {")

        let mirror = Mirror(reflecting: self)

        for child in mirror.children {
            guard let name = child.label else { continue }

            switch child.value {
            case let b as Bool:
                lines.append("  \(name): \(b ? "true" : "false")")

            case let n as UInt32:
                lines.append("  \(name): \(n)")

            default:
                break
            }
        }

        lines.append("}")
        return lines.joined(separator: "\n")
    }
}
