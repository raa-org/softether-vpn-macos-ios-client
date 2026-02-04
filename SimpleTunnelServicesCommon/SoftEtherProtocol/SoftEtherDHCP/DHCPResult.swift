//
//  DHCPResult.swift
//  SimpleTunnel

import Foundation

struct DHCPResult {
    /// Assigned client IPv4 address (yiaddr)
    public let address: IPv4Address

    /// Subnet mask
    public let mask: IPv4Address

    /// Default gateway (router option 3)
    public let router: IPv4Address?

    /// DNS server (option 6)
    public let dns: IPv4Address?

    /// Lease time in seconds (option 51)
    public let leaseTime: TimeInterval

    public init(
        address: IPv4Address,
        subnetMask: IPv4Address,
        router: IPv4Address?,
        dns: IPv4Address?,
        leaseTime: TimeInterval
    ) {
        self.address = address
        self.mask = subnetMask
        self.router = router
        self.dns = dns
        self.leaseTime = leaseTime
    }

    /// Helpful: convert to standard dotted decimal strings.
    public var addressString: String { address.description }
    public var maskString: String { mask.description }
    public var routerString: String? { router?.description }
    public var dnsString: String? { dns?.description }
}

extension SoftEtherNetworkParameters {
    init(from dhcp: DHCPResult) {

        let gateway = dhcp.router?.description ?? "0.0.0.0"
        let dns = dhcp.dns.map { [$0.description] } ?? []

        self.init(
            clientIPv4: dhcp.address.description,
            subnetMask: dhcp.mask.description,
            gatewayIPv4: gateway,
            mtu: 1400,
            dnsServers: dns
        )
    }
}
