//
//  SoftEtherSessionUDPParams+Pack.swift
//  SimpleTunnel
//

import Foundation

extension SoftEtherSessionUDPParams {

    /// Parse UDP Acceleration parameters from the server Welcome pack.
    ///
    /// SoftEther encodes IP values using `PackAddIp()`, which emits:
    /// - `<base>` as VALUE_INT (IPv4 in SoftEther's IP32 format)
    /// - `<base>@ipv6_bool` as VALUE_INT (bool)
    /// - `<base>@ipv6_array` as VALUE_DATA (16 bytes)
    /// - `<base>@ipv6_scope_id` as VALUE_INT
    init?(welcomePack pack: SoftEtherPack) throws {
        let enabled = pack.bool(SoftEtherPackTag.UdpAccelTags.useUdpAccel) ?? false
        guard enabled else { return nil }

        // Mandatory fields when UDP acceleration is enabled.
        guard let port = pack.u32(SoftEtherPackTag.UdpAccelTags.udpServerPort) else {
            throw SoftEtherError("Welcome: missing \(SoftEtherPackTag.UdpAccelTags.udpServerPort)")
        }
        guard let serverCookie = pack.u32(SoftEtherPackTag.UdpAccelTags.udpServerCookie) else {
            throw SoftEtherError("Welcome: missing \(SoftEtherPackTag.UdpAccelTags.udpServerCookie)")
        }
        guard let clientCookie = pack.u32(SoftEtherPackTag.UdpAccelTags.udpClientCookie) else {
            throw SoftEtherError("Welcome: missing \(SoftEtherPackTag.UdpAccelTags.udpClientCookie)")
        }
        guard let keyV1 = pack.bin(SoftEtherPackTag.UdpAccelTags.udpServerKeyV1) else {
            throw SoftEtherError("Welcome: missing \(SoftEtherPackTag.UdpAccelTags.udpServerKeyV1)")
        }
        guard let keyV2 = pack.bin(SoftEtherPackTag.UdpAccelTags.udpServerKeyV2) else {
            throw SoftEtherError("Welcome: missing \(SoftEtherPackTag.UdpAccelTags.udpServerKeyV2)")
        }

        let version = pack.u32(SoftEtherPackTag.UdpAccelTags.udpVersion) ?? 1

        // Optional security knobs (server can disable/enable them).
        let useEncryption = pack.bool(SoftEtherPackTag.UdpAccelTags.udpUseEncryption) ?? true
        let useHmac = pack.bool(SoftEtherPackTag.UdpAccelTags.udpUseHmac) ?? false
        let fastDetect = pack.bool(SoftEtherPackTag.UdpAccelTags.udpFastDisconnectDetect) ?? false

        // IP (IPv4 + optional IPv6 companion fields).
        let base = SoftEtherPackTag.UdpAccelTags.udpServerIP
        let isIPv6 = pack.bool(SoftEtherPackTag.UdpAccelTags.ipv6Bool(base)) ?? false

        let ipv6Array = pack.bin(SoftEtherPackTag.UdpAccelTags.ipv6Array(base))
        let ipv6Scope = pack.u32(SoftEtherPackTag.UdpAccelTags.ipv6ScopeId(base))

        // For IPv4, SoftEther stores IP32 in the base key.
        // For IPv6, the base key can be present but should be ignored.
        let ipv4 = pack.u32(base)

        self.init(
            useUDPAccel: true,
            version: version,
            useEncryption: useEncryption,
            useHmac: useHmac,
            fastDisconnectDetect: fastDetect,
            serverIP: isIPv6 ? nil : ipv4,
            serverPort: port,
            isServerIPv6: isIPv6,
            serverIPv6: isIPv6 ? ipv6Array : nil,
            serverIPv6ScopeId: isIPv6 ? ipv6Scope : nil,
            serverCookie: serverCookie,
            clientCookie: clientCookie,
            serverKeyV2: keyV2,
            serverKeyV1: keyV1
        )
    }
}
