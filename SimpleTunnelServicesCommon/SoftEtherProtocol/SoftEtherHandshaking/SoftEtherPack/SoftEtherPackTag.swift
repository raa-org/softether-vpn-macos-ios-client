//
//  SoftEtherPackTag.swift
//  SimpleTunnel

import Foundation

enum SoftEtherPackTag {
    // error
        static let error = "error" // u32

        // hello
        static let random = "random" // bin[20]
        static let serverVer = "version" // u32
        static let serverBuild = "build" // u32
        static let serverStr = "hello" // str

        // redirect branch
        static let redirect = "Redirect" // bool
        static let ip = "Ip" // u32
        static let port = "Port" // u32[]

        // welcome (after auth)
        static let sessionName = "session_name" // str
        static let connectionName = "connection_name" // str
        static let sessionKey = "session_key" // bin [20] (SENSITIVE)
        static let sessionKey32 = "session_key_32" // u32
        static let enableUdpRecovery = "enable_udp_recovery" // bool
        static let maxConnection = "max_connection" // u32
        static let useCompress = "use_compress" // bool
        static let useEncrypt = "use_encrypt" // bool
        static let noSendSignature = "no_send_signature" // bool
        static let halfConnection = "half_connection" // bool
        static let isAzureSession = "is_azure_session" // bool
        static let timeout = "timeout" // u32
        static let qos = "qos" // u32 / bool
        static let vlanId = "vlan_id" // u32
        static let udpSendKey = "udp_send_key" // bin (SENSITIVE)
        static let udpRecieveKey = "udp_recv_key" // bin (SENSITIVE)

        // auth request (client -> server) tags
        static let method = "method" // str
        static let hubName = "hubname" // str
        static let userName = "username" // str (PII)
        static let authType = "authtype" // int
        static let jwt = "jwt" // str (SENSITIVE)

        static let protocolType = "protocol" // int
        static let clientStr = "client_str" // str
        static let clientVer = "client_ver" // int
        static let clientBuild = "client_build" // int
        static let pencore = "pencore" // data (entropy-like, treat as sensitive)

        // UDP accel client advertisement (client -> server)
        static let udpAccelClientIp = "udp_acceleration_client_ip" // int
        static let udpAccelClientPort = "udp_acceleration_client_port" // int
        static let udpAccelClientKeyV1 = "udp_acceleration_client_key" // data (SENSITIVE)
        static let udpAccelClientKeyV2 = "udp_acceleration_client_key_v2" // data (SENSITIVE)

        static let supportHmacOnUdpAcceleration = "support_hmac_on_udp_acceleration" // bool/int
        static let supportUdpAccelFastDisconnectDetect = "support_udp_accel_fast_disconnect_detect" // bool/int
        static let udpAccelerationMaxVersion = "udp_acceleration_max_version" // int

    enum PolicyTags {
        private static let prefix = "policy:"

        // Ver2 bools
        static let Access = prefix + "Access"
        static let DHCPFilter = prefix + "DHCPFilter"
        static let DHCPNoServer = prefix + "DHCPNoServer"
        static let DHCPForce = prefix + "DHCPForce"
        static let NoBridge = prefix + "NoBridge"
        static let NoRouting = prefix + "NoRouting"
        static let CheckMac = prefix + "CheckMac"
        static let CheckIP = prefix + "CheckIP"
        static let ArpDhcpOnly = prefix + "ArpDhcpOnly"
        static let PrivacyFilter = prefix + "PrivacyFilter"
        static let NoServer = prefix + "NoServer"
        static let NoBroadcastLimiter = prefix + "NoBroadcastLimiter"
        static let MonitorPort = prefix + "MonitorPort"
        static let FixPassword = prefix + "FixPassword"
        static let NoQoS = prefix + "NoQoS"

        // Ver2 uints
        static let MaxConnection = prefix + "MaxConnection"
        static let TimeOut = prefix + "TimeOut"
        static let MaxMac = prefix + "MaxMac"
        static let MaxIP = prefix + "MaxIP"
        static let MaxUpload = prefix + "MaxUpload"
        static let MaxDownload = prefix + "MaxDownload"
        static let MultiLogins = prefix + "MultiLogins"

        // Ver3 bools
        static let RSandRAFilter = prefix + "RSandRAFilter"
        static let RAFilter = prefix + "RAFilter"
        static let DHCPv6Filter = prefix + "DHCPv6Filter"
        static let DHCPv6NoServer = prefix + "DHCPv6NoServer"
        static let NoRoutingV6 = prefix + "NoRoutingV6"
        static let CheckIPv6 = prefix + "CheckIPv6"
        static let NoServerV6 = prefix + "NoServerV6"
        static let NoSavePassword = prefix + "NoSavePassword"
        static let FilterIPv4 = prefix + "FilterIPv4"
        static let FilterIPv6 = prefix + "FilterIPv6"
        static let FilterNonIP = prefix + "FilterNonIP"
        static let NoIPv6DefaultRouterInRA = prefix + "NoIPv6DefaultRouterInRA"
        static let NoIPv6DefaultRouterInRAWhenIPv6 = prefix + "NoIPv6DefaultRouterInRAWhenIPv6"

        // Ver3 uints
        static let MaxIPv6 = prefix + "MaxIPv6"
        static let AutoDisconnect = prefix + "AutoDisconnect"
        static let VLanId = prefix + "VLanId"

        // Ver3 flag
        static let Ver3 = prefix + "Ver3"
    }
    
    enum UdpAccelTags {
        static let useUdpAccel = "use_udp_acceleration" // bool / int
        static let udpVersion = "udp_acceleration_version" // u32
        static let udpServerIP = "udp_acceleration_server_ip" // bin[4]
        static let udpServerPort = "udp_acceleration_server_port" // u32
        static let udpServerCookie = "udp_acceleration_server_cookie" // u32
        static let udpClientCookie = "udp_acceleration_client_cookie" // u32
        static let udpServerKeyV2 = "udp_acceleration_server_key_v2" // bin (SENSITIVE)
        static let udpServerKeyV1 = "udp_acceleration_server_key" // bin (SENSITIVE)

        static let udpUseEncryption = "udp_acceleration_use_encryption" // bool
        static let udpUseHmac = "use_hmac_on_udp_acceleration" // bool
        static let udpFastDisconnectDetect = "udp_accel_fast_disconnect_detect" // bool

        static func ipv6Bool(_ base: String) -> String { base + "@ipv6_bool" }
        static func ipv6Array(_ base: String) -> String { base + "@ipv6_array" }
        static func ipv6ScopeId(_ base: String) -> String { base + "@ipv6_scope_id" }
    }
}

extension SoftEtherPack {
    
    // MARK: - Logging allowlist
    
    static let logAllowedKeys: Set<String> = [
            // Generic / non-secret
            SoftEtherPackTag.error,
            SoftEtherPackTag.serverVer,
            SoftEtherPackTag.serverBuild,
            SoftEtherPackTag.serverStr,

            // Redirect info
            SoftEtherPackTag.redirect,
            SoftEtherPackTag.ip,
            SoftEtherPackTag.port,

            // Non-secret welcome metadata
            SoftEtherPackTag.sessionName,
            SoftEtherPackTag.connectionName,
            SoftEtherPackTag.enableUdpRecovery,
            SoftEtherPackTag.maxConnection,
            SoftEtherPackTag.useCompress,
            SoftEtherPackTag.useEncrypt,
            SoftEtherPackTag.noSendSignature,
            SoftEtherPackTag.halfConnection,
            SoftEtherPackTag.isAzureSession,
            SoftEtherPackTag.timeout,
            SoftEtherPackTag.qos,
            SoftEtherPackTag.vlanId,
            SoftEtherPackTag.sessionKey32,

            // Auth request (safe subset)
            SoftEtherPackTag.method,
            SoftEtherPackTag.hubName,
            SoftEtherPackTag.authType,

            SoftEtherPackTag.protocolType,
            SoftEtherPackTag.clientStr,
            SoftEtherPackTag.clientVer,
            SoftEtherPackTag.clientBuild,

            // UDP accel (safe subset of client advertisement)
            SoftEtherPackTag.UdpAccelTags.useUdpAccel,
            SoftEtherPackTag.udpAccelClientIp,       // optional: remove if you don't want to log local IP
            SoftEtherPackTag.udpAccelClientPort,
            SoftEtherPackTag.supportHmacOnUdpAcceleration,
            SoftEtherPackTag.supportUdpAccelFastDisconnectDetect,
            SoftEtherPackTag.udpAccelerationMaxVersion,

            // UDP accel negotiation flags from server (safe)
            SoftEtherPackTag.UdpAccelTags.udpVersion,
            SoftEtherPackTag.UdpAccelTags.udpServerPort,
            SoftEtherPackTag.UdpAccelTags.udpUseEncryption,
            SoftEtherPackTag.UdpAccelTags.udpUseHmac,
            SoftEtherPackTag.UdpAccelTags.udpFastDisconnectDetect
        ]

        static let logAllowedPolicyKeys: Set<String> = [
            SoftEtherPackTag.PolicyTags.Access,
            SoftEtherPackTag.PolicyTags.DHCPFilter,
            SoftEtherPackTag.PolicyTags.DHCPNoServer,
            SoftEtherPackTag.PolicyTags.DHCPForce,
            SoftEtherPackTag.PolicyTags.NoBridge,
            SoftEtherPackTag.PolicyTags.NoRouting,
            SoftEtherPackTag.PolicyTags.CheckMac,
            SoftEtherPackTag.PolicyTags.CheckIP,
            SoftEtherPackTag.PolicyTags.ArpDhcpOnly,
            SoftEtherPackTag.PolicyTags.PrivacyFilter,
            SoftEtherPackTag.PolicyTags.NoServer,
            SoftEtherPackTag.PolicyTags.NoBroadcastLimiter,
            SoftEtherPackTag.PolicyTags.MonitorPort,
            SoftEtherPackTag.PolicyTags.FixPassword,
            SoftEtherPackTag.PolicyTags.NoQoS,

            SoftEtherPackTag.PolicyTags.MaxConnection,
            SoftEtherPackTag.PolicyTags.TimeOut,
            SoftEtherPackTag.PolicyTags.MaxMac,
            SoftEtherPackTag.PolicyTags.MaxIP,
            SoftEtherPackTag.PolicyTags.MaxUpload,
            SoftEtherPackTag.PolicyTags.MaxDownload,
            SoftEtherPackTag.PolicyTags.MultiLogins,

            SoftEtherPackTag.PolicyTags.RSandRAFilter,
            SoftEtherPackTag.PolicyTags.RAFilter,
            SoftEtherPackTag.PolicyTags.DHCPv6Filter,
            SoftEtherPackTag.PolicyTags.DHCPv6NoServer,
            SoftEtherPackTag.PolicyTags.NoRoutingV6,
            SoftEtherPackTag.PolicyTags.CheckIPv6,
            SoftEtherPackTag.PolicyTags.NoServerV6,
            SoftEtherPackTag.PolicyTags.NoSavePassword,
            SoftEtherPackTag.PolicyTags.FilterIPv4,
            SoftEtherPackTag.PolicyTags.FilterIPv6,
            SoftEtherPackTag.PolicyTags.FilterNonIP,
            SoftEtherPackTag.PolicyTags.NoIPv6DefaultRouterInRA,
            SoftEtherPackTag.PolicyTags.NoIPv6DefaultRouterInRAWhenIPv6,

            SoftEtherPackTag.PolicyTags.MaxIPv6,
            SoftEtherPackTag.PolicyTags.AutoDisconnect,
            SoftEtherPackTag.PolicyTags.VLanId,

            SoftEtherPackTag.PolicyTags.Ver3
        ]
}
