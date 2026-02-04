//
//  SoftEtherPolice+Pack.swift
//  SimpleTunnel

extension SoftEtherPolicy {
    init(from pack: SoftEtherPack) {
        // Ver2 bools
        self.Access             = pack.bool(SoftEtherPackTag.PolicyTags.Access) ?? false
        self.DHCPFilter         = pack.bool(SoftEtherPackTag.PolicyTags.DHCPFilter) ?? false
        self.DHCPNoServer       = pack.bool(SoftEtherPackTag.PolicyTags.DHCPNoServer) ?? false
        self.DHCPForce          = pack.bool(SoftEtherPackTag.PolicyTags.DHCPForce) ?? false
        self.NoBridge           = pack.bool(SoftEtherPackTag.PolicyTags.NoBridge) ?? false
        self.NoRouting          = pack.bool(SoftEtherPackTag.PolicyTags.NoRouting) ?? false
        self.CheckMac           = pack.bool(SoftEtherPackTag.PolicyTags.CheckMac) ?? false
        self.CheckIP            = pack.bool(SoftEtherPackTag.PolicyTags.CheckIP) ?? false
        self.ArpDhcpOnly        = pack.bool(SoftEtherPackTag.PolicyTags.ArpDhcpOnly) ?? false
        self.PrivacyFilter      = pack.bool(SoftEtherPackTag.PolicyTags.PrivacyFilter) ?? false
        self.NoServer           = pack.bool(SoftEtherPackTag.PolicyTags.NoServer) ?? false
        self.NoBroadcastLimiter = pack.bool(SoftEtherPackTag.PolicyTags.NoBroadcastLimiter) ?? false
        self.MonitorPort        = pack.bool(SoftEtherPackTag.PolicyTags.MonitorPort) ?? false
        self.FixPassword        = pack.bool(SoftEtherPackTag.PolicyTags.FixPassword) ?? false
        self.NoQoS              = pack.bool(SoftEtherPackTag.PolicyTags.NoQoS) ?? false

        // Ver2 uints
        self.MaxConnection = pack.u32(SoftEtherPackTag.PolicyTags.MaxConnection) ?? 0
        self.TimeOut       = pack.u32(SoftEtherPackTag.PolicyTags.TimeOut) ?? 0
        self.MaxMac        = pack.u32(SoftEtherPackTag.PolicyTags.MaxMac) ?? 0
        self.MaxIP         = pack.u32(SoftEtherPackTag.PolicyTags.MaxIP) ?? 0
        self.MaxUpload     = pack.u32(SoftEtherPackTag.PolicyTags.MaxUpload) ?? 0
        self.MaxDownload   = pack.u32(SoftEtherPackTag.PolicyTags.MaxDownload) ?? 0
        self.MultiLogins   = pack.u32(SoftEtherPackTag.PolicyTags.MultiLogins) ?? 0

        // Ver3 bools
        self.RSandRAFilter                 = pack.bool(SoftEtherPackTag.PolicyTags.RSandRAFilter) ?? false
        self.RAFilter                      = pack.bool(SoftEtherPackTag.PolicyTags.RAFilter) ?? false
        self.DHCPv6Filter                  = pack.bool(SoftEtherPackTag.PolicyTags.DHCPv6Filter) ?? false
        self.DHCPv6NoServer                = pack.bool(SoftEtherPackTag.PolicyTags.DHCPv6NoServer) ?? false
        self.NoRoutingV6                   = pack.bool(SoftEtherPackTag.PolicyTags.NoRoutingV6) ?? false
        self.CheckIPv6                     = pack.bool(SoftEtherPackTag.PolicyTags.CheckIPv6) ?? false
        self.NoServerV6                    = pack.bool(SoftEtherPackTag.PolicyTags.NoServerV6) ?? false
        self.NoSavePassword                = pack.bool(SoftEtherPackTag.PolicyTags.NoSavePassword) ?? false
        self.FilterIPv4                    = pack.bool(SoftEtherPackTag.PolicyTags.FilterIPv4) ?? false
        self.FilterIPv6                    = pack.bool(SoftEtherPackTag.PolicyTags.FilterIPv6) ?? false
        self.FilterNonIP                   = pack.bool(SoftEtherPackTag.PolicyTags.FilterNonIP) ?? false
        self.NoIPv6DefaultRouterInRA       = pack.bool(SoftEtherPackTag.PolicyTags.NoIPv6DefaultRouterInRA) ?? false
        self.NoIPv6DefaultRouterInRAWhenIPv6 = pack.bool(SoftEtherPackTag.PolicyTags.NoIPv6DefaultRouterInRAWhenIPv6) ?? false

        // Ver3 uints
        self.MaxIPv6        = pack.u32(SoftEtherPackTag.PolicyTags.MaxIPv6) ?? 0
        self.AutoDisconnect = pack.u32(SoftEtherPackTag.PolicyTags.AutoDisconnect) ?? 0
        self.VLanId         = pack.u32(SoftEtherPackTag.PolicyTags.VLanId) ?? 0

        // Ver3 flag
        self.Ver3 = pack.bool(SoftEtherPackTag.PolicyTags.Ver3) ?? false
    }

    func add(into pack: inout SoftEtherPack) {
        // Ver2 bools
        pack.addBool(SoftEtherPackTag.PolicyTags.Access, Access)
        pack.addBool(SoftEtherPackTag.PolicyTags.DHCPFilter, DHCPFilter)
        pack.addBool(SoftEtherPackTag.PolicyTags.DHCPNoServer, DHCPNoServer)
        pack.addBool(SoftEtherPackTag.PolicyTags.DHCPForce, DHCPForce)
        pack.addBool(SoftEtherPackTag.PolicyTags.NoBridge, NoBridge)
        pack.addBool(SoftEtherPackTag.PolicyTags.NoRouting, NoRouting)
        pack.addBool(SoftEtherPackTag.PolicyTags.CheckMac, CheckMac)
        pack.addBool(SoftEtherPackTag.PolicyTags.CheckIP, CheckIP)
        pack.addBool(SoftEtherPackTag.PolicyTags.ArpDhcpOnly, ArpDhcpOnly)
        pack.addBool(SoftEtherPackTag.PolicyTags.PrivacyFilter, PrivacyFilter)
        pack.addBool(SoftEtherPackTag.PolicyTags.NoServer, NoServer)
        pack.addBool(SoftEtherPackTag.PolicyTags.NoBroadcastLimiter, NoBroadcastLimiter)
        pack.addBool(SoftEtherPackTag.PolicyTags.MonitorPort, MonitorPort)
        pack.addBool(SoftEtherPackTag.PolicyTags.FixPassword, FixPassword)
        pack.addBool(SoftEtherPackTag.PolicyTags.NoQoS, NoQoS)

        // Ver2 uints
        pack.addInt(SoftEtherPackTag.PolicyTags.MaxConnection, MaxConnection)
        pack.addInt(SoftEtherPackTag.PolicyTags.TimeOut, TimeOut)
        pack.addInt(SoftEtherPackTag.PolicyTags.MaxMac, MaxMac)
        pack.addInt(SoftEtherPackTag.PolicyTags.MaxIP, MaxIP)
        pack.addInt(SoftEtherPackTag.PolicyTags.MaxUpload, MaxUpload)
        pack.addInt(SoftEtherPackTag.PolicyTags.MaxDownload, MaxDownload)
        pack.addInt(SoftEtherPackTag.PolicyTags.MultiLogins, MultiLogins)

        // Ver3 bools
        pack.addBool(SoftEtherPackTag.PolicyTags.RSandRAFilter, RSandRAFilter)
        pack.addBool(SoftEtherPackTag.PolicyTags.RAFilter, RAFilter)
        pack.addBool(SoftEtherPackTag.PolicyTags.DHCPv6Filter, DHCPv6Filter)
        pack.addBool(SoftEtherPackTag.PolicyTags.DHCPv6NoServer, DHCPv6NoServer)
        pack.addBool(SoftEtherPackTag.PolicyTags.NoRoutingV6, NoRoutingV6)
        pack.addBool(SoftEtherPackTag.PolicyTags.CheckIPv6, CheckIPv6)
        pack.addBool(SoftEtherPackTag.PolicyTags.NoServerV6, NoServerV6)
        pack.addBool(SoftEtherPackTag.PolicyTags.NoSavePassword, NoSavePassword)
        pack.addBool(SoftEtherPackTag.PolicyTags.FilterIPv4, FilterIPv4)
        pack.addBool(SoftEtherPackTag.PolicyTags.FilterIPv6, FilterIPv6)
        pack.addBool(SoftEtherPackTag.PolicyTags.FilterNonIP, FilterNonIP)
        pack.addBool(SoftEtherPackTag.PolicyTags.NoIPv6DefaultRouterInRA, NoIPv6DefaultRouterInRA)
        pack.addBool(SoftEtherPackTag.PolicyTags.NoIPv6DefaultRouterInRAWhenIPv6, NoIPv6DefaultRouterInRAWhenIPv6)

        // Ver3 uints
        pack.addInt(SoftEtherPackTag.PolicyTags.MaxIPv6, MaxIPv6)
        pack.addInt(SoftEtherPackTag.PolicyTags.AutoDisconnect, AutoDisconnect)
        pack.addInt(SoftEtherPackTag.PolicyTags.VLanId, VLanId)

        // Ver3 flag
        pack.addBool(SoftEtherPackTag.PolicyTags.Ver3, Ver3)
    }
}
