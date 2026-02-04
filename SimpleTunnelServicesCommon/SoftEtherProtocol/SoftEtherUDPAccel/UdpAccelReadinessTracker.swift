//
//  UdpAccelReadinessTracker.swift
//  SimpleTunnel
//

/// SoftEther-compatible readiness/tick tracker for UDPAccel.
/// Owns only timing + tick/window logic. 
struct UdpAccelReadinessTracker {

    // MARK: - Constants (SoftEther)

    struct Const {
        static let windowSizeMs: UInt64 = 30_000       // UDP_ACCELERATION_WINDOW_SIZE_MSEC
        static let requireContinuousMs: UInt64 = 10_000 // UDP_ACCELERATION_REQUIRE_CONTINUOUS
        static let keepAliveTimeoutMs: UInt64 = 9_000   // UDP_ACCELERATION_KEEPALIVE_TIMEOUT
        static let keepAliveTimeoutFastMs: UInt64 = 2_100 // UDP_ACCELERATION_KEEPALIVE_TIMEOUT_FAST
    }

    // MARK: - Config

    private(set) var fastDisconnectDetect: Bool = false

    // MARK: - Tick state

    /// Last "yourTick" value received from the peer (ACK of our tick)
    private(set) var lastRecvMyTick: UInt64 = 0

    /// Last "myTick" value received from the server (ACKed back in outgoing packets)
    private(set) var lastReceivedServerTick: UInt64 = 0

    /// For diagnostics
    private(set) var lastReceivedAtMs: UInt64 = 0

    // MARK: - Readiness window state (UdpAccelIsSendReady behavior)

    /// Time when we last observed a "valid" receive for readiness purposes
    private var lastRecvTickForReadyMs: UInt64 = 0

    /// Time when we first entered a stable receive state
    private var firstStableReceiveTickMs: UInt64 = 0

    // MARK: - Endpoint pinning anti-stale helper

    /// Prevents endpoint pinning on stale packets
    private(set) var lastSetSrcEndpointTick: UInt64 = 0

    // MARK: - Lifecycle

    mutating func reset(fastDisconnectDetect: Bool) {
        self.fastDisconnectDetect = fastDisconnectDetect

        self.lastRecvMyTick = 0
        self.lastReceivedServerTick = 0
        self.lastReceivedAtMs = 0

        self.lastRecvTickForReadyMs = 0
        self.firstStableReceiveTickMs = 0

        self.lastSetSrcEndpointTick = 0
    }

    // MARK: - Packet processing

    enum PacketVerdict {
        /// Drop this packet (out of window / stale).
        case drop

        /// Accept this packet. `shouldPinEndpoint` tells caller whether it may update pinned endpoint using packet source.
        case accept(shouldPinEndpoint: Bool)
    }

    /// Call after decrypt + header parse (ticks already extracted).
    mutating func onDecryptedPacket(myTickFromPeer: UInt64,
                                   yourTickAckFromPeer: UInt64,
                                   nowMs: UInt64) -> PacketVerdict {
        // Anti-replay / out-of-window:
        // If peer's myTick is too far behind our last seen myTick, drop.
        if myTickFromPeer < lastReceivedServerTick {
            let delta = lastReceivedServerTick &- myTickFromPeer
            if delta >= Const.windowSizeMs {
                return .drop
            }
        }

        // Update tick state
        lastReceivedServerTick = max(lastReceivedServerTick, myTickFromPeer)
        lastRecvMyTick = max(lastRecvMyTick, yourTickAckFromPeer)
        lastReceivedAtMs = nowMs

        // "Ready" tracking:
        // Update LastRecvTick only if we have an ACK for our tick and the ACK is within the sliding window.
        if lastRecvMyTick != 0, lastRecvMyTick &+ Const.windowSizeMs >= nowMs {
            lastRecvTickForReadyMs = nowMs
            if firstStableReceiveTickMs == 0 {
                firstStableReceiveTickMs = nowMs
            }
        }

        // Endpoint pinning should be allowed only for fresh ticks
        let shouldPin = (lastSetSrcEndpointTick < lastReceivedServerTick)
        if shouldPin {
            lastSetSrcEndpointTick = lastReceivedServerTick
        }

        return .accept(shouldPinEndpoint: shouldPin)
    }

    // MARK: -
    
    /// Call this when you detect keepalive timeout and want SoftEther-like behavior:
    /// reset stability window so next time requires continuous receive again.
    mutating func onKeepAliveTimeout() {
        firstStableReceiveTickMs = 0
    }
    
    mutating func isReadyAndApplyTimeoutSideEffects(nowMs: UInt64) -> Bool {
        let timeoutMs: UInt64 = fastDisconnectDetect ? Const.keepAliveTimeoutFastMs : Const.keepAliveTimeoutMs
        guard lastRecvTickForReadyMs != 0 else {
            return false
        }
        if nowMs > (lastRecvTickForReadyMs &+ timeoutMs) {
            firstStableReceiveTickMs = 0
            return false
        }
        guard firstStableReceiveTickMs != 0 else {
            return false
        }
        guard nowMs >= (firstStableReceiveTickMs &+ Const.requireContinuousMs) else {
            return false
        }
        return true
    }
}
