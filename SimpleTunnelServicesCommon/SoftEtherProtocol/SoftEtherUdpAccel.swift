//
//  SoftEtherUdpAccel.swift
//  SimpleTunnel
//

import Foundation
import Security
import CryptoKit
import OSLog

/// Minimal UDP Acceleration implementation (UDPAccel v2 only)
final class SoftEtherUdpAccel {

    // MARK: - Public state
    
    public enum State: String {
        case idle
        case preflight
        case running
    }
    
    // MARK: - Keys (generated once per instance)

    private lazy var keyV2: Data = {
        var data = Data(count: 128) // UDP_ACCELERATION_COMMON_KEY_SIZE_V2
        let count = data.count
        let rc = data.withUnsafeMutableBytes { buf -> Int32 in
            guard let base = buf.baseAddress else {
                return errSecParam
            }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        precondition(rc == errSecSuccess, "SecRandomCopyBytes failed: \(rc)")
        return data
    }()

    private lazy var keyV1: Data = {
        var data = Data(count: 20) // UDP_ACCELERATION_COMMON_KEY_SIZE_V1
        let count = data.count
        let rc = data.withUnsafeMutableBytes { buf -> Int32 in
            guard let base = buf.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        precondition(rc == errSecSuccess, "SecRandomCopyBytes failed: \(rc)")
        return data
    }()

    // MARK: -

    typealias FrameHandler = (_ frame: Data, _ flag: UInt8) -> Void
    var onFrame: FrameHandler?

    public var isDataPathReady: Bool {
        if DispatchQueue.getSpecific(key: Self.ioQueueKey) == Self.ioQueueValue {
            return isSendReadyLocked(checkKeepAlive: true)
        } else {
            return ioQueue.sync { isSendReadyLocked(checkKeepAlive: true) }
        }
    }

    var clientPort: UInt16 { localPort }
    var clientKeyV1: Data { keyV1 }
    var clientKeyV2: Data { keyV2 }

    /// 4 bytes IPv4 (network byte order)
    var localIPv4Data: Data {
        var s = localIPv4.s_addr
        return Data(bytes: &s, count: 4)
    }

    // MARK: - Private state
    
    public private(set) var state: State = .idle
    
    private(set) var localPort: UInt16 = 0
    private(set) var localIPv4: in_addr = in_addr(s_addr: INADDR_ANY)
    
    private var socketFD: Int32 = -1
    private var routeProbeServerAddr4: sockaddr_in?
    
    // Cookies:
    // - Incoming packets must have cookie == clientCookie
    // - Outgoing packets must have cookie == serverCookie
    private var clientCookie: UInt32 = 0
    private var serverCookie: UInt32 = 0
    
    // MARK: -
    private var lastImmediateAckAtMs: UInt64 = 0

    // Diagnostics
    private var sentKeepAliveCount: UInt64 = 0
    private var sentPacketCount: UInt64 = 0
    private var recvOkCount: UInt64 = 0
    private var recvDecryptFailCount: UInt64 = 0
    private var recvCookieMismatchCount: UInt64 = 0
    private var lastStatsLogAtMs: UInt64 = 0
    
    private var recvPosixErrorCount: UInt64 = 0
    private var lastRecvPosixErrorLogAtMs: UInt64 = 0

    // MARK: -
    private var readiness = UdpAccelReadinessTracker()
    private var endpoints = UdpAccelEndpointManager()
    
    private var sendCrypto = UdpAccelCryptoBoxV2Send()
    private var recvCrypto = UdpAccelCryptoBoxV2Recv()
    
    private let ioQueue = DispatchQueue(label: "SoftEtherUdpAccel.IO", qos: .userInitiated)
    private var isStopping = false

    private var readSource: DispatchSourceRead?
    private var recvBuf = [UInt8](repeating: 0, count: 65_535)
    
    private var keepAliveTimer: DispatchSourceTimer?
    
    private static let logger = LoggerService.vpnext
    
    private static let ioQueueKey = DispatchSpecificKey<UInt8>()
    private static let ioQueueValue: UInt8 = 1

    init() {
        ioQueue.setSpecific(key: Self.ioQueueKey, value: Self.ioQueueValue)
    }
    
    deinit {
        closeSync()
    }

    // MARK: - Socket lifecycle

    /// Bind a UDP socket to 0.0.0.0:0 and infer the outbound interface by "connecting" to `routeProbeHost:routeProbePort`
    func prepareForHandshake(routeProbeHost host: String, routeProbePort port: UInt16, bindIPv4: in_addr = in_addr(s_addr: INADDR_ANY)) throws {
        try onIOQueueSync {
            try prepareForHandshakeLocked(routeProbeHost: host, routeProbePort: port, bindIPv4: bindIPv4)
        }
    }
    private func prepareForHandshakeLocked(routeProbeHost host: String, routeProbePort port: UInt16, bindIPv4: in_addr = in_addr(s_addr: INADDR_ANY)) throws {
        assertOnIOQueue()

#if DEBUG
        if state == .idle {
            precondition(socketFD < 0 && readSource == nil && keepAliveTimer == nil, "idle invariant violated")
        }
#endif
        
        guard state == .idle else {
            throw SoftEtherError("SoftEtherUdpAccel.prepareForHandshake: bad state: \(state)")
        }
        
        guard socketFD < 0 else {
            throw SoftEtherError("socket already opened")
        }
        
        isStopping = false

        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else {
            throw posix("socket")
        }
        
        let flags = fcntl(fd, F_GETFL, 0)
        if flags < 0 {
            Darwin.close(fd)
            throw posix("fcntl(F_GETFL)")
        }

        if fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 {
            Darwin.close(fd)
            throw posix("fcntl(F_SETFL, O_NONBLOCK)")
        }

        // bind 0.0.0.0:0
        var bindAddr = sockaddr_in()
        bindAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        bindAddr.sin_family = sa_family_t(AF_INET)
        bindAddr.sin_port = in_port_t(0).bigEndian
        bindAddr.sin_addr = bindIPv4

        let bindResult: Int32 = withUnsafePointer(to: &bindAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            Darwin.close(fd)
            throw posix("bind")
        }

        var remoteIP = in_addr()
        if inet_aton(host, &remoteIP) == 0 {
            Darwin.close(fd)
            throw SoftEtherError("SoftEtherUdpAccel.prepareForHandshake: routeProbeHost must be IPv4 dotted-quad (no DNS/IPv6 yet)")
        }

        var remote = sockaddr_in()
        remote.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        remote.sin_family = sa_family_t(AF_INET)
        remote.sin_port = port.bigEndian
        remote.sin_addr = remoteIP

        self.routeProbeServerAddr4 = remote

        let connectResult: Int32 = withUnsafePointer(to: &remote) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connectResult == 0 else {
            Darwin.close(fd)
            throw posix("connect(udp)")
        }

        // getsockname -> local ip + local port
        var out = sockaddr_in()
        var outLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        let getSocketNameResult: Int32 = withUnsafeMutablePointer(to: &out) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.getsockname(fd, $0, &outLen)
            }
        }
        guard getSocketNameResult == 0 else {
            Darwin.close(fd)
            throw posix("getsockname")
        }

        self.socketFD = fd
        self.localPort = UInt16(bigEndian: out.sin_port)
        self.localIPv4 = out.sin_addr
        self.state = .preflight

        // Disconnect the UDP socket so we can receive from any source endpoint
        // This keeps route inference (probe connect) while allowing recvfrom() to observe the real server endpoint
        var unspec = sockaddr()
        unspec.sa_len = UInt8(MemoryLayout<sockaddr>.size)
        unspec.sa_family = sa_family_t(AF_UNSPEC)
        _ = withUnsafePointer(to: &unspec) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr>.size))
            }
        }
    }

    func close() {
        ioQueue.async { [weak self] in
            guard let self else {
                return
            }
            self.closeLocked()
        }
    }
    
    func closeSync() {
        if DispatchQueue.getSpecific(key: Self.ioQueueKey) == Self.ioQueueValue {
            closeLocked()
        } else {
            ioQueue.sync(execute: closeLocked)
        }
    }
    
    private func closeLocked() {
        assertOnIOQueue()
        _stopLocked()
        state = .idle
    }

    // MARK: - UDPAccel configuration

    /// Configure UDPAccel parameters from server Welcome pack and start background receive + keepalive
    /// Supports UDPAccel v2 only
    func start(using welcome: SoftEtherSessionUDPParams) throws {
        try onIOQueueSync {
            try startLocked(using: welcome)
        }
    }

    private func startLocked(using welcome: SoftEtherSessionUDPParams) throws {
        assertOnIOQueue()

        guard !isStopping else {
            throw SoftEtherError("UDPAccel is stopping")
        }
        
        SoftEtherUdpAccel.logger.both(.info, "[UDPAccel] start(using:): begin")

        guard state == .preflight else {
            SoftEtherUdpAccel.logger.both(.error, "[UDPAccel] rejected: bad state for start(using:): \(self.state.rawValue)")
            throw SoftEtherError("UDPAccel start(using:) called in bad state: \(state)")
        }

        guard socketFD >= 0 else {
            SoftEtherUdpAccel.logger.both(.error, "[UDPAccel] rejected: socket not opened (call prepareForHandshake before start)")
            throw SoftEtherError("UDPAccel socket is not open")
        }

        SoftEtherUdpAccel.logger.both(.info, """
        [UDPAccel] welcome params:
          useUDPAccel=\(welcome.useUDPAccel)
          version=\(welcome.version)
          fastDisconnectDetect=\(welcome.fastDisconnectDetect)
          serverIP32=\(welcome.serverIP.map { "0x" + String($0, radix: 16) } ?? "nil")
          serverPort=\(welcome.serverPort.map(String.init) ?? "nil")
          serverKeyV2.bytes=\(welcome.serverKeyV2?.count ?? 0)
          serverCookie.present=\((welcome.serverCookie ?? 0) != 0)
          clientCookie.present=\((welcome.clientCookie ?? 0) != 0)
        """)

        guard welcome.useUDPAccel else {
            SoftEtherUdpAccel.logger.both(.error, "[UDPAccel] rejected: UDP acceleration disabled in welcome")
            throw SoftEtherError("UDP acceleration disabled in welcome")
        }
        guard welcome.version >= 2 else {
            SoftEtherUdpAccel.logger.both(.error, "[UDPAccel] rejected: UDPAccel v1 is not supported (version=\(welcome.version))")
            throw SoftEtherError("UDPAccel v1 is not supported by this implementation yet")
        }

        let serverIP32: UInt32 = welcome.serverIP ?? 0

        guard let serverPortU32 = welcome.serverPort, serverPortU32 > 0, serverPortU32 <= UInt32(UInt16.max) else {
            SoftEtherUdpAccel.logger.both(.error, "[UDPAccel] rejected: missing/invalid udp_acceleration_server_port (value=\(welcome.serverPort.map(String.init) ?? "nil"))")
            throw SoftEtherError("Welcome: missing/invalid udp_acceleration_server_port")
        }

        guard let serverCookie = welcome.serverCookie, serverCookie != 0 else {
            SoftEtherUdpAccel.logger.both(.error, "[UDPAccel] rejected: missing udp_acceleration_server_cookie")
            throw SoftEtherError("Welcome: missing udp_acceleration_server_cookie")
        }
        guard let clientCookie = welcome.clientCookie, clientCookie != 0 else {
            SoftEtherUdpAccel.logger.both(.error, "[UDPAccel] rejected: missing udp_acceleration_client_cookie")
            throw SoftEtherError("Welcome: missing udp_acceleration_client_cookie")
        }
        guard let serverKeyV2 = welcome.serverKeyV2, serverKeyV2.count >= 32 else {
            SoftEtherUdpAccel.logger.both(.error, "[UDPAccel] rejected: missing/short udp_acceleration_server_key_v2 (bytes=\(welcome.serverKeyV2?.count ?? 0))")
            throw SoftEtherError("Welcome: missing udp_acceleration_server_key_v2")
        }

        SoftEtherUdpAccel.logger.both(.info, "[UDPAccel] welcome validated: v2 OK, ip/port/cookies/keys present")

        readiness.reset(fastDisconnectDetect: welcome.fastDisconnectDetect)
        endpoints.reset()

        // Determine server IPv4 (route-probe fallback)
        let serverIPv4: in_addr
        if serverIP32 != 0 {
            serverIPv4 = in_addr(s_addr: serverIP32)
        } else if let rp = routeProbeServerAddr4 {
            serverIPv4 = rp.sin_addr
        } else {
            throw SoftEtherError("Welcome: missing udp_acceleration_server_ip (IPv4) and no route-probe fallback")
        }

        let serverPort = UInt16(serverPortU32)

        // Configure endpoint candidates
        endpoints.setConfigured(ip: serverIPv4, port: serverPort)
        if serverIP32 != 0 {
            endpoints.setReported(ip: in_addr(s_addr: serverIP32), port: serverPort)
        }

        // Log resolved peer
        var ipStr = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        var tmpAddr = serverIPv4
        inet_ntop(AF_INET, &tmpAddr, &ipStr, socklen_t(INET_ADDRSTRLEN))
        let ipPrintable = String(cString: ipStr)
        SoftEtherUdpAccel.logger.both(.info, "[UDPAccel] peer resolved: \(ipPrintable):\(serverPort)")

        // Store cookies
        self.serverCookie = serverCookie
        self.clientCookie = clientCookie
        SoftEtherUdpAccel.logger.both(.info, "[UDPAccel] cookies set (peerCookie/clientCookie present)")

        // Configure cryptoBox (send uses client's keyV2, recv uses server's keyV2)
        let sendKey = SymmetricKey(data: keyV2.prefix(32))
        let recvKey = SymmetricKey(data: serverKeyV2.prefix(32))

        var initialNonce = Data(count: 12)
        let rc = initialNonce.withUnsafeMutableBytes { buf -> Int32 in
            guard let base = buf.baseAddress else {
                return errSecParam
            }
            return SecRandomCopyBytes(kSecRandomDefault, 12, base)
        }
        precondition(rc == errSecSuccess, "SecRandomCopyBytes failed: \(rc)")

        try sendCrypto.reset(sendKey: sendKey, initialNonce: initialNonce)
        recvCrypto.reset(recvKey: recvKey)
        
        SoftEtherUdpAccel.logger.both(.info, "[UDPAccel] crypto configured (ChaCha20-Poly1305 v2), nonce initialized")

        // Start I/O
        SoftEtherUdpAccel.logger.both(.info, "[UDPAccel] starting background receive + keepalive (fast=\(welcome.fastDisconnectDetect))")
        startIO(keepAliveFast: welcome.fastDisconnectDetect)

        SoftEtherUdpAccel.logger.both(.info, "[UDPAccel] start() returned; sending initial keep-alive")
        sendKeepAliveLocked()

        SoftEtherUdpAccel.logger.info("[UDPAccel] start(using:): done")
    }

    // MARK: - Start/stop

    private func startIO(keepAliveFast: Bool) {
        assertOnIOQueue()
        
        guard socketFD >= 0 else {
            SoftEtherUdpAccel.logger.both(.error, "[UDPAccel] startIO called before socket is opened")

            return
        }

        guard state == .preflight else {
            return
        }

        state = .running

        startReadingSocket()
        startKeepAliveTimer(keepAliveFast: keepAliveFast)
    }

    private func startReadingSocket() {
        guard socketFD >= 0 else {
            Self.logger.both(.error, "[UDPAccel] startReadingSocket called before start")
            return
        }
        guard readSource == nil else {
            return
        }

        let source = DispatchSource.makeReadSource(fileDescriptor: socketFD, queue: ioQueue)
        source.setEventHandler { [weak self] in
            self?.drainSocketLocked()
        }
        readSource = source
        source.resume()
    }

    private func startKeepAliveTimer(keepAliveFast: Bool) {
        guard keepAliveTimer == nil else {
            return
        }

        let timer = DispatchSource.makeTimerSource(queue: ioQueue)

        func scheduleNext() {
            let baseMs = keepAliveFast ? 700 : 1500
            let jitterMs = Int.random(in: 0...800)
            timer.schedule(deadline: .now() + .milliseconds(baseMs + jitterMs), repeating: .never, leeway: .milliseconds(50))
        }

        timer.setEventHandler { [weak self] in
            guard let self else {
                return
            }
            self.sendKeepAliveLocked()
            scheduleNext()
        }

        keepAliveTimer = timer
        scheduleNext()
        timer.resume()
    }

    func stop() {
        ioQueue.async { [weak self] in
            self?._stopLocked()
        }
    }
    
    private func _stopLocked() {
        assertOnIOQueue()
        
        if isStopping {
            return
        }
        isStopping = true
        defer {
            isStopping = false
        }

        // Tear down timers/sources first
        if let timer = keepAliveTimer {
            keepAliveTimer = nil
            timer.setEventHandler {}
            timer.setCancelHandler {}
            timer.cancel()
        }
        
        if let source = readSource {
            readSource = nil
            source.setEventHandler {}
            source.setCancelHandler {}
            source.cancel()
        }

        // Close FD once
        if socketFD >= 0 {
            Darwin.close(socketFD)
            socketFD = -1
        }

        // Reset derived state that is only valid while running/preflight
        routeProbeServerAddr4 = nil
        clientCookie = 0
        serverCookie = 0

        state = .idle
    }

    // MARK: - SoftEther-compatible readiness

    private func isSendReadyLocked(checkKeepAlive: Bool) -> Bool {
        assertOnIOQueue()
        
        guard state == .running else {
            return false
        }
        guard socketFD >= 0 else {
            return false
        }

        guard sendCrypto.sendKey != nil, recvCrypto.recvKey != nil else {
            return false
        }

        guard serverCookie != 0, clientCookie != 0 else {
            return false
        }

        guard UdpAccelEndpointManager.isValid(endpoints.configured) else {
            return false
        }
        
        guard endpoints.isPinnedValid() else {
            return false
        }

        if checkKeepAlive {
            let nowMs = SoftEtherUdpAccel.nowMs()
            guard readiness.isReadyAndApplyTimeoutSideEffects(nowMs: nowMs) else {
                return false
            }
        }

        return true
    }


    // MARK: - Sending

    func sendFrame(_ ethernetFrame: Data, flag: UInt8 = 0) {
        ioQueue.async { [weak self] in
            self?.sendLocked(payload: ethernetFrame, flag: flag, isKeepAlive: false)
        }
    }

    func sendKeepAlive() {
        ioQueue.async { [weak self] in
            self?.sendKeepAliveLocked()
        }
    }
    
    private func sendKeepAliveLocked() {
        assertOnIOQueue()
        sendLocked(payload: Data(), flag: 0, isKeepAlive: true)
    }
    
    private func sendLocked(payload: Data, flag: UInt8, isKeepAlive: Bool) {
        assertOnIOQueue()
        
        guard !isStopping else {
            return
        }
        guard self.state == .running else {
            return
        }
        guard socketFD >= 0 else {
            SoftEtherUdpAccel.logger.both(.error, "[UDPAccel] socket is not open")
            return
        }   
        guard sendCrypto.sendKey != nil else {
            SoftEtherUdpAccel.logger.both(.error, "[UDPAccel] sendCrypto not configured")
            return
        }
        guard serverCookie != 0 else {
            SoftEtherUdpAccel.logger.both(.error, "[UDPAccel] serverCookie is not configured")
            return
        }

        do {
            let nowMs = SoftEtherUdpAccel.nowMs()
            let myTick = nowMs == 0 ? 1 : nowMs
            let yourTick = readiness.lastReceivedServerTick
            
            let plain = try UdpAccelPacketCodec.encode(cookie: serverCookie, myTick: myTick, yourTick: yourTick, flag: flag, payload: payload)
            
            // Encrypt (ChaCha20-Poly1305)
            let packet = try sendCrypto.seal(plain)
            
            let primaryDst = endpoints.primaryDestination()
            
            let isReadyForKeepAlive: Bool = isKeepAlive ? isSendReadyLocked(checkKeepAlive: true) : true
            
            let dstStr = SoftEtherUdpAccel.formatIPv4Endpoint(primaryDst)
            
            SoftEtherUdpAccel.logger.debugIfDebugBuild("[UDPAccel] send: dst=\(dstStr) pinned=\(endpoints.hasPinned) myTick=\(nowMs == 0 ? 1 : nowMs) yourTick(ack)=\(readiness.lastReceivedServerTick) innerSize=\(payload.count) flag=\(flag) ready=\(isReadyForKeepAlive)")
            
            // Primary destination must succeed
            try sendPacketLocked(packet, dst: primaryDst, isPrimary: true)
            
            // Alternative destinations: only for keep-alives and only when not ready
            if isKeepAlive, !isReadyForKeepAlive {
                for dst in endpoints.keepAliveFallbackDestinations(excluding: primaryDst) {
                    try? sendPacketLocked(packet, dst: dst, isPrimary: false)
                }
            }
            
            sentPacketCount &+= 1
            if isKeepAlive {
                sentKeepAliveCount &+= 1
                logStatsIfNeededLocked()
            }
        } catch {
            Self.logger.both(.error, "[UDPAccel] send failed: \(String(describing: error))")
        }
    }
    
    private func sendPacketLocked(_ packet: Data, dst: sockaddr_in, isPrimary: Bool) throws {
        assertOnIOQueue()

        var dstCopy = dst
        let rc = packet.withUnsafeBytes { buf -> Int in
            guard let base = buf.baseAddress else { return -1 }
            return withUnsafePointer(to: &dstCopy) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.sendto(self.socketFD, base, buf.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }

        if rc < 0 {
            if isPrimary { throw posix("sendto(udp)") }
            let dstStr = Self.formatIPv4Endpoint(dstCopy)
            Self.logger.both(.error, "[UDPAccel] keepalive alt-dst send failed: dst=\(dstStr) errno=\(errno)")
        }
    }


    // MARK: - Receiving

    private func drainSocketLocked() {
        assertOnIOQueue()
        
        if isStopping {
            return
        }
        
        while true {
            var src = sockaddr_storage()
            var srcLen = socklen_t(MemoryLayout<sockaddr_storage>.size)

            let n: Int = recvBuf.withUnsafeMutableBytes { bufPtr in
                guard let base = bufPtr.baseAddress else {
                    return -1
                }

                return withUnsafeMutablePointer(to: &src) { srcPtr in
                    srcPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                        Darwin.recvfrom(self.socketFD, base, bufPtr.count, 0, saPtr, &srcLen)
                    }
                }
            }

            if n > 0 {
                let packet = Data(recvBuf.prefix(n))
                processIncomingLocked(packet, source: src)
                continue
            }

            if n == 0 {
                break
            }

            let savedErrorno = errno
            if savedErrorno == EINTR {
                continue
            }
            
            // n < 0
            if savedErrorno == EWOULDBLOCK || savedErrorno == EAGAIN {
                break
            }
            
            recvPosixErrorCount &+= 1

            let now = SoftEtherUdpAccel.nowMs()
            if now &- lastRecvPosixErrorLogAtMs >= 5_000 {
                lastRecvPosixErrorLogAtMs = now
                SoftEtherUdpAccel.logger.both(.error,"[UDPAccel] recvfrom failed: errno=\(savedErrorno) \(String(cString: strerror(savedErrorno))) count=\(self.recvPosixErrorCount)")
            }

            break
        }
    }

    private func processIncomingLocked(_ packet: Data, source: sockaddr_storage) {
        assertOnIOQueue()
        
        if isStopping {
            return
        }
        
        guard packet.count >= UdpAccelCryptoBoxV2.wireOverhead + UdpAccelPacketCodec.minSize else {
            return
        }
        
        do {
            let plain = try recvCrypto.open(packet)
            if let innerSize = parseAndApplyPlainLocked(plain, source: source) {
                if innerSize == 0 {
                    immediateSendAckIfNeededLocked()
                }
            }
        } catch {
            recvDecryptFailCount &+= 1
        }
    }

    private func parseAndApplyPlainLocked(_ plain: Data, source: sockaddr_storage) -> UInt16? {
        assertOnIOQueue()
        
        let hdr: UdpAccelPacketCodec.Header
        do {
            hdr = try UdpAccelPacketCodec.decode(plain)
        } catch {
            return nil
        }

        guard hdr.cookie == clientCookie else {
            recvCookieMismatchCount &+= 1
            return nil
        }

        let myTick = hdr.myTick
        let yourTick = hdr.yourTick
        let flag = hdr.flag
        let payload = hdr.payload
        let size = payload.count

        let nowMs = Self.nowMs()
        switch readiness.onDecryptedPacket(myTickFromPeer: myTick, yourTickAckFromPeer: yourTick, nowMs: nowMs) {
        case .drop:
            return nil
        case .accept(let shouldPin):
            recvOkCount &+= 1
            if shouldPin {
                endpoints.pin(from: source)
            }
        }
            
        let pinnedStr = endpoints.hasPinned ? SoftEtherUdpAccel.formatIPv4Endpoint(endpoints.pinned) : "<unpinned>"
        SoftEtherUdpAccel.logger.debugIfDebugBuild("[UDPAccel] recv: pinnedSrc=\(pinnedStr) myTick(fromPeer)=\(myTick) yourTick(ackFromPeer)=\(yourTick) innerSize=\(size) flag=\(flag)")

        if size > 0 {
            self.onFrame?(payload, flag)
        }

        return UInt16(size)
    }

    // MARK: - UDP keep-alive helpers

    private func immediateSendAckIfNeededLocked() {
    
        SoftEtherUdpAccel.logger.debugIfDebugBuild("[UDPAccel] recieved keep alive from server")
        
        let now = SoftEtherUdpAccel.nowMs()
        if now &- lastImmediateAckAtMs < 250 {
            return
        }

        lastImmediateAckAtMs = now
        sendKeepAliveLocked()
    }

    private func logStatsIfNeededLocked() {
        
        let now = SoftEtherUdpAccel.nowMs()
        if now &- lastStatsLogAtMs < 5000 {
            return
        }
        lastStatsLogAtMs = now

        let lastAt = readiness.lastReceivedAtMs
        let lastRecvAgo: UInt64 = lastAt == 0 ? 0 : (now &- lastAt)

        SoftEtherUdpAccel.logger.both(.info, "[UDPAccel] stats: sentKA=\(self.sentKeepAliveCount) sentPkt=\(self.sentPacketCount) recvOK=\(self.recvOkCount) decryptFail=\(self.recvDecryptFailCount) cookieMismatch=\(self.recvCookieMismatchCount) lastRecvAgoMs=\(lastRecvAgo)")
    }

    // MARK: - Helpers
    
    private func posix(_ op: String) -> Error {
        let e = errno
        return SoftEtherError("\(op) failed: errno=\(e) \(String(cString: strerror(e)))")
    }

    private static func nowMs() -> UInt64 {
        return UInt64(DispatchTime.now().uptimeNanoseconds / 1_000_000)
    }
    
    private func onIOQueueSync<T>(_ block: () throws -> T) rethrows -> T {
        if DispatchQueue.getSpecific(key: Self.ioQueueKey) == Self.ioQueueValue {
            return try block()
        } else {
            return try ioQueue.sync(execute: block)
        }
    }
    
    @inline(__always)
    private func assertOnIOQueue() {
#if DEBUG
        dispatchPrecondition(condition: .onQueue(ioQueue))
#endif
    }
    
    private static func formatIPv4Endpoint(_ addr: sockaddr_in) -> String {
        let adress_copy = addr
        var ipBuf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        var ip = adress_copy.sin_addr
        inet_ntop(AF_INET, &ip, &ipBuf, socklen_t(INET_ADDRSTRLEN))

        let ipStr = String(cString: ipBuf)
        let port = UInt16(bigEndian: adress_copy.sin_port)
        return "\(ipStr):\(port)"
    }
}

