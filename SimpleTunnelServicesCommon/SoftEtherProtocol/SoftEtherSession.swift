import Foundation
import NetworkExtension
import Network
import Security
import CryptoKit
import OSLog

public final class SoftEtherSession: NSObject {
    
    enum State {
        case idle
        case tlsHandshaking
        case softEtherHandshaking
        case established           // handshake done, ready for DHCP
        case tunneling             // pumps running
        case stopped(Error?)
    }
    
    // MARK: - Properties
    
    public let configuration: SoftEtherClientConfiguration
    public private(set) var networkParameters: SoftEtherNetworkParameters?
    private weak var packetTunnelProvider: NEPacketTunnelProvider?
    
    private var secureConnection: SecureTCPConnection?
    private let streamTCPParser = SoftEtherTCPStreamParser()
    
    private var udpConnection: SoftEtherUdpAccel?
    
    private(set) var state: State = .idle
    
    private let clientMac: MacAddress = MacAddress.randomClientMac()
    
    private var arpManager: SoftEtherARPManager?
    private var dhcpManager: DHCPManager?
    private var dhcpReadLoopActive = false
    
    private var keepAliveTimer: DispatchSourceTimer?
    private let queue = DispatchQueue(label: "com.softether.session", qos: .userInitiated)
    
    private static let logger = LoggerService.vpnext

    // MARK: - Ethernet frame send/receive

    private func sendRawEthernetFrameToServer(_ rawFrame: Data) {
        if self.state == .tunneling, let udp = self.udpConnection, udp.isDataPathReady {
            udp.sendFrame(rawFrame)
            return
        }

        guard let connection = self.secureConnection else {
            SoftEtherSession.logger.both(.error, "No secure connection to send frame")
            return
        }

        let wire = SoftEtherEthernetFrame.makeFrame(for: rawFrame)
        connection.send(data: wire) { error in
            if let error {
                SoftEtherSession.logger.both(.error, "Failed to send frame via TCP: \(error.localizedDescription)")
            }
        }
    }

    private func classifyIncomingEthernetFrameData(_ frame: Data) -> (Data, NSNumber)? {
        do {
            let ethernetFrame = try SoftEtherEthernetFrame.decode(frame)

            if let dhcpManager = self.dhcpManager {
                dhcpManager.processIncoming(frame: ethernetFrame)
            }

            switch ethernetFrame.type {
            case 0x0800: // IPv4
                return (ethernetFrame.payload, NSNumber(value: AF_INET))

            case 0x86DD: // IPv6
                return (ethernetFrame.payload, NSNumber(value: AF_INET6))

            case 0x0806: // ARP
                SoftEtherSession.logger.debugIfDebugBuild("🔶 ARP ethernet frame")
                if let arpManager = self.arpManager {
                    arpManager.processIncomingARP(ethernetFrame.payload)
                } else {
                    SoftEtherSession.logger.both(.error, "There isn't any ARP Manager to handle ARP frame.")
                }
                return nil

            default:
                SoftEtherSession.logger.debugIfDebugBuild("🚫 Unknow ethernet frame")
                return nil
            }
        } catch {
            SoftEtherSession.logger.both(.error, "Failed to decode SoftEtherEthernetFrame")
            return nil
        }
    }

    private func configureUdpDataPath(packetFlow: NEPacketTunnelFlow) {
        guard let udp = self.udpConnection else {
            return
        }

        let flow = packetFlow
        
        udp.onFrame = { [weak self] frame, flag in
            guard let self = self else {
                return
            }
            
            self.queue.async { [weak self] in
                guard let self else {
                    return
                }
#if DEBUG
                dispatchPrecondition(condition: .onQueue(self.queue))
#endif
                
                guard self.state == .tunneling else {
                    return
                }

                if let (payload, proto) = self.classifyIncomingEthernetFrameData(frame) {
                    flow.writePackets([payload], withProtocols: [proto])
                }
            }
        }
    }
    
    // MARK: - Init
    
    public init(provider: NEPacketTunnelProvider, configuration: SoftEtherClientConfiguration)
    {
        self.packetTunnelProvider = provider
        self.configuration = configuration
    }
    
    // MARK: - STEP 1 — TLS CONNECT
    
    public func connect(completion: @escaping (Result<Void, Error>) -> Void) {
        guard state == .idle else {
            completion(.failure(SoftEtherError("Bad state: \(state)")))
            return
        }
        
        state = .tlsHandshaking
        
        secureConnection = SecureTCPConnection(host: configuration.host, port: configuration.port)
        secureConnection?.connect { [weak self] success, error in
            guard let self else {
                return
            }
            
            if let error = error {
                self.state = .stopped(error)
                return completion(.failure(error))
            }
            
            if success {
                SoftEtherSession.logger.both(.default, "TLS connection established")
                completion(.success(()))
            } else {
                let err = SoftEtherError("TLS connection failed")
                self.state = .stopped(err)
                completion(.failure(err))
            }
        }
    }
    
    // MARK: - STEP 2 — PREPERING FOR SOFTETHER HANDSHAKE
    
    public func prepareForUDPAccelerationIfNeeded() {
        
        guard (configuration.enabledUDPAcceleration) else {
            SoftEtherSession.logger.both(.info, "Don't initiate UDP connection beacause UDP acceleration disabled in config.")
            return
        }
        
        let udpConnection = SoftEtherUdpAccel()
        do {
            try udpConnection.prepareForHandshake(routeProbeHost: configuration.host, routeProbePort: UInt16(configuration.port))
            self.udpConnection = udpConnection
            
            SoftEtherSession.logger.both(.default, "UDP preflight: localIP=\(udpConnection.localIPv4Data.hexDump()) port=\(udpConnection.localPort)")
        } catch {
            SoftEtherSession.logger.both(.error, "UDP preflight failed: \(error.localizedDescription)")
        }
    }
    
    // MARK: - STEP 2 — SOFTETHER HANDSHAKE
    
    public func handshake(using auth: SoftEtherAuthMethod, completion: @escaping (Result<SoftEtherSessionParams, Error>) -> Void) {
        guard state == .tlsHandshaking else {
            completion(.failure(SoftEtherError("Handshake in wrong state: \(state)")))
            return
        }
        
        state = .softEtherHandshaking
        
        prepareForUDPAccelerationIfNeeded()
        
        performSoftEtherHandshake(using: auth) { [weak self] result in
            guard let self else {
                return
            }
            
            switch result {
            case .success(let sessionParams):
                self.state = .established
                SoftEtherSession.logger.both(.default, "Successful Welcome response for session \(sessionParams.sessionName) with connection \(sessionParams.connectionName)")

                // UDP Acceleration: start minimal UDPAccel engine (keep-alive + decrypt).
                if let udpParams = sessionParams.udp, let udp = self.udpConnection {
                    do {
                        try udp.start(using: udpParams)
                        SoftEtherSession.logger.both(.default, "UDPAccel started: server=\(udpParams.serverAddressDescription):\(udpParams.serverPort ?? 0)")
                    } catch {
                        SoftEtherSession.logger.both(.error, "UDPAccel init failed: \(error.localizedDescription)")
                    }
                }

                completion(.success(sessionParams))
                
            case .failure(let err):
                self.state = .stopped(err)
                completion(.failure(err))
            }
        }
    }
    
    // MARK: - STEP 3 — DHCP
    
    public func obtainIPviaDHCP(completion: @escaping (Result<SoftEtherNetworkParameters, Error>) -> Void) {
        guard state == .established else {
            completion(.failure(SoftEtherError("DHCP in wrong state: \(state)")))
            return
        }
        
        let dhcpPManager = DHCPManager(myMac: clientMac, sendEthernetFrame: { [weak self] data in
            self?.sendRawEthernetFrameToServer(data)
        })
        dhcpManager = dhcpPManager
        
        startDhcpReadLoop()
        
        dhcpPManager.start { [weak self] result in
            guard let self else { return }
            
            self.dhcpReadLoopActive = false
            self.dhcpManager?.stop()
            
            switch result {
            case .success(let dhcpResult):
                SoftEtherSession.logger.both(.default, "DHCP manager success. Assigned adress is \(dhcpResult.addressString)")
                
                // Save numeric values for ARP routing
                let networkPararmeters = SoftEtherNetworkParameters(from: dhcpResult)
                self.networkParameters = networkPararmeters
                
                SoftEtherSession.logger.both(.default, "\(networkPararmeters.description)")
                completion(.success(networkPararmeters))
                
            case .failure(let error):
                SoftEtherSession.logger.error("DHCP manager failed to start. Error is \(error.localizedDescription, privacy: .public)")
                self.state = .stopped(error)
                completion(.failure(error))
            }
        }
    }
    
    // MARK: - STEP 4 — Start Pumps
    
    public func startTunneling() {
        guard let packetTunnelProvider = self.packetTunnelProvider else {
            SoftEtherSession.logger.both(.default, "There isn't any packet tunnel provider!")
            return
        }
        
        guard state == .established else {
            SoftEtherSession.logger.both(.default, "startTunneling in wrong state: \(self.state.description)")
            return
        }
        
        guard let networkParameters = self.networkParameters else {
            SoftEtherSession.logger.both(.default, "Can't start tunneling without received network parameters via DHCP manager.")
            return
        }
        
        state = .tunneling
        
        // ARP
        let ARPManager = SoftEtherARPManager(
            myIP: ipv4ToUInt32(networkParameters.clientIPv4),
            myMac: clientMac,
            sendEthernetFrame: { [weak self] data in
                self?.sendRawEthernetFrameToServer(data)
            }
        )
        ARPManager.start()
        self.arpManager = ARPManager
        
        // ARP resolve gateway first
        ARPManager.request(ip: ipv4ToUInt32(networkParameters.gatewayIPv4))
        
        startKeepAlive()
        
        configureUdpDataPath(packetFlow: packetTunnelProvider.packetFlow)

        // pumps
        startReadFromTun(packetFlow: packetTunnelProvider.packetFlow)
        startReadFromServer(packetFlow: packetTunnelProvider.packetFlow)
    }
    
    public func stop() {
        state = .stopped(nil)
        
        udpConnection?.onFrame = nil
        udpConnection?.closeSync()
        
        secureConnection?.disconnect()
        dhcpManager?.stop()
        arpManager?.stop()
        
        stopKeepAlive()
    }
    
    // MARK: - Internal helpers (handshake, reading, keepalive)
    
    private func performSoftEtherHandshake(using auth: SoftEtherAuthMethod, completion: @escaping (Result<SoftEtherSessionParams, Error>) -> Void) {
        guard let secureConnection = self.secureConnection else {
            completion(.failure(SoftEtherError("performSoftEtherHandshake: no active SecureConnection")))
            return
        }
        
        let handshaker = SoftEtherHandshaker(secureConnection: secureConnection, udpConnection: udpConnection, configuration: configuration, logger: SoftEtherSession.logger)
        
        handshaker.performHandshake(using: auth) { result in
            completion(result)
        }
    }
    
    private func startKeepAlive() {
        
        guard keepAliveTimer == nil else {
            return
        }
        
        guard self.state == .tunneling else {
            return
        }
        
        let sendKeepAliveIfNeeded: () -> Void = { [weak self] in
            guard let self = self,
                  self.state == .tunneling,
                  let connection = self.secureConnection
            else {
                return
            }

            let frame = SoftEtherKeepAlive.makeFrame()
            
            connection.send(data: frame) { error in
                if let error {
                    SoftEtherSession.logger.both(.error, "KeepAlive send error: \(error.localizedDescription)")
                } else {
                    SoftEtherSession.logger.debugIfDebugBuild("KeepAlive sent")
                }
            }
            
            if let timer = self.keepAliveTimer {
                self.scheduleKeepAlive(on: timer)
            }
        }
        
        sendKeepAliveIfNeeded()
        
        let timer = DispatchSource.makeTimerSource(queue: queue)
        keepAliveTimer = timer
        
        scheduleKeepAlive(on: timer)
        timer.setEventHandler {
            sendKeepAliveIfNeeded()
        }
        timer.resume()
    }
    
    private func scheduleKeepAlive(on timer: DispatchSourceTimer) {
        let base: TimeInterval = 15
        let jitter: TimeInterval = Double.random(in: -5...5) // 10–20 sec
        let interval = max(5, base + jitter)
        timer.schedule(deadline: .now() + interval, repeating: interval)
    }
    
    private func stopKeepAlive() {
        if let timer = keepAliveTimer {
            timer.cancel()
            keepAliveTimer = nil
        }
    }
    
    public func startPacketPump(packetFlow: NEPacketTunnelFlow) {
        state = .tunneling
        
        configureUdpDataPath(packetFlow: packetFlow)

        // Reading from utun -> SoftEther
        startReadFromTun(packetFlow: packetFlow)

        // Reading from SoftEther -> utun
        startReadFromServer(packetFlow: packetFlow)
    }
    
    private func startReadFromTun(packetFlow: NEPacketTunnelFlow) {
        
        packetFlow.readPackets { [weak self] packets, protocols in
            
            guard let self = self else {
                return
            }
            
            SoftEtherSession.logger.debugIfDebugBuild("Read \(packets.count) packets from TUN")
            
            guard self.state == .tunneling else {
                SoftEtherSession.logger.both(.error, "Can't send packets from TUN. SoftEtherSession is in wrong state: \(self.state)")
                return
            }
            
            guard self.secureConnection != nil || self.udpConnection != nil else {
                SoftEtherSession.logger.both(.error, "There isn't any connection.")
                return
            }
            
            guard let arpManager = self.arpManager else {
                SoftEtherSession.logger.both(.error, "There isn't any ARP manager.")
                return
            }
            
            guard let networkParameters = networkParameters else {
                SoftEtherSession.logger.both(.error, "There isn't any network parameters.")
                return
            }
            
            for i in packets.indices {
                
                let ipPacket = packets[i]
                
                // IPv4 check (minimal, not a full parse)
                guard ipPacket.count >= 20 else {
                    continue
                }
                
                let dstIP = ipPacket.readUInt32BE(at: 16) // dst ip (bytes 16..19)
                
                let myAssignedIP = ipv4ToUInt32(networkParameters.clientIPv4)
                let subnetMask = ipv4ToUInt32(networkParameters.subnetMask)
                let gatewayIPv4 = ipv4ToUInt32(networkParameters.gatewayIPv4)
                
                let targetIP: UInt32 = SoftEtherSession.isOnLink(ip: dstIP, myAssignedIP: myAssignedIP, subnetMask: subnetMask) ? dstIP : gatewayIPv4 // same subnet → ARP real host, outside → ARP gateway instead
                
                let resolvedDstMac = arpManager.resolve(ip: targetIP)
                if resolvedDstMac == nil {
                    SoftEtherSession.logger.both(.info, "🟡 No ARP entry for \(ipStr(from: targetIP)). Sending ARP request + sending unresolved frame.")
                    arpManager.request(ip: targetIP)
                }
                
                let dstMac = resolvedDstMac ?? ZeroMac
                let ethernetFrame = SoftEtherEthernetFrame(
                    dst: dstMac,
                    src: self.clientMac,
                    type: 0x0800,
                    payload: ipPacket
                )
                
                self.sendRawEthernetFrameToServer(ethernetFrame.encode())
            }
            
            self.startReadFromTun(packetFlow: packetFlow)
        }
    }
    
    
    private func startReadFromServer(packetFlow: NEPacketTunnelFlow) {
        
        guard let secureConnection = self.secureConnection else {
            SoftEtherSession.logger.both(.default, "There isn't any connection to receive from server.")
            return
        }
        
        guard self.state == .tunneling else {
            SoftEtherSession.logger.both(.default, "The connection has wrong state.")
            return
        }
        
        secureConnection.receive { [weak self] data, error in
            guard let self = self else {
                return
            }
            
            if let error = error {
                SoftEtherSession.logger.both(.error, "⛔ Failed to receive data from server: \(String(describing: error))")
                self.stop()
                return
            }
            
            if let data {
                SoftEtherSession.logger.debugIfDebugBuild("RECV via TLS: got \(data.count) bytes")
                
                let frames = self.streamTCPParser.feed(data)
                
                var outPackets: [Data] = []
                var protocols: [NSNumber] = []
                
                for frame in frames {
                    if let (payload, proto) = self.classifyIncomingEthernetFrameData(frame) {
                        outPackets.append(payload)
                        protocols.append(proto)
                    }
                }

                if !outPackets.isEmpty {
                    SoftEtherSession.logger.debugIfDebugBuild("Packet flow writing: \(outPackets.count) packets")
                    packetFlow.writePackets(outPackets, withProtocols: protocols)
                } else {
                    SoftEtherSession.logger.debugIfDebugBuild("⭕ Packet flow writing: No packets to write. Didn't parse any full frame.")
                }
            } else {
                SoftEtherSession.logger.debugIfDebugBuild("⭕ RECV via TLS: no bytes")
            }
            
            self.startReadFromServer(packetFlow: packetFlow)
        }
    }

    private func startDhcpReadLoop() {
        guard !dhcpReadLoopActive else {
            return
        }
        
        guard let secureConnection = self.secureConnection else {
            return
        }
        
        dhcpReadLoopActive = true
        SoftEtherSession.logger.both(.default, "Starting DHCP read loop")
        
        func loop() {
            
            guard dhcpReadLoopActive else {
                return
            }
            
            secureConnection.receive { [weak self] data, error in
                guard let self = self else { return }
                
                if let error {
                    SoftEtherSession.logger.both(.error, "DHCP read loop error: \(error.localizedDescription)")
                    self.dhcpReadLoopActive = false
                    return
                }
                
                if let data {
                    // demultiplex the SoftEther TCP stream into frames
                    let frames = self.streamTCPParser.feed(data)
                    
                    for frame in frames {
                        do {
                            let ethernetFrame = try SoftEtherEthernetFrame.decode(frame)
                            
                            if let dhcpManager = self.dhcpManager {
                                dhcpManager.processIncoming(frame: ethernetFrame)
                            }
                        } catch {
                            SoftEtherSession.logger.both(.error, "Failed to decode ethernet frame in DHCP loop: \(error.localizedDescription)")
                        }
                    }
                }
                
                // keep reading while DHCP is still alive and the session is not stopped
                if self.dhcpReadLoopActive, case .established = self.state {
                    loop()
                } else {
                    SoftEtherSession.logger.both(.default, "DHCP read loop stopped (state: \(self.state.description))")
                }
            }
        }
        
        loop()
    }
    
    func stopDhcpReadLoop() {
        SoftEtherSession.logger.both(.default, "Stopping DHCP read loop")
        dhcpReadLoopActive = false
        dhcpManager?.stop()
        dhcpManager = nil
    }
    
    private static func isOnLink(ip: UInt32, myAssignedIP: UInt32, subnetMask: UInt32) -> Bool {
        return (ip & subnetMask) == (myAssignedIP & subnetMask)
    }
}


extension SoftEtherSession.State: Equatable {
    static func == (lhs: SoftEtherSession.State, rhs: SoftEtherSession.State) -> Bool {
        switch (lhs, rhs) {
        case (.idle, .idle),
             (.tlsHandshaking, .tlsHandshaking),
             (.softEtherHandshaking, .softEtherHandshaking),
             (.established, .established),
             (.tunneling, .tunneling),
             (.stopped, .stopped):
            return true
        default:
            return false
        }
    }
}

extension SoftEtherSession.State: CustomStringConvertible {
    var description: String {
        switch self {
        case .idle: return "idle"
        case .tlsHandshaking: return "tlsHandshaking"
        case .softEtherHandshaking: return "softEtherHandshaking"
        case .established: return "established"
        case .tunneling: return "tunneling"
        case .stopped(let error):
            if let error { return "stopped(caused by error: \(error.localizedDescription))" }
            return "stopped"
        }
    }
}

