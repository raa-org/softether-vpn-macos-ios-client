//
//  DHCPManager.swift
//  SimpleTunnel

import Foundation
import NetworkExtension
import OSLog

public enum DHCPError: Error, CustomStringConvertible {
    case timeout
    case nak                        // DHCP server sent a NAK
    case invalidMessage             // malformed DHCP message
    case invalidConfiguration       // required fields missing (IP, mask, etc)
    case internalError(String)      // unexpected state or error message
    
    public var description: String {
        switch self {
        case .timeout:
            return "DHCP timeout"
        case .nak:
            return "DHCP NAK received"
        case .invalidMessage:
            return "Invalid or malformed DHCP message"
        case .invalidConfiguration:
            return "DHCP ACK received but configuration is incomplete"
        case .internalError(let msg):
            return "Internal DHCP error: \(msg)"
        }
    }
}

final class DHCPManager {

    enum DHCPState {
        case idle
        case sendingDiscover
        case waitingOffer
        case waitingAck
        case bound
        case renewing
    }

    private let logger = LoggerService.dhcp
    
    private let myMac: MacAddress
    private let sendEthernetFrame: (Data) -> Void

    // MARK: - Public state (read-only)
    private(set) var assignedIP: IPv4Address?
    private(set) var subnetMask: IPv4Address?
    private(set) var gateway: IPv4Address?
    private(set) var dns: IPv4Address?
    private(set) var leaseTime: TimeInterval = 0
    
    private(set) var state: DHCPState = .idle
    
    // MARK: - Completion Handlers
    private var initialCompletion: ((Result<DHCPResult, DHCPError>) -> Void)?
    private var renewCallback: ((DHCPResult) -> Void)?

    // MARK: - Internal data
    private var leaseStart: Date?
    private var serverID: IPv4Address?
    private var requestedIP: IPv4Address?
    
    private var timer: Timer?
    private var lastSentAt: Date?
    private var resendAttempts: Int = 0
    
    private let resendInterval: TimeInterval = 3.0
    private let maxDiscoverRetries: Int = 4
    private let maxRequestRetries: Int = 4
    
    private lazy var transactionId: UInt32 = {
        var value: UInt32 = 0
        let success = SecRandomCopyBytes(kSecRandomDefault, 4, &value)
        if success != 0 {
            self.logger.error("DHCPManager failed to generate Transaction ID")
        }
        return value
    }()

    // MARK: - Public API
    init(myMac: MacAddress, sendEthernetFrame: @escaping (Data) -> Void) {
        self.myMac = myMac
        self.sendEthernetFrame = sendEthernetFrame
    }

    func start( completion: @escaping (Result<DHCPResult, DHCPError>) -> Void, onRenew: ((DHCPResult) -> Void)? = nil) {
        logger.info("🚀 DHCPManager start()")

        initialCompletion = completion
        renewCallback = onRenew
        
        clearLease()
        state = .sendingDiscover
        resendAttempts = 0
        
        sendDiscover()
        state = .waitingOffer
        
        startTimerIfNeeded()
    }

    func stop() {
        logger.info("🛑 DHCPManager stop()")
        timer?.invalidate()
        timer = nil
        clearLease()
        state = .idle
        initialCompletion = nil
        renewCallback = nil
    }

    // MARK: - Incoming Frames

    func processIncoming(frame: SoftEtherEthernetFrame) {
        
        guard let dhcpMessage = DHCPParser.parse(frame: frame) else {
            return
        }

        switch dhcpMessage.messageType {
        case .offer:
            handleOffer(dhcpMessage)
        case .ack:
            handleAck(dhcpMessage)
        case .nak:
            handleNak(dhcpMessage)
        default:
            break
        }
    }

    // MARK: - Timer

    private func startTimerIfNeeded() {
        guard timer == nil else { return }
        
        timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            self?.tick()
        }
    }

    private func tick() {
        let now = Date()
        
        switch state {
        case .waitingOffer:
            handleWaitingOfferTick(now: now)
            
        case .waitingAck:
            handleWaitingAckTick(now: now)
            
        case .renewing:
            handleWaitingAckTick(now: now)
            
        case .bound:
            handleLeaseTick(now: now)

        case .idle, .sendingDiscover:
            break
        }
    }

    // MARK: - Sending

    private func sendDiscover() {
        logger.info("📡 Sending DHCP DISCOVER")
        
        let discover = DHCPBuilder.buildDiscover(mac: myMac, xid: transactionId)
        let raw = discover.encode()                      // L2 frame
        
        sendEthernetFrame(raw)
        lastSentAt = Date()
    }

    private func sendRequest(serverID: IPv4Address, requestedIP: IPv4Address) {
        logger.info("📡 Sending DHCP REQUEST for \(requestedIP.description, privacy: .public)")
        
        let request = DHCPBuilder.buildRequest(mac: myMac, xid: transactionId, serverID: serverID, requestedIP: requestedIP)
        let requestFrame = request.encode()
        
        sendEthernetFrame(requestFrame)
        lastSentAt = Date()
    }

    private func resendRequest() {
        guard let server = serverID,
              let ip = requestedIP ?? assignedIP else {
            logger.error("❌ resendRequest() called without serverID or IP")
            return
        }
        
        sendRequest(serverID: server, requestedIP: ip)
    }

    private func sendRenew() {
        guard let server = serverID,
              let ip = assignedIP else {
            logger.error("❌ sendRenew() called without serverID or assignedIP")
            return
        }
        
        resendAttempts = 0
        sendRequest(serverID: server, requestedIP: ip)
    }

    // MARK: - DHCP Message Handlers

    private func handleOffer(_ offerMessage: DHCPMessage) {
        guard state == .waitingOffer else {
            return
        }
        
        logger.info("📨 DHCP OFFER received")

        serverID = offerMessage.serverID
        requestedIP = offerMessage.yiaddr
        resendAttempts = 0
        
        guard let server = serverID,
              let ip = requestedIP else {
            logger.error("❌ OFFER missing serverID or yiaddr")
            restartFromDiscover()
            return
        }

        state = .waitingAck
        sendRequest(serverID: server, requestedIP: ip)
    }

    private func handleAck(_ ackMessage: DHCPMessage) {
        guard state == .waitingAck || state == .renewing else {
            return
        }

        logger.info("📨 DHCP ACK received")
        
        let wasRenew = (state == .renewing)

        assignedIP = ackMessage.yiaddr
        subnetMask = ackMessage.subnetMask
        gateway    = ackMessage.router
        dns        = ackMessage.dns
        leaseTime  = ackMessage.leaseTime
        leaseStart = Date()
        serverID   = ackMessage.serverID
        
        guard let ip = assignedIP,
              let mask = subnetMask else {
            initialCompletion?(.failure(.invalidConfiguration))
            stop()
            return
        }
        
        state = .bound
        resendAttempts = 0
        lastSentAt = nil
        
        let result = DHCPResult(address: ip, subnetMask: mask, router: gateway, dns: dns, leaseTime: leaseTime)

        if wasRenew {
            renewCallback?(result)
        } else {
            initialCompletion?(.success(result))
            // The initial completion should never fire twice
            initialCompletion = nil
        }
    }

    private func handleNak(_ nakMessage: DHCPMessage) {
        logger.error("❌ DHCP NAK received — restarting DISCOVER")
        restartFromDiscover()
    }

    // MARK: - Tick handlers

    /// DISCOVER resend logic (waiting for OFFER)
    private func handleWaitingOfferTick(now: Date) {
        guard let last = lastSentAt else { return }

        if now.timeIntervalSince(last) >= resendInterval {
            if resendAttempts < maxDiscoverRetries {
                resendAttempts += 1
                logger.info("⏱ Resending DHCP DISCOVER (attempt \(self.resendAttempts + 1))")
                sendDiscover()
            } else {
                logger.error("❌ DHCP DISCOVER timeout after \(self.resendAttempts) retries")
                initialCompletion?(.failure(.timeout))
                initialCompletion = nil
                stop()
            }
        }
    }

    /// REQUEST resend logic (waiting for ACK)
    private func handleWaitingAckTick(now: Date) {
        guard let last = lastSentAt else { return }

        if now.timeIntervalSince(last) >= resendInterval {
            if resendAttempts < maxRequestRetries {
                resendAttempts += 1
                logger.info("⏱ Resending DHCP REQUEST (attempt \(self.resendAttempts + 1))")
                resendRequest()
            } else {
                logger.error("❌ DHCP REQUEST timeout after \(self.resendAttempts) retries")
                initialCompletion?(.failure(.timeout))
                initialCompletion = nil
                stop()
            }
        }
    }

    /// Lease expiration → start renew (only if in .bound)
    private func handleLeaseTick(now: Date) {
        guard let leaseStart, leaseTime > 0 else { return }
        
        let elapsed = now.timeIntervalSince(leaseStart)
        
        // RFC2131: T1 = 50% lease → start RENEW
        if elapsed >= leaseTime * 0.5, state == .bound {
            logger.info("⏳ Lease 50% passed — RENEWING")
            state = .renewing
            resendAttempts = 0
            sendRenew()
        }
    }


    // MARK: - Reset Helpers

    private func clearLease() {
        assignedIP = nil
        subnetMask = nil
        gateway = nil
        dns = nil
        leaseTime = 0
        leaseStart = nil
        serverID = nil
        requestedIP = nil
        resendAttempts = 0
        lastSentAt = nil
    }

    private func restartFromDiscover() {
        clearLease()
        state = .sendingDiscover
        resendAttempts = 0
        sendDiscover()
        state = .waitingOffer
    }
}
