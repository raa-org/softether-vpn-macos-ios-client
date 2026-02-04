//
//  ARP.swift
//  SimpleTunnel

import Foundation
import OSLog

final class SoftEtherARPManager {

    enum ArpType {
        case request(srcIP: UInt32, targetIP: UInt32)
        case replyToUs(srcIP: UInt32, mac: MacAddress)
        case gratuitous(srcIP: UInt32, mac: MacAddress)
        case replyOther(srcIP: UInt32, mac: MacAddress)
    }

    struct Entry {
        let mac: MacAddress
        var updated: Date
    }
    
    enum ArpOptionCode: UInt16 {
        case request = 1   // who-has
        case reply   = 2   // is-at
    }

    private let logger = LoggerService.arp
    private let queue = DispatchQueue(label: "arp.manager")
    private var table: [UInt32: Entry] = [:]
    private var pending: [UInt32: Int] = [:] // ip -> attempt counter

    private let maxRetries = 4
    private let retryInterval: TimeInterval = 2
    private let entryTTL: TimeInterval = 60 // 1 min
    private let gratuitousInterval: TimeInterval = 30

    private let myIP: UInt32
    private let myMac: MacAddress

    private let sendEthernetFrame: (Data) -> Void

    private var gratuitousTimer: DispatchSourceTimer?
    
    init(myIP: UInt32, myMac: MacAddress, sendEthernetFrame: @escaping (Data) -> Void) {
        self.myIP = myIP
        self.myMac = myMac
        self.sendEthernetFrame = sendEthernetFrame
    }
    
    private func parse(_ payload: Data) -> ArpType? {

        guard payload.count >= 28 else { return nil }

        let op = payload.readUInt16BE(at: 6)
        let srcMac = MacAddress(Array(payload[8..<14]))
        let srcIP  = payload.readUInt32BE(at: 14)
        let dstMac = MacAddress(Array(payload[18..<24]))
        let dstIP  = payload.readUInt32BE(at: 24)
        
        logger.debugIfDebugBuild("[ARP manager] Parsing arp message: option = \(op) scrIP = \(ipStr(from: srcIP)) srcMac = \(srcMac.description) dstIP = \(ipStr(from: dstIP)) dstMac = \(dstMac.description).")

        switch op {
        case 1: // request
            return .request(srcIP: srcIP, targetIP: dstIP)

        case 2: // reply
            if dstIP == myIP {
                return .replyToUs(srcIP: srcIP, mac: srcMac)
            }
            return .replyOther(srcIP: srcIP, mac: srcMac)

        default:
            return nil
        }
    }
    
    private func handle(_ payload: Data) {
        guard let type = parse(payload) else {
            logger.both(.error, "[ARP manager] Parsing arp message failed. There isn't any option.")
            return
        }

        switch type {

        case .request(let srcIP, let targetIP):
            table[srcIP] = Entry(mac: MacAddress(Array(payload[8..<14])), updated: Date())
            logger.debugIfDebugBuild("ARP request: \(ipStr(from: srcIP)) asking for \(ipStr(from: targetIP))")

            if targetIP == myIP {
                guard let srcIPMac = table[srcIP] else {
                    logger.both(.error, "[ARP manager] There isn't any records for ip: \(ipStr(from: srcIP)).")
                    return
                }
                sendReply(toIP: srcIP, toMac: srcIPMac.mac)
            } else {
                logger.debugIfDebugBuild("[ARP manager] Don't send reply. No match myIP: \(ipStr(from: self.myIP))) and targetIP: \(ipStr(from: targetIP))) ")
            }

        case .replyToUs(let srcIP, let mac):
            logger.debugIfDebugBuild("ARP reply: \(ipStr(from: srcIP)) is at \(mac)")
            table[srcIP] = Entry(mac: mac, updated: Date())
            pending.removeValue(forKey: srcIP)

        case .replyOther(let srcIP, let mac):
            logger.debugIfDebugBuild("ARP reply other: \(ipStr(from: srcIP)) at \(mac)")
            table[srcIP] = Entry(mac: mac, updated: Date())

        case .gratuitous(let srcIP, let mac):
            logger.debugIfDebugBuild("ARP gratuitous: \(ipStr(from: srcIP)) at \(mac)")
            table[srcIP] = Entry(mac: mac, updated: Date())
        }
    }
    
    private func sendRequest(_ ip: UInt32) {
        
        // already waiting for this IP
        if pending[ip] != nil {
            logger.debugIfDebugBuild("⏳ ARP already pending for \(ipStr(from: ip))")
            return
        }
        
        let attempt = pending[ip] ?? 0
        
        if attempt >= maxRetries {
            logger.debugIfDebugBuild("ARP timeout for \(ipStr(from: ip))")
            pending.removeValue(forKey: ip)
            return
        }

        pending[ip] = attempt + 1
        
        let payload = buildArpPayload(
            opCode: .request,
            senderIP: myIP,
            senderMac: myMac,
            targetIP: ip,
            targetMac: ZeroMac
        )
        
        let frame = SoftEtherEthernetFrame(
                dst: BroadcastMac,
                src: myMac,
                type: 0x0806,
                payload: payload
            ).encode()

        logger.both(.info, "Sending request ARP")
        sendEthernetFrame(frame)

        queue.asyncAfter(deadline: .now() + retryInterval) { [weak self] in
            self?.retryIfNeeded(ip)
        }
    }

    private func retryIfNeeded(_ ip: UInt32) {
        if let entry = table[ip],
           Date().timeIntervalSince(entry.updated) < entryTTL {
            pending.removeValue(forKey: ip)
            return
        }
        sendRequest(ip)
    }

    private func sendReply(toIP: UInt32, toMac: MacAddress) {
        let payload = buildArpPayload(
            opCode: .reply,
            senderIP: myIP,
            senderMac: myMac,
            targetIP: toIP,
            targetMac: toMac
        )

        let frame = SoftEtherEthernetFrame(
            dst: toMac,
            src: myMac,
            type: 0x0806,
            payload: payload
        ).encode()
        
        logger.debugIfDebugBuild("Sending reply ARP")
        sendEthernetFrame(frame)
    }
    
    private func startGratuitous() {
        let t = DispatchSource.makeTimerSource(queue: queue)
        gratuitousTimer = t
        t.schedule(deadline: .now() + 1, repeating: gratuitousInterval)
        t.setEventHandler { [weak self] in
            self?.sendGratuitous()
        }
        t.resume()
    }

    private func sendGratuitous() {
        let payload = buildArpPayload(
            opCode: .reply,
            senderIP: myIP,
            senderMac: myMac,
            targetIP: myIP,
            targetMac: myMac
        )
        let frame = SoftEtherEthernetFrame(
            dst: BroadcastMac,
            src: myMac,
            type: 0x0806,
            payload: payload
        ).encode()
        
        logger.debugIfDebugBuild("Sending gratuitous ARP")
        sendEthernetFrame(frame)
    }
    
    /// Build ARP  payload (full 28 bytes)
    func buildArpPayload(opCode: ArpOptionCode, senderIP: UInt32, senderMac: MacAddress, targetIP: UInt32, targetMac: MacAddress) -> Data {
        var d = Data()
        d.appendUInt16BE(1)                  // HW type: Ethernet (1)
        d.appendUInt16BE(0x0800)             // Protocol: IPv4 (0x0800)
        d.append(6)                          // Hardware size
        d.append(4)                          // Protocol size
        d.appendUInt16BE(opCode.rawValue)    // Opcode: 1=request, 2=reply
        d.append(contentsOf: senderMac.bytesArray)
        d.appendUInt32BE(senderIP)
        d.append(contentsOf: targetMac.bytesArray)
        d.appendUInt32BE(targetIP)
        return d
    }
}

extension SoftEtherARPManager {
    func start() {
        startGratuitous()
    }

    func stop() {
        gratuitousTimer?.cancel()
        gratuitousTimer = nil
    }

    func resolve(ip: UInt32) -> MacAddress? {
        queue.sync {
            guard let entry = table[ip] else { return nil }
            if Date().timeIntervalSince(entry.updated) < entryTTL {
                return entry.mac
            }
            return nil
        }
    }

    func processIncomingARP(_ payload: Data) {
        queue.async {
            self.handle(payload)
        }
    }

    func request(ip: UInt32) {
        queue.async {
            self.sendRequest(ip)
        }
    }
}
