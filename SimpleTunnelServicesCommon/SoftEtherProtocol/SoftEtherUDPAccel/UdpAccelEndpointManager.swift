    //
    //  UdpAccelEndpointManager.swift
    //  SimpleTunnel
    //

    import Foundation
    import Darwin

    struct UdpAccelEndpointManager {

        private(set) var configured: sockaddr_in = sockaddr_in()
        private(set) var reported: sockaddr_in = sockaddr_in()
        private(set) var hasReported: Bool = false

        private(set) var pinned: sockaddr_in = sockaddr_in()
        private(set) var hasPinned: Bool = false

        mutating func reset() {
            configured = sockaddr_in()
            reported = sockaddr_in()
            hasReported = false
            pinned = sockaddr_in()
            hasPinned = false
        }

        mutating func setConfigured(ip: in_addr, port: UInt16) {
            var a = sockaddr_in()
            a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            a.sin_family = sa_family_t(AF_INET)
            a.sin_addr = ip
            a.sin_port = port.bigEndian
            configured = a
        }

        mutating func setReported(ip: in_addr, port: UInt16) {
            var a = sockaddr_in()
            a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            a.sin_family = sa_family_t(AF_INET)
            a.sin_addr = ip
            a.sin_port = port.bigEndian
            reported = a
            hasReported = true
        }

        func primaryDestination() -> sockaddr_in {
            return hasPinned ? pinned : configured
        }

        mutating func pin(from source: sockaddr_storage) {
            var src = source
            guard src.ss_family == sa_family_t(AF_INET) else { return }

            withUnsafePointer(to: &src) { ptr in
                ptr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { p4 in
                    pinned = p4.pointee
                    hasPinned = true
                }
            }
        }

        func isPinnedValid() -> Bool {
            guard hasPinned else { return false }
            return pinned.sin_port != 0 && pinned.sin_addr.s_addr != 0
        }

        // MARK: -  Helpers

        private static func endpointKey(_ a: sockaddr_in) -> UInt64 {
            // NOTE: sin_addr.s_addr is already in network byte order.
            // For equality checks we can compare raw s_addr + raw sin_port.
            let ip = UInt64(a.sin_addr.s_addr)
            let port = UInt64(UInt16(bigEndian: a.sin_port))
            return (ip << 16) | port
        }

        public static func isValid(_ a: sockaddr_in) -> Bool {
            a.sin_addr.s_addr != 0 && a.sin_port != 0
        }

        /// Fallback destinations for keep-alive (SoftEther-ish):
        /// pinned (if any), configured, reported (if any) — deduped — excluding `primary`.
        func keepAliveFallbackDestinations(excluding primary: sockaddr_in) -> [sockaddr_in] {
            let primaryKey = Self.endpointKey(primary)

            var out: [sockaddr_in] = []
            var seen = Set<UInt64>()

            func push(_ a: sockaddr_in) {
                guard Self.isValid(a) else { return }
                let k = Self.endpointKey(a)
                guard k != primaryKey else { return }      // exclude primary
                guard !seen.contains(k) else { return }    // dedup
                seen.insert(k)
                out.append(a)
            }

            if hasPinned { push(pinned) }
            push(configured)
            if hasReported { push(reported) }

            return out
        }
    }

