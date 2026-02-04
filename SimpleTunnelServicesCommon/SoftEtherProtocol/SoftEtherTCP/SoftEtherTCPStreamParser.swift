//
//  SoftEtherStreamParser.swift
//  SimpleTunnel

import Foundation
import OSLog

import Foundation
import OSLog

/// Parses a SoftEther TCP stream:
/// [u32 num]  -> either KEEP_ALIVE_MAGIC or the count of data blocks
///   if num == KEEP_ALIVE_MAGIC:
///       [u32 size] + [size bytes]  -> ignore (keep-alive packet)
///   else:
///       repeat num times:
///           [u32 len] + [len bytes] -> a data block ([len][option][payload])
///
final class SoftEtherTCPStreamParser {

    private var buffer = Data()
    private let logger = LoggerService.vpnext

    func feed(_ chunk: Data) -> [Data] {
        buffer.append(chunk)

        logger.debugIfDebugBuild("🔽 FEED: chunk \(chunk.count) bytes, buffer now \(self.buffer.count)")

        var packets: [Data] = []
        var idx = buffer.startIndex

        // MARK: outer loop
        outer: while true {

            let available = buffer.distance(from: idx, to: buffer.endIndex)
            if available < 4 { break } // need at least num

            // Save point before reading num
            let numStart = idx
            let num = buffer.readUInt32BE(advancing: &idx)

            // MARK: KEEPALIVE
            if num == SoftEtherKeepAlive.magic {
                // read size
                if buffer.distance(from: idx, to: buffer.endIndex) < 4 {
                    idx = numStart; break outer
                }

                let size = Int(buffer.readUInt32BE(advancing: &idx))

                // wait full keepalive payload
                if buffer.distance(from: idx, to: buffer.endIndex) < size {
                    idx = numStart; break outer
                }

                // skip payload
                idx = buffer.index(idx, offsetBy: size)
                continue
            }

            // MARK: NORMAL BLOCKS
            let count = Int(num)
            var tmpFrames: [Data] = []

            for _ in 0..<count {

                // need 4 bytes for len
                if buffer.distance(from: idx, to: buffer.endIndex) < 4 {
                    idx = numStart; break outer
                }

                let blockHeaderIdx = idx
                let len = Int(buffer.readUInt32BE(advancing: &idx))

                if len == 0 {
                    logger.warning("⚠️ empty block len=0")
                    continue
                }

                // need full block
                if buffer.distance(from: idx, to: buffer.endIndex) < len {
                    // rollback to block header
                    idx = blockHeaderIdx
                    idx = numStart
                    break outer
                }

                // extract body
                let start = idx
                let end = buffer.index(start, offsetBy: len)
                let slice = buffer[start..<end]
                idx = end

                tmpFrames.append(Data(slice))
            }

            packets.append(contentsOf: tmpFrames)
        }

        // MARK: Cleanup consumed buffer
        if idx > buffer.startIndex {
            buffer = Data(buffer[idx..<buffer.endIndex])
        }

        return packets
    }
}
