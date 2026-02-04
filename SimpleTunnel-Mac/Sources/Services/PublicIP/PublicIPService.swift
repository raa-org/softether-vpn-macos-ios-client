//
//  PublicIPService.swift
//  SimpleTunnel
//

import Foundation
import Darwin // inet_pton

enum PublicIPError: LocalizedError {
    
    case invalidURL(String)
    case httpStatus(Int)
    case invalidResponse

    var errorDescription: String? {
        switch self {
        case .invalidURL(let s): return "Invalid URL: \(s)"
        case .httpStatus(let code): return "HTTP \(code)"
        case .invalidResponse: return "Invalid response"
        }
    }
}

actor PublicIPService {
    
    private static let urlString = "https://ifconfig.co/ip"
    private let minInterval: TimeInterval = 60

    private var lastFetchAt: Date?

    func fetch(force: Bool = false) async throws -> String {
        
        // Hard rate limit
        if !force, let last = lastFetchAt, Date().timeIntervalSince(last) < minInterval {
            throw CancellationError() // "too soon" — caller can ignore
        }
        lastFetchAt = Date()

        guard let url = URL(string: Self.urlString) else {
            throw PublicIPError.invalidURL(Self.urlString)
        }

        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        req.timeoutInterval = 10
        req.setValue("text/plain", forHTTPHeaderField: "Accept")
        req.setValue("SoftEtherVPN-macOS", forHTTPHeaderField: "User-Agent")

        let (data, resp) = try await URLSession.shared.data(for: req)
        let status = (resp as? HTTPURLResponse)?.statusCode ?? -1
        guard status == 200 else {
            throw PublicIPError.httpStatus(status)
        }

        let raw = String(decoding: data, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)

        guard isValidIP(raw) else {
            throw PublicIPError.invalidResponse
        }
        return raw
    }

    private func isValidIP(_ s: String) -> Bool {
        
        var v4 = in_addr()
        if s.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            return true
        }

        var v6 = in6_addr()
        if s.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
            return true
        }

        return false
    }
}

