//
//  SoftEtherError.swift
//  SimpleTunnel
//


import Foundation

/// Lightweight error type for SoftEther-specific errors
struct SoftEtherError: Error, LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}
