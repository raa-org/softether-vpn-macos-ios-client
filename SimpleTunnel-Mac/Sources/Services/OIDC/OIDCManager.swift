//
//  OIDCManager.swift
//  SimpleTunnel

import Foundation
import AppAuth
import AppKit
import OSLog

struct OIDCTokens {
    let accessToken: String?
    let refreshToken: String?
    let idToken: String?
    let expiresAt: Date?
}

enum OIDCError: Error {
    case invalidConfig
    case userCancelled
    case noAuthState
    case tokenRefreshFailed
    case invalidResponse
}

final class OIDCManager {

    // MARK: - State
    
    private var authStates: [String: OIDAuthState] = [:]
    private static let logger = LoggerService.oidc
    
    init() {
        AuthStateKeychainStore.clearLegacyIfPresent()
    }
    
    // MARK: - Public API
    
    func isLoggedIn(profileName: String, oidcConfig: OIDCConfig) -> Bool {
        let key = makeKey(profileName: profileName, oidcConfig: oidcConfig)

        if let state = authStates[key] {
            return state.isAuthorized
        }

        do {
            if let state = try AuthStateKeychainStore.load(key: key) {
                authStates[key] = state
                return state.isAuthorized
            }
        } catch {
            Self.logger.both(.error, "Keychain load failed: \(error.localizedDescription)")
        }

        return false
    }
    
    func ensureValidTokens(oidcConfig: OIDCConfig, profileName: String, presentingWindow: NSWindow) async throws -> OIDCTokens {
        
        let key = AuthStateKeychainStore.stateKey(profileName: profileName, issuerUrl: oidcConfig.issuerUrl, clientId: oidcConfig.clientId)
        
        if let state = try loadStateIfNeeded(key: key) {
            OIDCManager.logger.both(.info, "ensureValidTokens with existing state (key=\(key))")
            return try await fetchFreshTokens(using: state, key: key)
        }
        
        OIDCManager.logger.both(.info, "Starting interactive OIDC login (key=\(key))")
        let state = try await loginInteractive(oidcConfig: oidcConfig, presentingWindow: presentingWindow)
        setAuthState(state, key: key)
        return try await fetchFreshTokens(using: state, key: key)
    }
    
    func logout(profileName: String, oidcConfig: OIDCConfig) {
        let key = AuthStateKeychainStore.stateKey(profileName: profileName, issuerUrl: oidcConfig.issuerUrl, clientId: oidcConfig.clientId)
        setAuthState(nil, key: key)
        OIDCManager.logger.both(.info, "OIDC Logged out: auth state cleared (key=\(key))")
    }
    
    func logoutAll() {
        authStates.removeAll()
        do {
            try AuthStateKeychainStore.clearAllAuthStates()
            Self.logger.both(.info, "OIDC logout all: cleared all auth states from Keychain")
        } catch {
            Self.logger.both(.error, "OIDC logout all failed: \(error.localizedDescription)")
        }
    }
    
    func makeKey(profileName: String, oidcConfig: OIDCConfig) -> String {
        return AuthStateKeychainStore.stateKey(profileName: profileName, issuerUrl: oidcConfig.issuerUrl, clientId: oidcConfig.clientId)
    }
}

private extension OIDCManager {
    
    func loadStateIfNeeded(key: String) throws -> OIDAuthState? {
        if let cached = authStates[key] { return cached }
        if let restored = try AuthStateKeychainStore.load(key: key) {
            authStates[key] = restored
            return restored
        }
        return nil
    }
    
    func loginInteractive(oidcConfig: OIDCConfig, presentingWindow: NSWindow) async throws -> OIDAuthState {
        guard
                let issuerURL = URL(string: oidcConfig.issuerUrl),
                let redirectURI = URL(string: oidcConfig.redirectUri),
                !oidcConfig.clientId.isEmpty,
                !oidcConfig.scopes.isEmpty
            else {
                throw OIDCError.invalidConfig
            }
        
        let config = try await discoverConfiguration(issuerURL: issuerURL)
        
        let request = OIDAuthorizationRequest(
            configuration: config,
            clientId: oidcConfig.clientId,
            clientSecret: nil,
            scopes: oidcConfig.scopes,
            redirectURL: redirectURI,
            responseType: OIDResponseTypeCode,
            additionalParameters: nil
        )
        
        return try await withCheckedThrowingContinuation { continuation in
            AppDelegate.currentAuthorizationFlow = OIDAuthState.authState(byPresenting: request, presenting: presentingWindow) { state, error in
                AppDelegate.currentAuthorizationFlow = nil
                
                if let nsError = error as NSError?,
                   nsError.domain == OIDGeneralErrorDomain,
                   nsError.code == OIDErrorCode.userCanceledAuthorizationFlow.rawValue {
                    OIDCManager.logger.both(.info, "User cancelled OIDC flow")
                    continuation.resume(throwing: OIDCError.userCancelled)
                    return
                }
                
                if let error {
                    OIDCManager.logger.both(.error, "OIDC interactive login failed: \(error.localizedDescription)")
                    continuation.resume(throwing: error)
                    return
                }
                
                guard let state else {
                    OIDCManager.logger.both(.error, "OIDC interactive login returned nil state")
                    continuation.resume(throwing: OIDCError.invalidResponse)
                    return
                }
                
                OIDCManager.logger.both(.info, "OIDC interactive login succeeded")
                continuation.resume(returning: state)
            }
        }
    }
    
    func discoverConfiguration(issuerURL: URL) async throws -> OIDServiceConfiguration {
        try await withCheckedThrowingContinuation { continuation in
            OIDAuthorizationService.discoverConfiguration(forIssuer: issuerURL) { config, error in
                if let error {
                    OIDCManager.logger.both(.error, "OIDC discovery failed: \(error.localizedDescription)")
                    continuation.resume(throwing: error)
                    return
                }
                guard let config else {
                    OIDCManager.logger.both(.error, "OIDC discovery returned nil configuration")
                    continuation.resume(throwing: OIDCError.invalidConfig)
                    return
                }
                OIDCManager.logger.both(.info, "OIDC discovery succeeded")
                continuation.resume(returning: config)
            }
        }
    }
    
    func fetchFreshTokens(using state: OIDAuthState, key: String) async throws -> OIDCTokens {
        try await withCheckedThrowingContinuation { continuation in
            state.performAction { [weak self] access, id, error in
                guard let self else {
                    continuation.resume(throwing: OIDCError.noAuthState)
                    return
                }

                if let error {
                    OIDCManager.logger.both(.error, "OIDC performAction failed: \(error.localizedDescription)")
                    continuation.resume(throwing: error)
                    return
                }

                let accessToken = access ?? ""
                let idToken = id
                let refreshToken = state.lastTokenResponse?.refreshToken
                let expiresAt = state.lastTokenResponse?.accessTokenExpirationDate

                guard !accessToken.isEmpty else {
                    continuation.resume(throwing: OIDCError.tokenRefreshFailed)
                    return
                }

                self.setAuthState(state, key: key)

                continuation.resume(returning: OIDCTokens(
                    accessToken: accessToken,
                    refreshToken: refreshToken,
                    idToken: idToken,
                    expiresAt: expiresAt
                ))
            }
        }
    }
    
    private func setAuthState(_ newState: OIDAuthState?, key: String) {
        authStates[key] = newState

        if let state = newState {
            do { try AuthStateKeychainStore.save(state, key: key) }
            catch { Self.logger.both(.error, "Failed to save OIDAuthState: \(error.localizedDescription)") }
        } else {
            AuthStateKeychainStore.clear(key: key)
        }
    }
}
