import Foundation
import Network
import Security
import OSLog

/// SecureConnection handles the TLS connection with the SoftEther VPN server
class SecureTCPConnection {
    
    // MARK: - Properties
    
    private var connection: NWConnection?
    private let host: String
    private let port: UInt16
    private let queue = DispatchQueue(label: "com.softether.connection", qos: .userInitiated)
    private static let logger = LoggerService.vpnext
    
    // MARK: - Initialization
    
    /// Initialize a secure connection
    /// - Parameters:
    ///   - host: Server hostname or IP address
    ///   - port: Server port number
    init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }
    
    // MARK: - Public Methods
    
    /// Connect to the server using TLS
    /// - Parameter completion: Callback with connection result
    func connect(completion: @escaping (Bool, Error?) -> Void) {
        guard let portEndpoint = NWEndpoint.Port(rawValue: port) else
        {
            completion(false, NSError(domain: "SoftEtherConnectionError", code: 1001, userInfo: [NSLocalizedDescriptionKey: "Try to connect to bad port."]))
            return
        }
        
        let hostEndpoint = NWEndpoint.Host(host)
        
        // Create TLS parameters
        let tlsOptions = NWProtocolTLS.Options()
        
        // Configure TLS for maximum compatibility with SoftEther
        sec_protocol_options_set_min_tls_protocol_version( tlsOptions.securityProtocolOptions, .TLSv12)
        
        sec_protocol_options_set_verify_block(tlsOptions.securityProtocolOptions, { (metadata, trust, verifyBlockCompletionHandler) in
            let isValid = true
            verifyBlockCompletionHandler(isValid)
        }, .main)
        
        // Create TCP options with TLS
        let tcpOptions = NWProtocolTCP.Options()
        
        // Create connection parameters
        let parameters = NWParameters(tls: tlsOptions, tcp: tcpOptions)
        
        // Create the connection
        let nwConnection = NWConnection(host: hostEndpoint, port: portEndpoint, using: parameters)
        connection = nwConnection
        
        nwConnection.stateUpdateHandler = { [weak self] state in
            guard let self else {
                return
            }

            SecureTCPConnection.logger.both(.default, "🔵 NWConnection state changed → \(SecureTCPConnection.describe(state))")

            switch state {
            case .ready:
                SecureTCPConnection.logger.both(.default, "🟢 TLS/ TCP ready — connection fully established")
                completion(true, nil)

            case .waiting(let error):
                SecureTCPConnection.logger.both(.error, "🟡 WAITING — system cannot connect: \(error.localizedDescription)")
                self.disconnect()
                completion(false, error)

            case .failed(let error):
                SecureTCPConnection.logger.both(.error, "🔴 FAILED — connection broken: \(error.localizedDescription)")
                
                if case NWError.posix(let posixError) = error {
                    SecureTCPConnection.logger.both(.error, "POSIX error: \(posixError.rawValue) — \(String(cString: strerror(posixError.rawValue)))")
                }
                if case NWError.dns(let dnsError) = error {
                    SecureTCPConnection.logger.both(.error, "DNS error: \(dnsError.description)")
                }
                
                self.disconnect()
                completion(false, error)

            case .cancelled:
                SecureTCPConnection.logger.both(.error, "⚫ CANCELLED — connection closed by client or system")
                completion(false, NSError(domain:"SoftEther", code:1000, userInfo:[NSLocalizedDescriptionKey: "Connection cancelled"]))

            default:
                SecureTCPConnection.logger.both(.default, "ℹ️ State: \(SecureTCPConnection.describe(state))")
            }
        }
        
        // Start the connection
        nwConnection.start(queue: queue)
        SecureTCPConnection.logger.both(.default, "Start connection to \(hostEndpoint.debugDescription):\(portEndpoint.debugDescription)")
    }
    
    /// Disconnect from the server
    func disconnect() {
        SecureTCPConnection.logger.both(.default, "Secure connection disconnecting")
        connection?.cancel()
        connection = nil
        SecureTCPConnection.logger.both(.default, "Secure connection disconnected")
    }
    
    
    /// Send data to the server
    /// - Parameters:
    ///   - data: Data to send
    ///   - completion: Callback with error if any
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        
        guard let connection = connection, connection.state == .ready else {
            completion(SoftEtherError("Connection not ready"))
            return
        }
        
        if let tcp = tcpMetadata() {
            SecureTCPConnection.logger.debugIfDebugBuild("📤 TCP send_state before send: availableReceiveBuffer=\(tcp.availableReceiveBuffer) availableSendBuffer=\(tcp.availableSendBuffer)")
        }

        SecureTCPConnection.logger.debugIfDebugBuild("⬆️ Sending \(data.count) bytes…")
        
        connection.send(content: data, completion: .contentProcessed {[weak self] error in
            
            if let error {
                SecureTCPConnection.logger.both(.error, "❌ SEND ERROR: \(error.localizedDescription)")
            } else {
                SecureTCPConnection.logger.debugIfDebugBuild("✔️ SEND OK (\(data.count) bytes)")
            }

            if let tcp = self?.tcpMetadata() {
                SecureTCPConnection.logger.debugIfDebugBuild("📤 TCP send_state before send: availableReceiveBuffer=\(tcp.availableReceiveBuffer) availableSendBuffer=\(tcp.availableSendBuffer)")
            }
            
            completion(error)
        })
    }
    
    /// Receive data from the server
    /// - Parameter completion: Callback with received data and error if any
    func receive(completion: @escaping (Data?, Error?) -> Void) {
        
        guard let connection = connection else {
            SecureTCPConnection.logger.both(.default, "There isn't any NEConnection.")
            completion(nil, SoftEtherError("There isn't any NEConnection."))
            return
        }
        
        guard connection.state == .ready else {
            SecureTCPConnection.logger.both(.default, "Connection is not ready. Current state is \(SecureTCPConnection.describe(connection.state))")
            completion(nil, SoftEtherError("Connection is not ready."))
            return
        }
        
        if let tcp = tcpMetadata() {
            SecureTCPConnection.logger.debugIfDebugBuild("📥 TCP receive_state before receive: availableReceiveBuffer=\(tcp.availableReceiveBuffer) availableSendBuffer=\(tcp.availableSendBuffer)")
        }
        
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64*1024) {[weak self] data, _, isComplete, error in
            
            if let error {
                SecureTCPConnection.logger.both(.error, "❌ RECV ERROR: \(error.localizedDescription)")
                completion(nil, error)
                return
            }

            if isComplete {
                SecureTCPConnection.logger.both(.error, "⛔ RECV COMPLETE — server closed connection.")
                self?.disconnect()
                completion(data, SoftEtherError("Server closed connection"))
                return
            }

            if let data {
                SecureTCPConnection.logger.debugIfDebugBuild("⬇️ RECV \(data.count) bytes")
            } else {
                SecureTCPConnection.logger.both(.debug, "⬇️ RECV: nil data (keepalive?)")
            }

            completion(data, nil)
            
            if let tcp = self?.tcpMetadata() {
                SecureTCPConnection.logger.debugIfDebugBuild("📥 TCP receive_state before receive: availableReceiveBuffer=\(tcp.availableReceiveBuffer) availableSendBuffer=\(tcp.availableSendBuffer)")
            }
        }
    }
    
    /// Helpers
    private func tcpMetadata() -> NWProtocolTCP.Metadata? {
        return connection?.metadata(definition: NWProtocolTCP.definition) as? NWProtocolTCP.Metadata
    }

    static func describe(_ state: NWConnection.State) -> String {
        switch state {
         case .setup:
             return "setup"
         case .preparing:
             return "preparing"
         case .ready:
             return "ready"
         case .failed(let error):
             return "failed with errror: \(error.localizedDescription)"
         case .waiting(let error):
             return "waiting with error: \(error.localizedDescription)"
         case .cancelled:
             return "cancelled"
         @unknown default:
             return "unknown"
         }
     }
}
