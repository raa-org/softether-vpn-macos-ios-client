//
//  SoftEtherHandshaker.swift
//  SimpleTunnel

import Foundation
import CryptoKit
import OSLog

final class SoftEtherHandshaker {
    
    /// Server challenge returned by Hello
    struct Challenge {
        let random: Data // expected to be 20 bytes (SHA-1 size) per protocol
        
        init(random: Data) throws {
            guard random.count == 20 else {
                throw SoftEtherError("Challenge.random must be 20 bytes")
            }
            self.random = random
        }
    }

    private let secureConnection: SecureTCPConnection
    private let udpConnection: SoftEtherUdpAccel?
    private let configuration: SoftEtherClientConfiguration
    private let logger: Logger

    init(secureConnection: SecureTCPConnection, udpConnection: SoftEtherUdpAccel?, configuration: SoftEtherClientConfiguration, logger: Logger) {
        self.secureConnection = secureConnection
        self.udpConnection = udpConnection
        self.configuration = configuration
        self.logger = logger
    }

    /// Full SoftEther handshake: Hello -> Auth -> Welcome
    func performHandshake(using auth: SoftEtherAuthMethod, completion: @escaping (Result<SoftEtherSessionParams, Error>) -> Void) {
        let host = configuration.host
        let hubName = configuration.hubName

        uploadWatermark(hostAsString: host) { /*[weak self]*/ signatureUploadResult in
            switch signatureUploadResult {
            case .failure(let error):
                self.logger.both(.error, "Error during uploadWatermark: \(error.localizedDescription)")
                completion(.failure(error))
                return

            case .success(let helloResponse):
                self.logger.both(.default, "Received hello response")

                switch self.parseHello(helloResponse) {
                case .failure(let err):
                    self.logger.both(.error, "Failed parseHello: \(err.localizedDescription)")
                    completion(.failure(err))
                    return

                case .success(let challenge):

                    self.logger.both(.default, "Sending auth...")
                    
                    self.uploadAuth(hostAsString: host, hubName: hubName, fillAuthFields: { pack in
                        switch auth {
                            
                        case .usernamePassword(let securePasswordCredentials):
                            pack.addStr(SoftEtherPackTag.userName, securePasswordCredentials.username)
                            pack.addInt(SoftEtherPackTag.authType, 1)

                            let securePassword20 = SoftEtherHandshaker.makeSecurePassword(
                                username: securePasswordCredentials.username,
                                password: securePasswordCredentials.password,
                                random20: challenge.random
                            )
                            pack.addBin("secure_password", securePassword20)
                            break
                            
                        case .usernameJWT(let jwtCredentials):
                            pack.addStr(SoftEtherPackTag.userName, jwtCredentials.username)
                            pack.addInt(SoftEtherPackTag.authType, 6)
                            pack.addStr(SoftEtherPackTag.jwt, jwtCredentials.jwt)
                            break
                        }
                    }, completion: { /*[weak self]*/ authUploadResult in
                            switch authUploadResult {
                            case .failure(let err):
                                self.logger.both(.error, "uploadAuth failed: \(err.localizedDescription)")
                                completion(.failure(err))
                                return

                            case .success(let welcomeResponse):
                                self.logger.both(.default, "Received welcome response")

                                switch self.parseWelcome(welcomeResponse) {
                                case .failure(let err):
                                    completion(.failure(err))
                                    return

                                case .success(.redirect(let ip, let ports)):
                                    // TODO: handle redirect
                                    self.logger.both(.default, "Received redirect in welcome response")
                                    completion(.failure(SoftEtherError("Redirect not implemented: \(ip):\(ports)")))
                                    return

                                case .success(.welcome(let params)):
                                    completion(.success(params))
                                    return
                                }
                            }
                        }
                    )
                }
            }
        }
    }

    // MARK: - Hello (watermark)

    /// Send watermark + random tail
    private func uploadWatermark(hostAsString: String, completion: @escaping (Result<(status: Int, headers: [String:String], body: Data), Error>) -> Void) {
        var body = Data(softEtherWatermarkAsBytes)
        // rand_size = Rand32() % (HTTP_PACK_RAND_SIZE_MAX * 2)
        let randSize = Int(arc4random_uniform(UInt32(SoftEtherHTTP.HTTP_PACK_RAND_SIZE_MAX * 2)))
        if randSize > 0 {
            var tail = [UInt8](repeating: 0, count: randSize)
            let rc = SecRandomCopyBytes(kSecRandomDefault, randSize, &tail)
            if rc == errSecSuccess {
                body.append(contentsOf: tail)
            } else {
                completion(.failure(SoftEtherError("Can't generate random tail.")))
                return
            }
        }

        let httpPostRequest = SoftEtherHTTP.makePOST(
            hostAsString: hostAsString,
            path: SoftEtherHTTP.Path.connect,
            contentType: SoftEtherHTTP.ContentType.image,
            body: body
        )

        logger.both(.default, "Sending watermark")
        secureConnection.send(data: httpPostRequest) { [weak self] error in
            guard let self else {
                return
            }

            if let error {
                logger.both(.error, "Failed on seding watermark")
                completion(.failure(error))
                return
            }

            logger.both(.default, "Sent watermark, wait response")
            SoftEtherHTTP.receiveAndReadHTTPResponse(with: self.secureConnection) {[weak self] result in
                self?.logger.both(.default, "Receive response on watermark")
                completion(result)
            }
        }
    }

    private func parseHello(_ response: (status: Int, headers: [String:String], body: Data)) -> Result<Challenge, Error> {
        if response.status != 200 {
            return .failure(SoftEtherError("Hello message from server with http status=\(response.status)"))
        }

        let body = response.body
        do {
            let pack = try SoftEtherPack.decode(body)

            if let responceWithError = pack.sepError {
                return .failure(SoftEtherError("Hello response contains error field. SepError=\(responceWithError)"))
            }

            guard let random = pack.sepRandom else {
                return .failure(SoftEtherError("Hello missing sepRandom. PACK=\(pack.debugDescription)"))
            }
            guard random.count == 20 else {
                return .failure(SoftEtherError("sepRandom size \(random.count) != 20"))
            }

            let serverVersion = pack.serverVer ?? 0
            let serverBuild = pack.serverBuild ?? 0
            let serverString = pack.serverStr ?? "Empty field from server"
            self.logger.both(.default, "In Hello response server info: version = \(serverVersion) build = \(serverBuild) string = \(serverString)")

            do {
                let challenge = try Challenge(random: random)
                return .success(challenge)
            } catch {
                return .failure(SoftEtherError("Wrong random format from server: \(error.localizedDescription)"))
            }

        } catch {
            return .failure(SoftEtherError("Decode Hello failed: \(error.localizedDescription)"))
        }
    }

    // MARK: - Auth

    /// SHA0(password + uppercase(username)) → H1 (20b)
    /// SHA0(H1 + random[20]) → secure_password (20b)
    private static func makeSecurePassword(username: String, password: String, random20: Data) -> Data {
        precondition(random20.count == 20, "random must be 20 bytes")
        let userUp = username.uppercased()

        let pwBytes   = Data(password.utf8)   // ASCII-compatible
        let userBytes = Data(userUp.utf8)

        let h1 = SHA0.hash(pwBytes + userBytes)
        let secure = SHA0.hash(h1 + random20)
        return secure  // 20 bytes
    }

    private func uploadAuth(hostAsString: String, hubName: String, fillAuthFields: (SoftEtherPack) -> Void, completion: @escaping (Result<(status: Int, headers: [String:String], body: Data), Error>) -> Void) {
        let pack = SoftEtherPack()
        pack.addStr(SoftEtherPackTag.method, "login")
        pack.addStr(SoftEtherPackTag.hubName, hubName)

        fillAuthFields(pack)

        if configuration.enabledUDPAcceleration, let udp = udpConnection {
            
            pack.addBool(SoftEtherPackTag.UdpAccelTags.useUdpAccel, true)

            let ipSoftEtherU32 = SoftEtherPack.IPToUInt32(udp.localIPv4)

            if ipSoftEtherU32 == 0x0100007F { // 127.0.0.1
                pack.addInt(SoftEtherPackTag.udpAccelClientIp, 0)
            } else {
                pack.addInt(SoftEtherPackTag.udpAccelClientIp, ipSoftEtherU32)
            }
            
            pack.addInt(SoftEtherPackTag.udpAccelClientPort, UInt32(udp.clientPort))

            pack.addBin(SoftEtherPackTag.udpAccelClientKeyV1, udp.clientKeyV1)       // 20 bytes
            pack.addBin(SoftEtherPackTag.udpAccelClientKeyV2, udp.clientKeyV2)    // 128 bytes

            pack.addBool(SoftEtherPackTag.supportHmacOnUdpAcceleration, false)
            pack.addBool(SoftEtherPackTag.supportUdpAccelFastDisconnectDetect, true)
            pack.addInt(SoftEtherPackTag.udpAccelerationMaxVersion, 2)
        } else {
            pack.addBool(SoftEtherPackTag.UdpAccelTags.useUdpAccel, false)
        }
        
        pack.addInt(SoftEtherPackTag.protocolType, 0)         // TCP
        pack.addInt(SoftEtherPackTag.useEncrypt, 1)
        pack.addInt(SoftEtherPackTag.useCompress, 0)
        pack.addInt(SoftEtherPackTag.maxConnection, 1)
        pack.addInt(SoftEtherPackTag.halfConnection, 0)
        pack.addBool(SoftEtherPackTag.qos, false)

        pack.addStr(SoftEtherPackTag.clientStr, "SoftEther VPN Client (macOS)")
        pack.addInt(SoftEtherPackTag.clientVer, 0000001)
        pack.addInt(SoftEtherPackTag.clientBuild, 1)

        var rnd = Data(count: Int.random(in: 0..<1000))
        let count = rnd.count
        _ = rnd.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        pack.addBin(SoftEtherPackTag.pencore, rnd)

        let body = pack.encode()

        self.logger.bothDump(.debug, "Final auth that will be sent to server: \(pack.debugDescription)")
        
        let httpPostRequest = SoftEtherHTTP.makePOST(hostAsString: hostAsString, path: SoftEtherHTTP.Path.vpn, contentType: SoftEtherHTTP.ContentType.application, body: body)
        
        secureConnection.send(data: httpPostRequest) { [weak self] error in
            guard let self else { return }

            if let error {
                completion(.failure(error))
                return
            }

            SoftEtherHTTP.receiveAndReadHTTPResponse(with: self.secureConnection) { result in
                completion(result)
            }
        }
    }

    // MARK: - Welcome

    enum AuthOutcome {
        case redirect(ip: UInt32, ports: [UInt32])
        case welcome(_ softEtherSessionInfo: SoftEtherSessionParams)
    }

    private func parseWelcome(_ response: (status: Int, headers: [String:String], body: Data)) -> Result<AuthOutcome, Error> {
        if response.status != 200 {
            return .failure(SoftEtherError("Welcome message from server with http status=\(response.status)"))
        }

        let body = response.body
        do {
            let pack = try SoftEtherPack.decode(body)

            if let responceWithError = pack.sepError {
                return .failure(SoftEtherError("Welcome response contains error field. SepError=\(responceWithError)"))
            }

            if let isRedirect = pack.isRedirect {
                if isRedirect {
                    guard let ip = pack.redirectIP else {
                        return .failure(SoftEtherError("Welcome response with redirect doesn't contain ip address."))
                    }
                    let ports = pack.redirectPorts
                    return .success(.redirect(ip: ip, ports: ports))
                } else {
                    logger.both(.default, "Welcome response contains redirect tag with value 0.")
                }
            }

            self.logger.bothDump(.debug, "Welcome pack: \(pack.debugDescription)")

            do {
                let sessionParams = try SoftEtherSessionParams(from: pack)
                return .success(.welcome(sessionParams))
            } catch {
                return .failure(SoftEtherError("Parsing Welcome failed: \(error.localizedDescription)"))
            }
        } catch {
            return .failure(SoftEtherError("Decode Welcome failed: \(error.localizedDescription)"))
        }
    }
}
