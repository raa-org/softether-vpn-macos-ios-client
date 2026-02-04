import Foundation
import CryptoKit

struct SoftEtherHTTP {

    enum Path: String {
        case vpn     = "/vpnsvc/vpn.cgi"
        case connect = "/vpnsvc/connect.cgi"
    }
    
    enum ContentType: String {
        case image          = "image/jpeg"
        case application    = "application/octet-stream"
    }
    
    static let HTTP_PACK_RAND_SIZE_MAX = 1000
    
    static func makePOST(hostAsString: String, path: Path, contentType: ContentType, body: Data) -> Data {
        var head = ""
        head += "POST \(path.rawValue) HTTP/1.1\r\n"
        head += "Host: \(hostAsString)\r\n"
        //head += "User-Agent: Mozilla/5.0\r\n"
        head += "Content-Type: \(contentType.rawValue)\r\n"   // same as in source of SE (HTTP_CONTENT_TYPE3)
        head += "Connection: Keep-Alive\r\n"
        head += "Content-Length: \(body.count)\r\n"
        head += "\r\n"
        var req = Data(head.utf8)
        req.append(body)
        return req
    }
    
    // MARK: - HTTP parsing utils

    static func parseHTTPHeaders(_ head: String) throws -> (status: Int, headers: [String:String]) {
        let lines = head.split(separator: "\r\n", omittingEmptySubsequences: false)
        guard let statusLine = lines.first else {
            throw NSError(domain: "SoftEther", code: -10, userInfo: [NSLocalizedDescriptionKey:"Empty status line"])
        }
        // e.g. "HTTP/1.1 200 OK"
        let parts = statusLine.split(separator: " ")
        guard parts.count >= 2, let status = Int(parts[1]) else {
            throw NSError(domain: "SoftEther", code: -11, userInfo: [NSLocalizedDescriptionKey:"Bad status line: \(statusLine)"])
        }
        var headers: [String:String] = [:]
        for line in lines.dropFirst() {
            if line.isEmpty { continue }
            if let idx = line.firstIndex(of: ":") {
                let key = line[..<idx].trimmingCharacters(in: .whitespaces)
                let val = line[line.index(after: idx)...].trimmingCharacters(in: .whitespaces)
                headers[key.lowercased()] = val
            }
        }
        return (status, headers)
    }
    
    static func receiveAndReadHTTPResponse(with connection: SecureTCPConnection, completion: @escaping (Result<(status: Int, headers: [String:String], body: Data), Error>) -> Void) {
        
        var buf = Data()

        func pumpHeaders() {
            
            connection.receive { chunk, error in
                
                if let err = error {
                    completion(.failure(err));
                    return
                }
                
                guard let chunk = chunk else {
                    completion(.failure(NSError(domain: "SoftEther", code: -12, userInfo: [NSLocalizedDescriptionKey:"EOF before headers"])))
                    return
                }
                buf.append(chunk)

                if let range = buf.range(of: Data([13,10,13,10])) { // \r\n\r\n
                    let headData = buf[..<range.lowerBound]
                    let rest = Data(buf[range.upperBound...]) // what recieved after header

                    guard let head = String(data: headData, encoding: .ascii) else {
                        completion(.failure(NSError(domain: "SoftEther", code: -13, userInfo: [NSLocalizedDescriptionKey:"Bad header encoding"])))
                        return
                    }

                    do {
                        let (status, headers) = try SoftEtherHTTP.parseHTTPHeaders(head)
                        let clStr = headers["content-length"]
                        let contentLength = clStr.flatMap(Int.init) ?? 0

                        // SoftEther doesn't used chunked. In a case of chunked - fail.
                        if headers["transfer-encoding"]?.lowercased() == "chunked" {
                            completion(.failure(NSError(domain: "SoftEther", code: -14, userInfo: [NSLocalizedDescriptionKey:"Chunked not supported"])))
                            return
                        }

                        var body = rest
                        if body.count >= contentLength {
                            completion(.success((status, headers, Data(body.prefix(contentLength)))))
                            return
                        }

                        // Read the rest of body
                        func pumpBody() {
                            connection.receive { more, err in
                                if let err = err {
                                    completion(.failure(err)); return
                                }
                                guard let more = more else {
                                    completion(.failure(NSError(domain: "SoftEther", code: -15, userInfo: [NSLocalizedDescriptionKey:"EOF in body"])))
                                    return
                                }
                                body.append(more)
                                if body.count >= contentLength {
                                    completion(.success((status, headers, Data(body.prefix(contentLength)))))
                                    return
                                }
                                pumpBody()
                            }
                        }
                        pumpBody()
                    } catch {
                        completion(.failure(error))
                    }
                    return
                }
                pumpHeaders()
            }
        }
        pumpHeaders()
    }
}
