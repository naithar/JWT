
import Foundation
import SwiftyJSON

public struct Token {
    
    public enum Error: Swift.Error {
        case notJSON
        case wrongToken
        case wrongTokenJSON
    }
    
    public private (set) var headers: [String : Any]
    public private (set) var payload: [String : Any]
    public private (set) var encoding: Encodable
    public private (set) var signer: Signer
    
    public private (set) var encoded: (header: String, payload: String, signature: String)
    
    public var token: String {
        return "\(self.encoded.header).\(self.encoded.payload).\(self.encoded.signature)"
    }
    
    public var isValid: Bool {
        let value = "\(self.encoded.header).\(self.encoded.payload)"
        guard let input = value.data(using: .utf8),
            let signature = try? self.encoding.decode(string: self.encoded.signature),
            let result = try? self.signer.verify(input, with: signature) else {
                return false
        }
        
        return result
    }
    
    public init(headers: [String : Any],
                payload: [String : Any],
                encoding: Encodable = Encoding.base64,
                signer: Signer) throws {
        var resultHeaders = [String : Any]()
        resultHeaders["alg"] = signer.algorithm
        resultHeaders["typ"] = "JWT"
        
        for (key, value) in headers {
            resultHeaders[key] = value
        }
        
        self.headers = resultHeaders
        
        self.payload = payload
        self.encoding = encoding
        self.signer = signer
        
        guard let headerString = JSON(self.headers).rawString() else {
            throw Error.notJSON
        }
        
        guard let payloadString = JSON(self.payload).rawString() else {
            throw Error.notJSON
        }
        
        self.encoded.header = try self.encoding.encode(string: headerString)
        self.encoded.payload = try self.encoding.encode(string: payloadString)
        
        let signerInput = "\(self.encoded.header).\(self.encoded.payload)"
        let signatureData = try self.signer.sign(string: signerInput)
        
        self.encoded.signature = try self.encoding.encode(data: signatureData)
    }
    
    public init(token: String,
                encoding: Encodable = Encoding.base64,
                signer: Signer) throws {
        self.encoding = encoding
        self.signer = signer
        
        let segments = token.components(separatedBy: ".")
        
        guard segments.count == 3 else {
            throw Error.wrongToken
        }
        
        self.encoded.header = segments[0]
        self.encoded.payload = segments[1]
        self.encoded.signature = segments[2]
        
        let headerJSONData = try encoding.decode(string: self.encoded.header)
        let payloadJSONData = try encoding.decode(string: self.encoded.payload)
        
        guard let headers = JSON(data: headerJSONData).dictionaryObject else {
            throw Error.wrongTokenJSON
        }
        
        self.headers = headers
        
        guard let payload = JSON(data: payloadJSONData).dictionaryObject else {
            throw Error.wrongTokenJSON
        }
        
        self.payload = payload
    }
}
