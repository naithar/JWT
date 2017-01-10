
import Foundation
import SwiftyJSON

public struct Token {
    
    public enum Error: Swift.Error {
        case notJSON
    }
    
    public private (set) var headers: [String : String]
    public private (set) var payload: [String : String]
    public private (set) var encoding: Encodable
    public private (set) var signer: Signer
    
    public private (set) var encoded = (
        header: String?.none,
        payload: String?.none,
        signature: String?.none
    )
    
    public var token: String {
        return "\(self.encoded.header).\(self.encoded.payload).\(self.encoded.signature)"
    }
    
    public init(headers: [String : String],
         payload: [String : String],
         encoding: Encodable,
         signer: Signer) throws {
        self.headers = headers
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
}
