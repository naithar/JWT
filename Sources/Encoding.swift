//
//  Encoding.swift
//  JWT
//
//  Created by Sergey Minakov on 10.01.17.
//
//

import Foundation

public protocol Encodable {
    
    func decode(string: String) throws -> Data
    func encode(string: String) throws -> String
    func encode(data: Data) throws -> String
}

public enum Encoding: Encodable {
    
    public enum Error: Swift.Error {
        case nonUTF8String
        case nonBase64String
    }
    
    case base64
    case base64URL
    
    public func decode(string: String) throws -> Data {
        
        func decode(base64: String) throws -> Data {
            guard let data = Data(base64Encoded: base64) else {
                throw Error.nonBase64String
            }
            return data
        }
        
        switch self {
        case .base64:
            return try decode(base64: string)
        case .base64URL:
            var converted = string.utf8CString.map { char -> CChar in
                switch char {
                case 45: // '-'
                    return  43 // '+'
                case 95: // '_'
                    return 47 // '/'
                default:
                    return char
                }
            }
            guard let unpadded = String(utf8String: &converted) else {
                throw Error.nonUTF8String
            }
            
            let characterCount = unpadded.utf8CString.count - 1 // ignore last /0
            let paddingRemainder = (characterCount % 4)
            let paddingCount = paddingRemainder > 0 ? 4 - paddingRemainder : 0
            let padding = Array(repeating: "=", count: paddingCount).joined()
            
            let base64String = unpadded + padding
            
            return try decode(base64: base64String)
        }
    }
    
    public func encode(string: String) throws -> String {
        guard let data = string.data(using: .utf8) else {
            throw Error.nonUTF8String
        }
        
        return try self.encode(data: data)
    }
    
    public func encode(data: Data) throws -> String {
        let base64String = data.base64EncodedString()
        
        switch self {
        case .base64:
            return base64String
        case .base64URL:
            return base64String
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
    }
}
