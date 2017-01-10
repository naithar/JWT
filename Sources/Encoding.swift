//
//  Encoding.swift
//  JWT
//
//  Created by Sergey Minakov on 10.01.17.
//
//

import Foundation

public protocol Encodable {
    
    func decode(data: String) throws -> String
    func encode(string: String) throws -> String
    func encode(data: Data) throws -> String
}

public enum Encoding: Encodable {
    
    public enum Error: Swift.Error {
        case unsupported
        case nonUTF8String
    }
    
    case base64
    case base64URL
    
    public func decode(data: String) throws -> String {
        throw Error.unsupported
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
