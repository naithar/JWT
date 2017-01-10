//
//  HMAC.swift
//  JWT
//
//  Created by Sergey Minakov on 10.01.17.
//
//

import Foundation

public protocol HMACSigner: Signer {
    
    var key: String { get }
    var hash: Hash { get }
}

public enum HMAC: HMACSigner {
    
    public enum Error: Swift.Error {
        case unsupported
    }
    
    case hs256(String)
    case hs384(String)
    case hs512(String)
    
    public var key: String {
        switch self {
        case .hs256(let key), .hs384(let key), .hs512(let key):
            return key
        }
    }
    
    public var hash: Hash {
        switch self {
        case .hs256:
            return .sha256
        case .hs384:
            return .sha384
        case .hs512:
            return .sha512
        }
    }
    
    public var algorithm: String {
        switch self {
        case .hs256:
            return "HS256"
        case .hs384:
            return "HS384"
        case .hs512:
            return "HS512"
        }
    }
    
    public func sign(string: String) throws -> Data {
        throw Error.unsupported
    }
    
    public func verify(_ input: Data, with output: Data) throws -> Bool {
        throw Error.unsupported
    }
}
