//
//  RSA.swift
//  JWT
//
//  Created by Sergey Minakov on 10.01.17.
//
//

import Foundation

//RS256	RSA using SHA-256 hash algorithm
//RS384	RSA using SHA-384 hash algorithm
//RS512	RSA using SHA-512 hash algorithm

public protocol RSASigner: Signer {
    
    var keys: JWT.Certificate.Keys { get }
    var hash: Hash { get }
}

public enum RSA {
    
    public enum Error: Swift.Error {
        case unsupported
    }
    
    case rs256(JWT.Certificate.Keys)
    case rs384(JWT.Certificate.Keys)
    case rs512(JWT.Certificate.Keys)
    
    public var keys: JWT.Certificate.Keys {
        switch self {
        case .rs256(let keys), .rs384(let keys), .rs512(let keys):
            return keys
        }
    }
    
    public var hash: Hash {
        switch self {
        case .rs256:
            return .sha256
        case .rs384:
            return .sha384
        case .rs512:
            return .sha512
        }
    }
    
    public var algorithm: String {
        switch self {
        case .rs256:
            return "RS256"
        case .rs384:
            return "RS384"
        case .rs512:
            return "RS512"
        }
    }
    
    public func sign(string: String) throws -> Data {
        throw Error.unsupported
    }
    
    public func verify(_ input: Data, with output: Data) throws -> Bool {
        throw Error.unsupported
    }
    
}
