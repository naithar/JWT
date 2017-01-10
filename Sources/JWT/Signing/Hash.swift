//
//  Hash.swift
//  JWT
//
//  Created by Sergey Minakov on 10.01.17.
//
//

import Foundation
import OpenSSL

public enum Hash {
    
    public enum Error: Swift.Error {
        case cannotHash
    }
    
    case sha256
    case sha384
    case sha512
    
    private func perform<T>(on message: Data,
                         context: T,
                         init initMethod: (UnsafeMutablePointer<T>) -> Int32,
                         update updateMethod: (UnsafeMutablePointer<T>, UnsafeRawPointer, Int) -> Int32,
                         final finalMethod: (UnsafeMutablePointer<UInt8>, UnsafeMutablePointer<T>) -> Int32,
                         length: Int) throws -> [UInt8] {
        var context = context
        var message = message
        
        guard initMethod(&context) == 1 else {
            throw Error.cannotHash
        }
        
        _ = try message.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) in
            guard updateMethod(&context, bytes, message.count) == 1 else {
                throw Error.cannotHash
            }
        }
        
        var digest = [UInt8](repeating: 0, count: length)
        guard finalMethod(&digest, &context) == 1 else {
            throw Error.cannotHash
        }
        
        return digest
    }

    public func perform(on input: Data) throws -> [UInt8] {
        switch self {
        case .sha256:
            return try self
                .perform(on: input,
                         context: SHA256_CTX(),
                         init: SHA256_Init,
                         update: SHA256_Update,
                         final: SHA256_Final,
                         length: Int(SHA256_DIGEST_LENGTH))
        case .sha384:
            return try self
                .perform(on: input,
                         context: SHA512_CTX(),
                         init: SHA384_Init,
                         update: SHA384_Update,
                         final: SHA384_Final,
                         length: Int(SHA384_DIGEST_LENGTH))
        case .sha512:
            return try self
                .perform(on: input,
                         context: SHA512_CTX(),
                         init: SHA512_Init,
                         update: SHA512_Update,
                         final: SHA512_Final,
                         length: Int(SHA512_DIGEST_LENGTH))
        }
    }
}
