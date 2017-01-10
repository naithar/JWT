//
//  Signature.swift
//  JWT
//
//  Created by Sergey Minakov on 10.01.17.
//
//

import Foundation
import OpenSSL

public protocol Signer {
    
    func sign(string: String) throws -> Data
    func verify(_ input: Data, with output: Data) throws -> Bool
}

public struct ES256: Signer {
    
    public enum Error: Swift.Error {
        case nonUTF8String
        case nonBase64EncodedKey
        case noKeyForCurve
        case cannotHash
        case cannotSign
        case cannotCreatePublicKey
    }
    
    public private (set) var curve = NID_X9_62_prime256v1
    public private (set) var keys: JWT.Certificate.Keys
    
    public init(`private` privateKey: String, `public` publicKey: String) {
        self.keys = JWT.Certificate.Keys(private: privateKey, public: publicKey)
    }
    
    public init(keys: JWT.Certificate.Keys) {
        self.keys = keys
    }
    
    public func sign(string: String) throws -> Data {
        guard let inputData = string.data(using: .utf8) else {
            throw Error.nonUTF8String
        }
        
        guard let keyData = Data(base64Encoded: self.keys.private) else {
            throw Error.nonBase64EncodedKey
        }
        
        var hash = try self.hash(for: inputData)
        let ecKeyPair = try self.newECKeyPair(for: keyData)
        
        guard let signature = ECDSA_do_sign(&hash, Int32(hash.count), ecKeyPair) else {
            throw Error.cannotSign
        }
        
        var derEncodedSignature: UnsafeMutablePointer<UInt8>?
        let derLength = i2d_ECDSA_SIG(signature, &derEncodedSignature)
        
        guard let derCopy = derEncodedSignature, derLength > 0 else {
            throw Error.cannotSign
        }
        
        var derBytes = [UInt8](repeating: 0, count: Int(derLength))
        
        for b in 0..<Int(derLength) {
            derBytes[b] = derCopy[b]
        }
        
        return Data(bytes: derBytes)
    }
    
    public func verify(_ input: Data, with output: Data) throws -> Bool {
        let outputBytes = [UInt8](output)
        var signaturePointer: UnsafePointer? = UnsafePointer(outputBytes)
        let signature = d2i_ECDSA_SIG(nil, &signaturePointer, outputBytes.count)
        let digest = try self.hash(for: input)
        let ecKey = try self.newECPublicKey()
        return ECDSA_do_verify(digest, Int32(digest.count), signature, ecKey) == 1
    }
}

extension ES256 {
    
    private func newECKey() throws -> OpaquePointer {
        guard let key = EC_KEY_new_by_curve_name(self.curve) else {
            throw Error.noKeyForCurve
        }
        
        return key
        
    }
    
    fileprivate func hash(for message: Data) throws -> [UInt8] {
        var context = SHA256_CTX()
        var message = message
        
        guard SHA256_Init(&context) == 1 else {
            throw Error.cannotHash
        }
        
        _ = try message.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) in
            guard SHA256_Update(&context, bytes, message.count) == 1 else {
                throw Error.cannotHash
            }
        }
        
        var digest = [UInt8](repeating: 0, count: Int(SHA256_DIGEST_LENGTH))
        guard SHA256_Final(&digest, &context) == 1 else {
            throw Error.cannotHash
        }
        
        return digest
    }
    
    fileprivate func newECKeyPair(for key: Data) throws -> OpaquePointer {
        var privateNum = BIGNUM()
        
        BN_init(&privateNum)
        
        _ = key.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) in
            BN_bin2bn(bytes, Int32(key.count), &privateNum)
        }
        
        let ecKey = try self.newECKey()
        EC_KEY_set_private_key(ecKey, &privateNum)
        
        // Derive public key
        let context = BN_CTX_new()
        BN_CTX_start(context)
        
        let group = EC_KEY_get0_group(ecKey)
        let publicKey = EC_POINT_new(group)
        EC_POINT_mul(group, publicKey, &privateNum, nil, nil, context)
        EC_KEY_set_public_key(ecKey, publicKey)
        
        EC_POINT_free(publicKey)
        BN_CTX_end(context)
        BN_CTX_free(context)
        BN_clear_free(&privateNum)
        
        return ecKey
    }
    
    fileprivate func newECPublicKey() throws -> OpaquePointer {
        var ecKey: OpaquePointer? = try newECKey()
        var publicBytesPointer: UnsafePointer<UInt8>?
        
        guard let key = Data(base64Encoded: self.keys.public) else {
            throw Error.cannotCreatePublicKey
        }
        _ = key.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) in
            publicBytesPointer = UnsafePointer<UInt8>(bytes)
        }
        guard let publicECKey = o2i_ECPublicKey(&ecKey, &publicBytesPointer, key.count) else {
            throw Error.cannotCreatePublicKey
        }
        return publicECKey
    }
}
