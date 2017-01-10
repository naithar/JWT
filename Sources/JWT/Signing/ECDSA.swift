//
//  ECDSA.swift
//  JWT
//
//  Created by Sergey Minakov on 10.01.17.
//
//

import Foundation
import OpenSSL

public protocol ECSASigner: Signer {
    
    var keys: JWT.Certificate.Keys { get }
    var curve: Int32 { get }
    var hash: Hash { get }
}

public enum ECDSA: ECSASigner {
    
    public enum Error: Swift.Error {
        case nonUTF8String
        case nonBase64EncodedKey
        case noKeyForCurve
        case cannotSign
        case cannotCreatePublicKey
    }
    
    case es256(JWT.Certificate.Keys)
    case es384(JWT.Certificate.Keys)
    case es512(JWT.Certificate.Keys)
    
    public var curve: Int32 {
        switch self {
        case .es256:
            return NID_X9_62_prime256v1
        case .es384:
            return NID_secp384r1
        case .es512:
            return NID_secp521r1
        }
    }
    
    public var hash: Hash {
        switch self {
        case .es256:
            return .sha256
        case .es384:
            return .sha384
        case .es512:
            return .sha512
        }
    }
    
    public var keys: JWT.Certificate.Keys {
        switch self {
        case .es256(let keys), .es384(let keys), .es512(let keys):
            return keys
        }
    }
    
    public var algorithm: String {
        switch self {
        case .es256:
            return "ES256"
        case .es384:
            return "ES384"
        case .es512:
            return "ES512"
        }
    }
    
    public func sign(string: String) throws -> Data {
        guard let inputData = string.data(using: .utf8) else {
            throw Error.nonUTF8String
        }
        
        guard let keyData = Data(base64Encoded: self.keys.private) else {
            throw Error.nonBase64EncodedKey
        }
        
        var hash = try self.hash.perform(on: inputData)
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
        let digest = try self.hash.perform(on: input)
        let ecKey = try self.newECPublicKey()
        return ECDSA_do_verify(digest, Int32(digest.count), signature, ecKey) == 1
    }
}

extension ECDSA {
    
    private func newECKey() throws -> OpaquePointer {
        guard let key = EC_KEY_new_by_curve_name(self.curve) else {
            throw Error.noKeyForCurve
        }
        
        return key
        
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
        var ecKey: OpaquePointer? = try self.newECKey()
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
