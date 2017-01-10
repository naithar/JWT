//
//  ECDSA.swift
//  JWT
//
//  Created by Sergey Minakov on 10.01.17.
//
//

import Foundation
import OpenSSL

public enum ECSAError: Swift.Error {
    case nonUTF8String
    case nonBase64EncodedKey
    case noKeyForCurve
    case cannotSign
    case noPublicKey
    case cannotCreatePublicKey
}

public protocol ECSASigner: Signer {
    
    var privateKey: String { get }
    var publicKey: String? { get }
    
    var curve: Int32 { get }
    var hash: Hash { get }
    
    init(`private` privateKey: String, `public` publicKey: String?)
    init(filePath: String)
    init(keys: JWT.Certificate.Keys)
}

public struct ES256 {
    
    public private (set) var privateKey: String
    public private (set) var publicKey: String?
    
    public let curve = NID_X9_62_prime256v1
    public let hash = Hash.sha256
    
    public let algorithm = "ES256"
    
    init(`private` privateKey: String, `public` publicKey: String? = nil) {
        self.privateKey = privateKey
        self.publicKey = publicKey
    }
    
    init(filePath: String) throws {
        let certificate = JWT.Certificate(pem: filePath)
        let keys = try certificate.keys()
        self.privateKey = keys.private
        self.publicKey = keys.public
    }
    
    init(keys: JWT.Certificate.Keys) {
        self.privateKey = keys.private
        self.publicKey = keys.public
    }
}

public struct ES384 {
    
    public private (set) var privateKey: String
    public private (set) var publicKey: String?
    
    public let curve = NID_secp384r1
    public let hash = Hash.sha384
    
    public let algorithm = "ES384"
    
    init(`private` privateKey: String, `public` publicKey: String? = nil) {
        self.privateKey = privateKey
        self.publicKey = publicKey
    }
    
    init(filePath: String) throws {
        let certificate = JWT.Certificate(pem: filePath)
        let keys = try certificate.keys()
        self.privateKey = keys.private
        self.publicKey = keys.public
    }
    
    init(keys: JWT.Certificate.Keys) {
        self.privateKey = keys.private
        self.publicKey = keys.public
    }
}

public struct ES512 {
    
    public private (set) var privateKey: String
    public private (set) var publicKey: String?
    
    public let curve = NID_secp521r1
    public let hash = Hash.sha512
    
    public let algorithm = "ES512"
    
    init(`private` privateKey: String, `public` publicKey: String? = nil) {
        self.privateKey = privateKey
        self.publicKey = publicKey
    }
    
    init(filePath: String) throws {
        let certificate = JWT.Certificate(pem: filePath)
        let keys = try certificate.keys()
        self.privateKey = keys.private
        self.publicKey = keys.public
    }
    
    init(keys: JWT.Certificate.Keys) {
        self.privateKey = keys.private
        self.publicKey = keys.public
    }
}

extension ECSASigner {
    
    private func newECKey() throws -> OpaquePointer {
        guard let key = EC_KEY_new_by_curve_name(self.curve) else {
            throw ECSAError.noKeyForCurve
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
        guard let publicKey = self.publicKey else {
            throw ECSAError.noPublicKey
        }
        var ecKey: OpaquePointer? = try self.newECKey()
        var publicBytesPointer: UnsafePointer<UInt8>?
        
        guard let key = Data(base64Encoded: publicKey) else {
            throw ECSAError.cannotCreatePublicKey
        }
        _ = key.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) in
            publicBytesPointer = UnsafePointer<UInt8>(bytes)
        }
        guard let publicECKey = o2i_ECPublicKey(&ecKey, &publicBytesPointer, key.count) else {
            throw ECSAError.cannotCreatePublicKey
        }
        return publicECKey
    }
    
    public func sign(string: String) throws -> Data {
        guard let inputData = string.data(using: .utf8) else {
            throw ECSAError.nonUTF8String
        }
        
        guard let keyData = Data(base64Encoded: self.privateKey) else {
            throw ECSAError.nonBase64EncodedKey
        }
        
        var hash = try self.hash.perform(on: inputData)
        let ecKeyPair = try self.newECKeyPair(for: keyData)
        
        guard let signature = ECDSA_do_sign(&hash, Int32(hash.count), ecKeyPair) else {
            throw ECSAError.cannotSign
        }
        
        var derEncodedSignature: UnsafeMutablePointer<UInt8>?
        let derLength = i2d_ECDSA_SIG(signature, &derEncodedSignature)
        
        guard let derCopy = derEncodedSignature, derLength > 0 else {
            throw ECSAError.cannotSign
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
