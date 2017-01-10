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
    
    var algorithm: String { get }
    
    func sign(string: String) throws -> Data
    func verify(_ input: Data, with output: Data) throws -> Bool
}

/*
 HS256	HMAC using SHA-256 hash algorithm
 HS384	HMAC using SHA-384 hash algorithm
 HS512	HMAC using SHA-512 hash algorithm
 RS256	RSA using SHA-256 hash algorithm
 RS384	RSA using SHA-384 hash algorithm
 RS512	RSA using SHA-512 hash algorithm
 ES256	ECDSA using P-256 curve and SHA-256 hash algorithm
 ES384	ECDSA using P-384 curve and SHA-384 hash algorithm
 ES512	ECDSA using P-521 curve and SHA-512 hash algorithm
 */

