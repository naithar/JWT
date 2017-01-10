//
//  Signer.swift
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

