//
//  Unsigned.swift
//  JWT
//
//  Created by Sergey Minakov on 10.01.17.
//
//

import Foundation


public struct Unsigned: Signer {
    
    public var algorithm: String {
        return "none"
    }
    
    public func sign(string: String) throws -> Data {
        return Data()
    }
    
    public func verify(_ input: Data, with output: Data) throws -> Bool {
        return true
    }
}
