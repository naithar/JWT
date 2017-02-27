//
//  Certificate.swift
//  JWT
//
//  Created by Sergey Minakov on 10.01.17.
//
//

import Foundation
import OpenSSL

#if os(Linux)
internal typealias NSRegularExpression = RegularExpression
#endif

public class Certificate {
    
    public enum Error: Swift.Error {
        case noFile
        case cannotParse
        case cannotReadPrivateKey
        case noECKey
        case cannotExtractPrivateKey
    }
    
    public enum `Type` {
        case pem
    }
    
    public struct Keys {
        
        public var `private`: String
        public var `public`: String
    }
    
    public private (set) var filePath: String
    public private (set) var type = Type.pem
    
    private var _parsedKeys: Keys?
    
    internal static var hexStringRegex: NSRegularExpression = {
        return try! NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive)
    }()
    
    public func keys() throws -> Keys {
        if let keys = self._parsedKeys {
            return keys
        }
        
        self._parsedKeys = try Certificate.keys(for: self.filePath)
        
        return self._parsedKeys!
    }
    
    public init(pem filePath: String) {
        self.filePath = filePath
    }
    
    private static func keys(for path: String) throws -> Keys {
        let directoryName: String
        let fileName: String
        
        if let range = path.range(of: "/", options: .backwards) {
            directoryName = path.substring(to: range.upperBound)
            fileName = path.substring(from: range.upperBound)
        } else {
            directoryName = ""
            fileName = path
        }
        
        let resultPath = directoryName + "." + fileName
        
        guard FileManager.default.fileExists(atPath: path) else {
            throw Error.noFile
        }
        
        if !FileManager.default.fileExists(atPath: resultPath) {
            let key = try String(contentsOfFile: path, encoding: .utf8)
                .replacingOccurrences(of: "-----BEGIN PRIVATE KEY-----", with: "")
                .replacingOccurrences(of: "-----END PRIVATE KEY-----", with: "")
                .trimmingCharacters(in: .whitespacesAndNewlines)
            
            let splittedText = key.split(byLength: 64)
            let newText = "-----BEGIN PRIVATE KEY-----\n\(splittedText.joined(separator: "\n"))\n-----END PRIVATE KEY-----"
            try newText.write(toFile: resultPath, atomically: false, encoding: .utf8)
        }
        
        var privateKey = EVP_PKEY_new()
        let file = fopen(resultPath, "r")
        defer { fclose(file) }
        
        guard PEM_read_PrivateKey(file, &privateKey, nil, nil) != nil else {
            throw Error.cannotReadPrivateKey
        }
        
        guard let ecKey = EVP_PKEY_get1_EC_KEY(privateKey) else {
            throw Error.noECKey
        }
        
        var publicKey: UnsafeMutablePointer<UInt8>?
        let publicKeyLength = Int(i2o_ECPublicKey(ecKey, &publicKey))
        let publicKeyString: String
        
        if let publicKey = publicKey {
            var array = [UInt8](repeating: 0, count: publicKeyLength)
            for i in 0..<publicKeyLength {
                array[i] = publicKey[i]
            }
            let publicData = Data(bytes: array)
            publicKeyString = publicData.reduce("") { $0 + String(format: "%02X", $1) }
        } else {
            publicKeyString = ""
        }
        
        let bn = EC_KEY_get0_private_key(ecKey)
        guard let privateKeyBN = BN_bn2hex(bn),
            let privateKeyStringPart = String.init(validatingUTF8: privateKeyBN),
            let privateKeyString = String?.some("00\(privateKeyStringPart)") else {
                throw Error.cannotExtractPrivateKey
        }
        
        let extractedPrivateKey = Data(fromHexString: privateKeyString).base64EncodedString()
        let extractedPublicKey = Data(fromHexString: publicKeyString).base64EncodedString()
        
        return Keys(private: extractedPrivateKey, public: extractedPublicKey)
    }
}
