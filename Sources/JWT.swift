
import Foundation
import OpenSSL

public struct Certificate {
    
    public enum Error: Swift.Error {
        case noFile
        case cannotParse
        case cannotReadPrivateKey
        case noECKey
        case cannotExtractPrivateKey
        case cannotExtractPublicKey
    }
    
    public enum `Type` {
        case pem
    }
    
    public typealias KeysValue = (`private`: String, `public`: String)
    
    public private (set) var filePath: String
    public private (set) var type = Type.pem
    
    private var _parsedKeys: KeysValue?
    
    public mutating func keys() throws -> KeysValue {
        if let keys = self._parsedKeys {
            return keys
        }
        
        self._parsedKeys = try Certificate.keys(for: self.filePath)
        
        return self._parsedKeys!
    }
    
    init(pem filePath: String) {
        self.filePath = filePath
    }
    
    private static func keys(for path: String) throws -> KeysValue {
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
            
            let splittedText = key.splitByLength(64)
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
            let privateKeyString = String?.some("00\(privateKeyStringPart)"),
            let extractedPrivateKey = privateKeyString.dataFromHexadecimalString()?.base64EncodedString() else {
                throw Error.cannotExtractPrivateKey
        }
        
        guard let extractedPublicKey = publicKeyString.dataFromHexadecimalString()?.base64EncodedString() else {
            throw Error.cannotExtractPublicKey
        }

        return (extractedPrivateKey, extractedPublicKey)
    }
}

extension String {
    func dataFromHexadecimalString() -> NSData? {
        let data = NSMutableData(capacity: characters.count / 2)
        
        let regex = try! NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive)
        regex.enumerateMatches(in: self, options: [], range: NSMakeRange(0, characters.count)) { match, flags, stop in
            let range = self.range(from: match!.range)
            let byteString = self.substring(with: range!)
            var num = UInt8(byteString, radix: 16)
            data?.append(&num, length: 1)
        }
        
        return data
    }
    
    func splitByLength(_ length: Int) -> [String] {
        var result = [String]()
        var collectedCharacters = [Character]()
        collectedCharacters.reserveCapacity(length)
        var count = 0
        
        for character in self.characters {
            collectedCharacters.append(character)
            count += 1
            if (count == length) {
                // Reached the desired length
                count = 0
                result.append(String(collectedCharacters))
                collectedCharacters.removeAll(keepingCapacity: true)
            }
        }
        
        // Append the remainder
        if !collectedCharacters.isEmpty {
            result.append(String(collectedCharacters))
        }
        
        return result
    }
}

extension String {
    
    static func decode(base64URLEncoded data: Data) -> String? {
        return self.init(data: data, encoding: .utf8)?
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
    
    func range(from nsRange: NSRange) -> Range<String.Index>? {
        guard
            let from16 = utf16.index(utf16.startIndex, offsetBy: nsRange.location, limitedBy: utf16.endIndex),
            let to16 = utf16.index(from16, offsetBy: nsRange.length, limitedBy: utf16.endIndex),
            let from = String.Index(from16, within: self),
            let to = String.Index(to16, within: self)
            else { return nil }
        return from ..< to
    }
}
