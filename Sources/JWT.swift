
import Foundation
import OpenSSL

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
    
    public typealias KeysValue = (`private`: String, `public`: String)
    
    public private (set) var filePath: String
    public private (set) var type = Type.pem
    
    private var _parsedKeys: KeysValue?
    
    internal static var hexStringRegex: NSRegularExpression = {
        return try! NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive)
    }()
    
    public func keys() throws -> KeysValue {
        if let keys = self._parsedKeys {
            return keys
        }
        
        self._parsedKeys = try Certificate.keys(for: self.filePath)
        
        return self._parsedKeys!
    }
    
    public init(pem filePath: String) {
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

        return (extractedPrivateKey, extractedPublicKey)
    }
}

extension Data {
    
    init(fromHexString string: String) {
        self.init(capacity: string.characters.count / 2)
        
        let regex = Certificate.hexStringRegex
        let stringRange = NSMakeRange(0, string.characters.count)
        regex.enumerateMatches(in: string,
                               range: stringRange) { match, flags, stop in
                                guard let match = match,
                                    let range = string.range(from: match.range),
                                    let byteString = String?.some(string.substring(with: range)),
                                    var num = UInt8(byteString, radix: 16) else {
                                        return
                                }
                                
                                self.append(&num, count: 1)
        }
    }
}

extension String {
    
    func split(byLength length: Int) -> [String] {
        var result = [String]()
        
        func offset(from index: String.Index, with offset: Int) -> String.Index {
            return self.index(index, offsetBy: offset, limitedBy: self.endIndex) ?? self.endIndex
        }
        
        func range(from index: String.Index, with length: Int) -> Range<String.Index> {
            return index..<offset(from: index, with: length)
        }
        
        var splitRange = range(from: self.startIndex, with: length)
        
        while splitRange.lowerBound != self.endIndex {
            let substring = self.substring(with: splitRange)
            result.append(substring)
            splitRange = range(from: splitRange.upperBound, with: length)
        }
        
        return result
    }
    
    func range(from nsRange: NSRange) -> Range<String.Index>? {
        guard let from16 = self.utf16.index(utf16.startIndex, offsetBy: nsRange.location, limitedBy: utf16.endIndex),
            let to16 = self.utf16.index(from16, offsetBy: nsRange.length, limitedBy: utf16.endIndex),
            let from = String.Index(from16, within: self),
            let to = String.Index(to16, within: self) else {
                return nil
        }
        return from..<to
    }
}

extension String {
    
    static func decode(base64URLEncoded data: Data) -> String? {
        return self.init(data: data, encoding: .utf8)?
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
