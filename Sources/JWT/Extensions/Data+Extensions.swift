//
//  Data+Extensions.swift
//  JWT
//
//  Created by Sergey Minakov on 10.01.17.
//
//

import Foundation

extension Data {
    
    init(fromHexString string: String) {
        var result = Data(capacity: string.characters.count / 2)
        
        let regex = Certificate.hexStringRegex
        let stringRange = NSMakeRange(0, string.characters.count)
        regex.enumerateMatches(in: string, options: [],
                               range: stringRange) { match, flags, stop in
                                guard let match = match,
                                    let range = string.range(from: match.range),
                                    let byteString = String?.some(string.substring(with: range)),
                                    var num = UInt8(byteString, radix: 16) else {
                                        return
                                }
                                
                                result.append(&num, count: 1)
        }
        
        self = result
    }
    
}
