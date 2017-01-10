//
//  String+Extensions.swift
//  JWT
//
//  Created by Sergey Minakov on 10.01.17.
//
//

import Foundation

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
