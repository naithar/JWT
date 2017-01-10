import XCTest
import Foundation
@testable import JWT

class JWTTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        var string = "Hello1"
        var encoded = try? Encoding.base64.encode(string: string)
        var decoded = try? Encoding.base64.decode(string: encoded!)
        
        print("\(string), \(encoded), \(decoded), \(String(data: decoded!, encoding: .utf8))")
        
        string = "Hello2"
        encoded = try? Encoding.base64URL.encode(string: string)
        decoded = try? Encoding.base64URL.decode(string: encoded!)
        
        print("\(string), \(encoded), \(decoded), \(String(data: decoded!, encoding: .utf8))")
    }


    static var allTests : [(String, (JWTTests) -> () throws -> Void)] {
        return [
            ("testExample", testExample),
        ]
    }
}
