import XCTest
@testable import JWT

class JWTTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        XCTAssertEqual(JWT().text, "Hello, World!")
    }


    static var allTests : [(String, (JWTTests) -> () throws -> Void)] {
        return [
            ("testExample", testExample),
        ]
    }
}