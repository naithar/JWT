import PackageDescription

let package = Package(
    name: "JWT",
    dependencies: [
        .Package(url: "https://github.com/IBM-Swift/SwiftyJSON.git", majorVersion: 17)
    ]
)

#if os(Linux)
    package.dependencies.append(.Package(url: "https://github.com/IBM-Swift/OpenSSL.git", majorVersion: 0))
#else
    package.dependencies.append(.Package(url: "https://github.com/IBM-Swift/OpenSSL-OSX.git", majorVersion: 0))
#endif
