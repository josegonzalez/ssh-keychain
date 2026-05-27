import Foundation
import XCTest
@testable import SSHKeychainCore

/// Vault backend tests against a `URLProtocol` mock instead of a real Vault
/// dev server. The mock validates that we send the right URL + token, returns
/// canned responses, and verifies the 403-retry path.
final class VaultBackendTests: XCTestCase {
    var staticToken: String!
    var samplePEM: Data!

    override func setUp() async throws {
        staticToken = "hvs.test-token"
        samplePEM = try generateEd25519PEM()
        VaultMockProtocol.reset()
    }

    override func tearDown() async throws {
        VaultMockProtocol.reset()
    }

    func testGetFetchesAndParses() async throws {
        let backend = try makeBackend()

        VaultMockProtocol.responder = { request -> (Int, Data) in
            XCTAssertEqual(request.url?.path, "/v1/secret/data/ssh/alice")
            XCTAssertEqual(request.value(forHTTPHeaderField: "X-Vault-Token"), "hvs.test-token")
            let pemString = String(data: self.samplePEM, encoding: .utf8)!
            let body: [String: Any] = ["data": ["data": ["private_key": pemString]]]
            return (200, try! JSONSerialization.data(withJSONObject: body))
        }

        let item = try await backend.get(key: "alice")
        XCTAssertEqual(item.key, "alice")
    }

    func testGetReturnsNotFoundOn404() async throws {
        let backend = try makeBackend()
        VaultMockProtocol.responder = { _ in (404, Data()) }
        do {
            _ = try await backend.get(key: "missing")
            XCTFail("expected notFound")
        } catch let err as BackendError {
            XCTAssertEqual(err, .notFound)
        }
    }

    func testForbiddenTriggersTokenRefreshAndRetry() async throws {
        let backend = try makeBackend()
        let pemString = String(data: samplePEM, encoding: .utf8)!
        let body: [String: Any] = ["data": ["data": ["private_key": pemString]]]
        let bodyData = try JSONSerialization.data(withJSONObject: body)

        let counter = Counter()
        VaultMockProtocol.responder = { _ in
            let n = counter.next()
            if n == 1 { return (403, Data()) }
            return (200, bodyData)
        }
        let item = try await backend.get(key: "alice")
        XCTAssertEqual(item.key, "alice")
        XCTAssertEqual(counter.value, 2, "expected exactly one retry after 403")
    }

    func testPutRejectsDuplicateWithoutOverwrite() async throws {
        let backend = try makeBackend()
        let pemString = String(data: samplePEM, encoding: .utf8)!
        let body: [String: Any] = ["data": ["data": ["private_key": pemString]]]
        let bodyData = try JSONSerialization.data(withJSONObject: body)
        VaultMockProtocol.responder = { _ in (200, bodyData) }
        do {
            try await backend.put(key: "alice", pem: samplePEM, options: PutOptions())
            XCTFail("expected exists")
        } catch let err as BackendError {
            XCTAssertEqual(err, .exists)
        }
    }

    func testPutWritesNewSecret() async throws {
        let backend = try makeBackend()
        var receivedBody: Data?
        VaultMockProtocol.responder = { request -> (Int, Data) in
            if request.httpMethod == "GET" {
                // Existence check: report 404 so the put proceeds.
                return (404, Data())
            }
            if request.httpMethod == "POST" {
                receivedBody = VaultMockProtocol.readBody(from: request)
                return (200, Data("{}".utf8))
            }
            return (405, Data())
        }
        try await backend.put(key: "alice", pem: samplePEM, options: PutOptions())
        XCTAssertNotNil(receivedBody, "POST body should have been captured")
        let parsed = try JSONSerialization.jsonObject(with: receivedBody!) as! [String: Any]
        let data = parsed["data"] as! [String: Any]
        XCTAssertNotNil(data["private_key"])
    }

    // MARK: helpers

    private func makeBackend() throws -> VaultBackend {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [VaultMockProtocol.self]
        let session = URLSession(configuration: configuration)
        setenv("SSK_TEST_VAULT_TOKEN", staticToken, 1)
        let provider = StaticAuthProvider(
            name: "test-vault",
            source: EnvSecretSource(variable: "SSK_TEST_VAULT_TOKEN")
        )
        return VaultBackend(
            name: "test",
            address: URL(string: "http://vault.example.test")!,
            mount: "secret",
            prefix: "ssh",
            provider: provider,
            tokenCache: TokenCache(persistToKeychain: false),
            session: session
        )
    }

    private func generateEd25519PEM() throws -> Data {
        let dir = FileManager.default.temporaryDirectory
            .appending(path: "vault-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let keyURL = dir.appending(path: "k")
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        p.arguments = ["-t", "ed25519", "-f", keyURL.path, "-N", "", "-C", "test"]
        p.standardOutput = Pipe()
        p.standardError = Pipe()
        try p.run()
        p.waitUntilExit()
        return try Data(contentsOf: keyURL)
    }
}

/// URLProtocol that routes every request to a closure for inspection +
/// response generation. The closure is `nonisolated(unsafe)` so tests can
/// reassign it across awaits.
final class VaultMockProtocol: URLProtocol, @unchecked Sendable {
    static nonisolated(unsafe) var responder: ((URLRequest) -> (Int, Data))?

    static func reset() {
        responder = nil
    }

    /// Reads the body of a request that may have come from `httpBody` or
    /// from `httpBodyStream` (URLSession turns POST bodies into streams).
    static func readBody(from request: URLRequest) -> Data? {
        if let data = request.httpBody { return data }
        guard let stream = request.httpBodyStream else { return nil }
        var buffer = Data()
        let chunkSize = 4096
        stream.open()
        defer { stream.close() }
        let temp = UnsafeMutablePointer<UInt8>.allocate(capacity: chunkSize)
        defer { temp.deallocate() }
        while stream.hasBytesAvailable {
            let read = stream.read(temp, maxLength: chunkSize)
            if read <= 0 { break }
            buffer.append(temp, count: read)
        }
        return buffer
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let responder = Self.responder else {
            client?.urlProtocol(self, didFailWithError: NSError(domain: "mock", code: 0))
            return
        }
        let (status, data) = responder(request)
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: [:]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
