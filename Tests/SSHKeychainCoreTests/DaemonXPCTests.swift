import Foundation
import XCTest
@testable import SSHKeychainCore

/// End-to-end XPC tests using an anonymous listener + the in-process server.
/// Validates that the protocol marshals correctly and the client/service pair
/// can exchange `DaemonStatus`, activity events, and reload calls.
final class DaemonXPCTests: XCTestCase {
    func testStatusRoundTrip() async throws {
        let registry = BackendRegistry()
        let agent = AgentService(registry: registry, cacheTTL: 0)
        // No sources loaded - status should still report `running`.
        try await agent.loadSources([])

        let service = DaemonXPCService(agent: agent, socketPath: "/tmp/test.sock", configPath: nil)
        let server = DaemonXPCServer(anonymousServing: service)
        defer { server.invalidate() }

        let client = DaemonXPCClient(endpoint: .listener(server.listener.endpoint))
        defer { client.disconnect() }

        let status = await client.status()
        XCTAssertNotNil(status)
        XCTAssertTrue(status?.running ?? false)
        XCTAssertEqual(status?.socketPath, "/tmp/test.sock")
        XCTAssertEqual(status?.identities.count, 0)
    }

    func testReloadRoundTrip() async throws {
        let registry = BackendRegistry()
        let agent = AgentService(registry: registry, cacheTTL: 0)
        try await agent.loadSources([])

        let service = DaemonXPCService(agent: agent, socketPath: "/tmp/test.sock", configPath: nil)
        let server = DaemonXPCServer(anonymousServing: service)
        defer { server.invalidate() }

        let client = DaemonXPCClient(endpoint: .listener(server.listener.endpoint))
        defer { client.disconnect() }

        try await client.reload()
        // reload doesn't return a value; absence of throw is the assertion.
    }

    func testLockAllRoundTrip() async throws {
        let registry = BackendRegistry()
        let agent = AgentService(registry: registry, cacheTTL: 60)
        try await agent.loadSources([])

        let service = DaemonXPCService(agent: agent, socketPath: "/tmp/test.sock", configPath: nil)
        let server = DaemonXPCServer(anonymousServing: service)
        defer { server.invalidate() }

        let client = DaemonXPCClient(endpoint: .listener(server.listener.endpoint))
        defer { client.disconnect() }

        let ok = await client.lockAll()
        XCTAssertTrue(ok)
    }
}
