import Crypto
import Foundation
import NIOSSH

/// Coordinates between the agent server (NIO-side) and the backends.
///
/// Holds the loaded identity map (public-key blob -> backend + key name) and
/// the `KeyCache` for warm signers. Built at agent startup by resolving the
/// configured `SourceSpec`s against the `BackendRegistry`.
public actor AgentService {
    public struct Identity: Sendable {
        public let backend: String
        public let key: String
        public let publicKey: NIOSSHPublicKey
        public let comment: String
    }

    private var identities: [Data: Identity] = [:]   // keyed by public-key blob
    private var loadedSpecs: [SourceSpec] = []        // remembered for SIGHUP reload
    private var activityRing: [ActivityEvent] = []    // bounded recent events for XPC
    private let activityCapacity = 256
    private(set) public var lastReloadAt: Date?
    private let registry: BackendRegistry
    private let cache: KeyCache

    public init(registry: BackendRegistry, cacheTTL: TimeInterval, cacheMaxEntries: Int = 32) {
        self.registry = registry
        self.cache = KeyCache(ttl: cacheTTL, maxEntries: cacheMaxEntries)
    }

    /// Load identities for one or more `SourceSpec`s. Calls `Backend.list` per
    /// backend and rejects explicit-key sources that don't match. The specs
    /// are remembered for `reload()`.
    public func loadSources(_ specs: [SourceSpec]) async throws {
        self.loadedSpecs = specs
        try await rebuildIdentities()
    }

    /// Re-enumerate from the previously-loaded source specs. Used by SIGHUP.
    /// On error, the previous identity map is preserved and the caller is
    /// informed via the thrown error.
    public func reload() async throws {
        try await rebuildIdentities()
        await cache.flushAll()
    }

    /// Replace the loaded specs entirely (config-file reload triggered the
    /// daemon to discover a new source list).
    public func replaceSources(_ specs: [SourceSpec]) async throws {
        self.loadedSpecs = specs
        try await rebuildIdentities()
        await cache.flushAll()
        self.lastReloadAt = Date()
    }

    public func listBackendCandidates(backend: String) async throws -> [String] {
        let b = try await registry.resolve(backend)
        let items = try await b.list(options: ListOptions(publicKeysOnly: true))
        return items.map(\.key)
    }

    private func rebuildIdentities() async throws {
        var next: [Data: Identity] = [:]
        for spec in loadedSpecs {
            let backend = try await registry.resolve(spec.backend)
            let publicItems = try await backend.list(options: ListOptions(publicKeysOnly: true))
            switch spec.keys {
            case .wildcard:
                for item in publicItems {
                    next[item.publicKey.sshKeyBlob] = Identity(
                        backend: spec.backend,
                        key: item.key,
                        publicKey: item.publicKey,
                        comment: item.comment ?? "\(spec.backend):\(item.key)"
                    )
                }
            case .explicit(let names):
                let byKey = Dictionary(uniqueKeysWithValues: publicItems.map { ($0.key, $0) })
                for name in names {
                    guard let item = byKey[name] else {
                        throw AgentServiceError.unknownKey(backend: spec.backend, key: name)
                    }
                    next[item.publicKey.sshKeyBlob] = Identity(
                        backend: spec.backend,
                        key: item.key,
                        publicKey: item.publicKey,
                        comment: item.comment ?? "\(spec.backend):\(item.key)"
                    )
                }
            }
        }
        // Atomic swap - assignment doesn't yield, so concurrent Sign requests
        // either see the old map (already in flight) or the new map.
        identities = next
    }

    /// Snapshot of currently-loaded identities for `RequestIdentities` responses.
    public func currentIdentities() -> [AgentProtocol.IdentitiesAnswer.Identity] {
        identities.values
            .sorted { $0.backend < $1.backend || ($0.backend == $1.backend && $0.key < $1.key) }
            .map { id in
                AgentProtocol.IdentitiesAnswer.Identity(keyBlob: id.publicKey.sshKeyBlob, comment: id.comment)
            }
    }

    /// Produce a signature for `data` using the key identified by `keyBlob`.
    /// Falls back to the backend if the cache misses.
    public func sign(keyBlob: Data, data: Data, flags: UInt32) async throws -> Data {
        _ = flags  // v1 only signs ed25519/ECDSA, neither uses sha2 flags
        guard let id = identities[keyBlob] else {
            throw AgentServiceError.notLoaded
        }
        if let cached = await cache.get(blob: keyBlob) {
            return try await cached.sign(data: data)
        }
        let backend = try await registry.resolve(id.backend)
        let item = try await backend.get(key: id.key)
        await cache.put(blob: keyBlob, signer: item.signer)
        let signature = try await item.signer.sign(data: data)
        recordSignActivity(keyBlob: keyBlob, signatureLength: signature.count)
        return signature
    }

    private func recordSignActivity(keyBlob: Data, signatureLength: Int) {
        let fingerprint = sha256Fingerprint(keyBlob)
        let event = ActivityEvent(
            timestamp: Date(),
            fingerprint: fingerprint,
            signatureLength: signatureLength,
            callingProcess: nil   // resolution via peer cred lands in phase 26
        )
        activityRing.append(event)
        if activityRing.count > activityCapacity {
            activityRing.removeFirst(activityRing.count - activityCapacity)
        }
    }

    /// Snapshot of the most-recent sign events. Used by the XPC service.
    public func recentActivity(limit: Int) -> [ActivityEvent] {
        Array(activityRing.suffix(max(0, limit)))
    }

    /// Snapshot of loaded identities for the XPC `status` response.
    public func loadedIdentities() async -> [LoadedIdentity] {
        var out: [LoadedIdentity] = []
        for id in identities.values {
            let fingerprint = sha256Fingerprint(id.publicKey.sshKeyBlob)
            let cached = await cache.get(blob: id.publicKey.sshKeyBlob) != nil
            out.append(LoadedIdentity(
                backend: id.backend,
                key: id.key,
                fingerprint: fingerprint,
                comment: id.comment,
                biometric: false,   // phase 26 surfaces backend-reported biometric flag
                cached: cached,
                lastUsedAt: nil
            ))
        }
        return out.sorted { $0.backend < $1.backend || ($0.backend == $1.backend && $0.key < $1.key) }
    }

    public func flushCache() async {
        await cache.flushAll()
    }

    /// Human-readable snapshot suitable for SIGUSR1 debugging dumps.
    public func dumpState() async -> String {
        let stats = await cache.stats()
        var lines: [String] = []
        lines.append("ssh-keychain agent state:")
        lines.append("  identities loaded: \(identities.count)")
        for id in identities.values.sorted(by: { $0.backend < $1.backend || ($0.backend == $1.backend && $0.key < $1.key) }) {
            let fp = sha256Fingerprint(id.publicKey.sshKeyBlob)
            lines.append("    \(id.backend):\(id.key)  \(fp)")
        }
        lines.append("  cache: count=\(stats.count)" +
                     (stats.oldestEntryAge.map { ", oldest=\(String(format: "%.1f", $0))s" } ?? ""))
        return lines.joined(separator: "\n") + "\n"
    }
}

private func sha256Fingerprint(_ blob: Data) -> String {
    // Mirrors `ssh-keygen -l`: SHA256:<base64 with no padding>.
    let digest = blob.sha256()
    let b64 = digest.base64EncodedString().trimmingCharacters(in: CharacterSet(charactersIn: "="))
    return "SHA256:\(b64)"
}

private extension Data {
    func sha256() -> Data {
        Data(Crypto.SHA256.hash(data: self))
    }
}

public enum AgentServiceError: Error, Sendable, Equatable {
    case unknownKey(backend: String, key: String)
    case notLoaded
}
