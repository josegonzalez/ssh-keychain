import Foundation

/// In-process cache of unlocked `SSHSigner`s keyed by public-key fingerprint.
///
/// The cache lives inside the agent's process. After a Touch ID prompt unlocks
/// a key for the first time, the resulting signer stays warm for `ttl` seconds
/// so concurrent `ssh` invocations don't re-prompt the user.
///
/// Capacity-bounded; evicts the least-recently-used entry when full.
public actor KeyCache {
    public struct Entry {
        let signer: any SSHSigner
        var expiresAt: Date
        var lastAccess: Date
    }

    private var entries: [Data: Entry] = [:]
    public let ttl: TimeInterval
    public let maxEntries: Int

    public init(ttl: TimeInterval, maxEntries: Int = 32) {
        self.ttl = ttl
        self.maxEntries = maxEntries
    }

    public func get(blob: Data) -> (any SSHSigner)? {
        guard let entry = entries[blob] else { return nil }
        let now = Date()
        if entry.expiresAt < now {
            entries.removeValue(forKey: blob)
            return nil
        }
        // Bump LRU position. Entry is a struct value, so reassign to update.
        var bumped = entry
        bumped.lastAccess = now
        entries[blob] = bumped
        return entry.signer
    }

    public func put(blob: Data, signer: any SSHSigner) {
        guard ttl > 0 else { return }   // cache disabled
        let now = Date()
        entries[blob] = Entry(
            signer: signer,
            expiresAt: now.addingTimeInterval(ttl),
            lastAccess: now
        )
        evictIfNeeded()
    }

    public func flushAll() {
        entries.removeAll()
    }

    public struct Stats: Sendable {
        public let count: Int
        public let oldestEntryAge: TimeInterval?
    }

    public func stats() -> Stats {
        let now = Date()
        let oldest = entries.values.map { now.timeIntervalSince($0.lastAccess) }.max()
        return Stats(count: entries.count, oldestEntryAge: oldest)
    }

    private func evictIfNeeded() {
        guard entries.count > maxEntries else { return }
        // Find LRU victim
        guard let lru = entries.min(by: { $0.value.lastAccess < $1.value.lastAccess }) else { return }
        entries.removeValue(forKey: lru.key)
    }
}
