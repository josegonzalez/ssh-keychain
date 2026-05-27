import Foundation

/// XPC interface vended by the ssh-keychain agent for the macOS app and the
/// `ssh-keychain status`/`doctor` CLI subcommands.
///
/// All methods are completion-handler-based because NSXPCConnection does not
/// yet bridge to Swift Concurrency natively. The client wrapper
/// (`DaemonXPCClient`) wraps each call in a continuation to present an
/// `async` interface.
@objc public protocol DaemonXPC {
    func status(reply: @escaping (DaemonStatus) -> Void)
    func reload(reply: @escaping (Bool, NSError?) -> Void)
    func lockAll(reply: @escaping (Bool) -> Void)
    func recentActivity(limit: Int, reply: @escaping ([ActivityEvent]) -> Void)
    func listSourceCandidates(backend: String, reply: @escaping ([String], NSError?) -> Void)
    func testBackend(configJSON: Data, reply: @escaping (Bool, NSError?) -> Void)
}

/// Snapshot of the daemon's state surface for the app's menu bar + Activity view.
///
/// `NSSecureCoding` required for XPC marshalling. We hand-implement it via
/// `NSKeyedArchiver` so the in-Core types stay value-typed where possible.
@objc(SSHKeychainDaemonStatus)
public final class DaemonStatus: NSObject, NSSecureCoding, @unchecked Sendable {
    public static var supportsSecureCoding: Bool { true }

    @objc public let running: Bool
    @objc public let version: String
    @objc public let socketPath: String
    @objc public let configPath: String?
    @objc public let lastReloadAt: Date?
    @objc public let identities: [LoadedIdentity]

    public init(
        running: Bool,
        version: String,
        socketPath: String,
        configPath: String?,
        lastReloadAt: Date?,
        identities: [LoadedIdentity]
    ) {
        self.running = running
        self.version = version
        self.socketPath = socketPath
        self.configPath = configPath
        self.lastReloadAt = lastReloadAt
        self.identities = identities
    }

    public func encode(with coder: NSCoder) {
        coder.encode(running, forKey: "running")
        coder.encode(version, forKey: "version")
        coder.encode(socketPath, forKey: "socketPath")
        coder.encode(configPath, forKey: "configPath")
        coder.encode(lastReloadAt, forKey: "lastReloadAt")
        coder.encode(identities, forKey: "identities")
    }

    public init?(coder: NSCoder) {
        self.running = coder.decodeBool(forKey: "running")
        guard let version = coder.decodeObject(of: NSString.self, forKey: "version") as String? else { return nil }
        self.version = version
        guard let socketPath = coder.decodeObject(of: NSString.self, forKey: "socketPath") as String? else { return nil }
        self.socketPath = socketPath
        self.configPath = coder.decodeObject(of: NSString.self, forKey: "configPath") as String?
        self.lastReloadAt = coder.decodeObject(of: NSDate.self, forKey: "lastReloadAt") as Date?
        let identities = coder.decodeArrayOfObjects(ofClass: LoadedIdentity.self, forKey: "identities") ?? []
        self.identities = identities
    }
}

@objc(SSHKeychainLoadedIdentity)
public final class LoadedIdentity: NSObject, NSSecureCoding, @unchecked Sendable {
    public static var supportsSecureCoding: Bool { true }

    @objc public let backend: String
    @objc public let key: String
    @objc public let fingerprint: String         // "SHA256:..."
    @objc public let comment: String
    @objc public let biometric: Bool
    @objc public let cached: Bool
    @objc public let lastUsedAt: Date?

    public init(backend: String, key: String, fingerprint: String, comment: String,
                biometric: Bool, cached: Bool, lastUsedAt: Date?)
    {
        self.backend = backend
        self.key = key
        self.fingerprint = fingerprint
        self.comment = comment
        self.biometric = biometric
        self.cached = cached
        self.lastUsedAt = lastUsedAt
    }

    public func encode(with coder: NSCoder) {
        coder.encode(backend, forKey: "backend")
        coder.encode(key, forKey: "key")
        coder.encode(fingerprint, forKey: "fingerprint")
        coder.encode(comment, forKey: "comment")
        coder.encode(biometric, forKey: "biometric")
        coder.encode(cached, forKey: "cached")
        coder.encode(lastUsedAt, forKey: "lastUsedAt")
    }

    public init?(coder: NSCoder) {
        guard let backend = coder.decodeObject(of: NSString.self, forKey: "backend") as String?,
              let key = coder.decodeObject(of: NSString.self, forKey: "key") as String?,
              let fingerprint = coder.decodeObject(of: NSString.self, forKey: "fingerprint") as String?,
              let comment = coder.decodeObject(of: NSString.self, forKey: "comment") as String?
        else { return nil }
        self.backend = backend
        self.key = key
        self.fingerprint = fingerprint
        self.comment = comment
        self.biometric = coder.decodeBool(forKey: "biometric")
        self.cached = coder.decodeBool(forKey: "cached")
        self.lastUsedAt = coder.decodeObject(of: NSDate.self, forKey: "lastUsedAt") as Date?
    }
}

@objc(SSHKeychainActivityEvent)
public final class ActivityEvent: NSObject, NSSecureCoding, @unchecked Sendable {
    public static var supportsSecureCoding: Bool { true }

    @objc public let timestamp: Date
    @objc public let fingerprint: String         // sha256 of the public key blob
    @objc public let signatureLength: Int
    @objc public let callingProcess: String?     // resolved via socket peer cred, if known

    public init(timestamp: Date, fingerprint: String, signatureLength: Int, callingProcess: String?) {
        self.timestamp = timestamp
        self.fingerprint = fingerprint
        self.signatureLength = signatureLength
        self.callingProcess = callingProcess
    }

    public func encode(with coder: NSCoder) {
        coder.encode(timestamp, forKey: "timestamp")
        coder.encode(fingerprint, forKey: "fingerprint")
        coder.encode(signatureLength, forKey: "signatureLength")
        coder.encode(callingProcess, forKey: "callingProcess")
    }

    public init?(coder: NSCoder) {
        guard let timestamp = coder.decodeObject(of: NSDate.self, forKey: "timestamp") as Date?,
              let fingerprint = coder.decodeObject(of: NSString.self, forKey: "fingerprint") as String?
        else { return nil }
        self.timestamp = timestamp
        self.fingerprint = fingerprint
        self.signatureLength = coder.decodeInteger(forKey: "signatureLength")
        self.callingProcess = coder.decodeObject(of: NSString.self, forKey: "callingProcess") as String?
    }
}
