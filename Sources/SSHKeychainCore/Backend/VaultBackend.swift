import Foundation
import NIOSSH

/// HashiCorp Vault KV-v2 backend.
///
/// Reads/writes secrets at `<address>/v1/<mount>/data/<prefix>/<key>` with the
/// `private_key` field by default. Per-source overrides on `vaultPath` and
/// `vaultField` are honored when the caller hands the backend a fully-qualified
/// path (used by the daemon to apply config-file per-source overrides).
///
/// The backend uses URLSession directly rather than a third-party HTTP client;
/// macOS Foundation has solid async/await support for what we need.
public actor VaultBackend: Backend {
    public nonisolated let name: String
    private let address: URL
    private let mount: String
    private let prefix: String?
    private let defaultField: String
    private let provider: any AuthProvider
    private let session: URLSession
    private let tokenCache: TokenCache

    public init(
        name: String,
        address: URL,
        mount: String,
        prefix: String?,
        defaultField: String = "private_key",
        provider: any AuthProvider,
        tokenCache: TokenCache,
        session: URLSession = .shared
    ) {
        self.name = name
        self.address = address
        self.mount = mount
        self.prefix = prefix
        self.defaultField = defaultField
        self.provider = provider
        self.tokenCache = tokenCache
        self.session = session
    }

    // MARK: Backend

    public func get(key: String) async throws -> Item {
        let json = try await read(path: dataPath(forKey: key))
        guard let data = json["data"] as? [String: Any],
              let inner = data["data"] as? [String: Any]
        else {
            throw VaultError.unexpectedShape("missing data.data envelope")
        }
        guard let pemString = inner[defaultField] as? String else {
            throw VaultError.fieldMissing(defaultField, key: key)
        }
        let pem = Data(pemString.utf8)
        let parsed = try KeyParser.parsePrivateKey(pem)
        return Item(
            key: key,
            publicKey: parsed.publicKey,
            signer: PEMSSHSigner(parsed: parsed),
            comment: parsed.comment
        )
    }

    public func put(key: String, pem: Data, options: PutOptions) async throws {
        guard let pemString = String(data: pem, encoding: .utf8) else {
            throw VaultError.unexpectedShape("pem not utf-8")
        }
        // Check existence to honor `overwrite` semantics, since Vault KV-v2
        // overwrites by default.
        if !options.overwrite {
            do {
                _ = try await read(path: dataPath(forKey: key))
                throw BackendError.exists
            } catch BackendError.notFound {
                // ok, doesn't exist
            }
        }
        let body: [String: Any] = [
            "data": [defaultField: pemString],
        ]
        _ = try await write(path: dataPath(forKey: key), body: body)
    }

    public func list(options: ListOptions) async throws -> [PublicItem] {
        let path = metadataPath(forKey: nil)
        var request = try makeRequest(path: path, method: "LIST")
        // Vault accepts both `LIST` HTTP verb and `?list=true` with GET. Use the
        // query-param form since some HTTP stacks reject non-standard verbs.
        var components = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "list", value: "true")]
        request.url = components.url
        request.httpMethod = "GET"
        let json = try await sendWithAuth(request: request, allowNotFound: true)
        guard let data = json["data"] as? [String: Any],
              let names = data["keys"] as? [String] else {
            return []
        }
        var items: [PublicItem] = []
        for name in names {
            // For each item, fetch the value to derive the public key. This is
            // unavoidable - Vault doesn't separately store a pubkey sidecar.
            // The cost shows up in `list` time and prompts only if the auth
            // provider needs Touch ID.
            guard let item = try? await get(key: name) else { continue }
            items.append(PublicItem(key: name, publicKey: item.publicKey, comment: item.comment))
        }
        return items
    }

    public func remove(key: String) async throws {
        let path = metadataPath(forKey: key)
        var request = try makeRequest(path: path, method: "DELETE")
        request.httpMethod = "DELETE"
        _ = try await sendWithAuth(request: request, allowNotFound: false)
    }

    // MARK: HTTP

    private func dataPath(forKey key: String) -> String {
        let p = prefix.map { "\($0)/" } ?? ""
        return "v1/\(mount)/data/\(p)\(key)"
    }

    private func metadataPath(forKey key: String?) -> String {
        let p = prefix.map { "\($0)/" } ?? ""
        if let key { return "v1/\(mount)/metadata/\(p)\(key)" }
        return "v1/\(mount)/metadata/\(p.dropLast())"
    }

    private func read(path: String) async throws -> [String: Any] {
        let request = try makeRequest(path: path, method: "GET")
        return try await sendWithAuth(request: request, allowNotFound: false)
    }

    private func write(path: String, body: [String: Any]) async throws -> [String: Any] {
        var request = try makeRequest(path: path, method: "POST")
        let data = try JSONSerialization.data(withJSONObject: body)
        request.httpBody = data
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        return try await sendWithAuth(request: request, allowNotFound: false)
    }

    private func makeRequest(path: String, method: String) throws -> URLRequest {
        let url = address.appending(path: path)
        var request = URLRequest(url: url)
        request.httpMethod = method
        return request
    }

    /// Adds the auth token, sends, and retries once on 403 after forcing a
    /// token refresh. Returns the parsed JSON body (empty dict for 204).
    private func sendWithAuth(request initial: URLRequest, allowNotFound: Bool) async throws -> [String: Any] {
        var request = initial
        let credential = try await tokenCache.token(for: provider)
        request.setValue(credential.token, forHTTPHeaderField: "X-Vault-Token")

        let (responseData, response) = try await session.data(for: request)
        let http = response as! HTTPURLResponse

        switch http.statusCode {
        case 200, 204:
            return try parseJSON(responseData)
        case 404 where allowNotFound:
            return [:]
        case 404:
            throw BackendError.notFound
        case 403:
            // Token may have been revoked; refresh and try again exactly once.
            await tokenCache.invalidate(for: provider.name)
            let refreshed = try await tokenCache.token(for: provider)
            var retry = initial
            retry.setValue(refreshed.token, forHTTPHeaderField: "X-Vault-Token")
            let (retryData, retryResponse) = try await session.data(for: retry)
            let retryHTTP = retryResponse as! HTTPURLResponse
            switch retryHTTP.statusCode {
            case 200, 204:
                return try parseJSON(retryData)
            case 404 where allowNotFound:
                return [:]
            case 404:
                throw BackendError.notFound
            default:
                throw VaultError.httpStatus(retryHTTP.statusCode, body: retryData)
            }
        default:
            throw VaultError.httpStatus(http.statusCode, body: responseData)
        }
    }

    private func parseJSON(_ data: Data) throws -> [String: Any] {
        if data.isEmpty { return [:] }
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw VaultError.unexpectedShape("response is not a JSON object")
        }
        return object
    }
}

public enum VaultError: Error {
    case httpStatus(Int, body: Data)
    case unexpectedShape(String)
    case fieldMissing(String, key: String)
}
