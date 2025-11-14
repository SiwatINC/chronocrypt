# ChronoCrypt

**Asymmetric Time-Based Data Encryption System**

A cryptographic library for temporal data access control with zero-knowledge authorization. ChronoCrypt uses asymmetric encryption (ECIES + AES-GCM) to enable data sources to encrypt temporal data streams while maintaining strong security properties even if the data source is compromised.

[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue.svg)](https://www.typescriptlang.org/)
[![Bun](https://img.shields.io/badge/Bun-1.0+-orange.svg)](https://bun.sh/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Security Model

ChronoCrypt implements an **asymmetric three-party architecture** where:

- **KeyHolder** (Trusted Zone): Generates and holds the master private key, authorizes access by deriving time-specific private keys
- **DataSource** (Untrusted Zone): Has only the public key, can encrypt but CANNOT decrypt
- **DataViewer** (Controlled Zone): Receives time-specific private keys from KeyHolder for authorized decryption

### Key Security Properties

✅ **DataSource Compromise Resistant**: If the DataSource is compromised, attackers cannot decrypt any data (no private key)
✅ **Temporal Binding**: Timestamps are cryptographically bound via HKDF - tampering prevents decryption
✅ **Authenticated Encryption**: AES-256-GCM with authentication tags detect any data tampering
✅ **Zero-Knowledge Authorization**: KeyHolder authorizes access without seeing encrypted data content
✅ **Granular Access Control**: Authorization at timestamp-level precision with extensible policies
✅ **Comprehensive Audit Trail**: All operations logged for compliance and forensics

## Features

- **Hybrid Asymmetric Encryption**: ECIES (EC P-256) + AES-256-GCM
- **HKDF Temporal Binding**: Timestamps cryptographically bound in key derivation
- **Three-Party Security Model**: Separation between encryption, authorization, and decryption
- **Flexible Policy System**: Extensible access control policies
- **Pluggable Storage**: Use in-memory, filesystem, or any database (Prisma examples included)
- **Full TypeScript/Bun Support**: Native async/await with Web Crypto API

## Installation

```bash
bun add @siwats/chronocrypt
```

## Quick Start

```typescript
import {
  generateMasterKeypair,
  exportPublicKey,
  createDataSource,
  createKeyHolder,
  createDataViewer,
  InMemoryEncryptedRepository,
  InMemoryAuditLog,
  createAllowAllPolicy
} from '@siwats/chronocrypt';

// 1. KeyHolder: Generate master keypair (keep private key secure!)
const masterKeypair = await generateMasterKeypair();
const publicKey = await exportPublicKey(masterKeypair.publicKey);

// 2. Setup storage
const repository = new InMemoryEncryptedRepository();
const auditLog = new InMemoryAuditLog();

// 3. DataSource: Encrypt data (PUBLIC KEY ONLY - cannot decrypt!)
const dataSource = createDataSource(publicKey, repository);
const data = new TextEncoder().encode('Sensitive temporal data');
const encrypted = await dataSource.encryptData(data);

// 4. KeyHolder: Authorize access
const keyHolder = createKeyHolder(masterKeypair, auditLog, [createAllowAllPolicy()]);
const authResponse = await keyHolder.authorizeAccess({
  requesterId: 'analyst-001',
  timeRange: { startTime: encrypted.timestamp, endTime: encrypted.timestamp },
  purpose: 'Data analysis'
});

// 5. DataViewer: Decrypt with authorized time-specific keys
const dataViewer = createDataViewer('analyst-001', auditLog);
dataViewer.loadAuthorizedKeys(authResponse.privateKeys!);
const decrypted = await dataViewer.decryptFromRepository(repository, encrypted.timestamp);

console.log(new TextDecoder().decode(decrypted!.data));
// Output: "Sensitive temporal data"
```

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         KeyHolder (Trusted)                      │
│  • Holds master private key                                     │
│  • Derives time-specific private keys                           │
│  • Enforces access control policies                             │
│  • Never sees encrypted data                                    │
└────────────────┬───────────────────────────────┬────────────────┘
                 │ Master Public Key             │ Time-Specific
                 ↓                               │ Private Keys
┌────────────────────────────┐                  ↓
│   DataSource (Untrusted)   │        ┌──────────────────────────┐
│  • Has PUBLIC key only     │        │  DataViewer (Controlled)  │
│  • Encrypts temporal data  │        │  • Receives authorized    │
│  • CANNOT decrypt          │        │    time-specific keys     │
│  • Stores encrypted data   │        │  • Decrypts only          │
└────────────────────────────┘        │    authorized data        │
                                      └──────────────────────────┘
```

## Cryptographic Details

### Encryption (DataSource)

1. Generate random AES-256 symmetric key `K`
2. Encrypt data: `ciphertext = AES-256-GCM(K, data, IV)`
3. Generate ephemeral ECDH keypair `(e_priv, e_pub)`
4. Perform ECDH: `shared_secret = ECDH(e_priv, recipient_public)`
5. Derive wrapping key: `wrap_key = HKDF(shared_secret, salt=timestamp, info='ChronoCrypt-Wrap-v1')`
6. Wrap symmetric key: `wrapped_K = AES-KW(wrap_key, K)`
7. Package: `{timestamp, wrapped_K, e_pub, ciphertext, IV, auth_tag}`

### Decryption (DataViewer)

1. Perform ECDH: `shared_secret = ECDH(time_specific_private, e_pub)`
2. Derive unwrapping key: `unwrap_key = HKDF(shared_secret, salt=timestamp, info='ChronoCrypt-Wrap-v1')`
3. Unwrap symmetric key: `K = AES-KW-UNWRAP(unwrap_key, wrapped_K)`
4. Decrypt data: `data = AES-256-GCM-DECRYPT(K, ciphertext, IV, auth_tag)`

**Temporal Binding**: The timestamp is used as salt in HKDF. Changing the timestamp in the encrypted package causes HKDF to derive a different key, making unwrapping fail.

## Storage Options

ChronoCrypt provides flexible storage through simple interfaces. Choose the storage backend that fits your needs:

### Built-in Storage

**In-Memory** (included) - Perfect for testing and development:
```typescript
import { InMemoryEncryptedRepository, InMemoryAuditLog } from '@siwats/chronocrypt';

const repository = new InMemoryEncryptedRepository();
const auditLog = new InMemoryAuditLog();
```

### Database Storage

**Prisma (PostgreSQL/SQLite)** - Production-ready database storage:

See [`examples/prisma/PRISMA_SETUP.md`](examples/prisma/PRISMA_SETUP.md) for complete setup guide with schema and implementation examples.

### Custom Storage

Implement your own storage by following the interfaces:

```typescript
import type { EncryptedDataRepository, AuditLogStorage } from '@siwats/chronocrypt';

class MyCustomRepository implements EncryptedDataRepository {
  async store(pkg: EncryptedPackage): Promise<void> { /* ... */ }
  async retrieve(timestamp: Timestamp): Promise<EncryptedPackage | null> { /* ... */ }
  async retrieveRange(range: TimeRange): Promise<EncryptedPackage[]> { /* ... */ }
  async exists(timestamp: Timestamp): Promise<boolean> { /* ... */ }
}
```

## Access Control Policies

ChronoCrypt supports extensible access control policies. Currently implemented:

```typescript
// Allow all requests (for development/testing)
createAllowAllPolicy()

// TODO: Additional policies coming soon
// - Requester whitelist
// - Time-based restrictions
// - Purpose validation
// - Maximum duration limits
```

Create custom policies by implementing the `AccessControlPolicy` interface:

```typescript
const customPolicy: AccessControlPolicy = {
  id: 'my-policy',
  name: 'My Custom Policy',
  evaluate: async (request: AccessRequest) => {
    // Return true to allow, false to deny
    return request.requesterId.startsWith('trusted-');
  },
  priority: 100
};
```

## Complete Example

See [`examples/complete-example.ts`](examples/complete-example.ts) for a full IoT sensor data encryption workflow demonstrating:
- Master keypair generation
- DataSource encryption (untrusted zone)
- KeyHolder authorization (trusted zone)
- DataViewer decryption (controlled zone)
- Audit log review
- Security properties demonstration

Run the example:
```bash
bun run examples/complete-example.ts
```

## Testing

Run the comprehensive test suite:

```bash
bun test
```

Test coverage includes:
- Asymmetric key generation and derivation
- Hybrid encryption/decryption (ECIES + AES-GCM)
- Temporal binding via HKDF
- Authentication failure detection
- End-to-end workflows
- Security property verification

## API Reference

### Core Cryptographic Functions

```typescript
// Generate EC P-256 master keypair
generateMasterKeypair(): Promise<MasterKeypair>

// Export/import public key (JWK format)
exportPublicKey(publicKey: CryptoKey): Promise<ExportedPublicKey>
importPublicKey(jwk: ExportedPublicKey): Promise<CryptoKey>

// Derive time-specific private key
deriveTimeSpecificPrivateKey(
  masterPrivateKey: CryptoKey,
  timestamp: Timestamp
): Promise<TimeSpecificPrivateKey>

// Hybrid encryption/decryption
encryptData(
  data: Uint8Array,
  recipientPublicKey: ExportedPublicKey,
  timestamp: Timestamp,
  metadata?: Record<string, unknown>
): Promise<EncryptedPackage>

decryptData(
  pkg: EncryptedPackage,
  timeSpecificPrivateKey: TimeSpecificPrivateKey
): Promise<Uint8Array>
```

### Entity Creation

```typescript
// Create DataSource (receives public key only)
createDataSource(
  publicKey: ExportedPublicKey,
  repository: EncryptedDataRepository,
  timestampGenerator?: () => Timestamp
): DataSource

// Create KeyHolder (holds private key)
createKeyHolder(
  masterKeypair: MasterKeypair,
  auditLog: AuditLogStorage,
  policies?: AccessControlPolicy[],
  keyHolderId?: string
): KeyHolder

// Create DataViewer
createDataViewer(
  viewerId: string,
  auditLog?: AuditLogStorage
): DataViewer
```

## Security Considerations

### Key Management

- **Master Private Key**: Must be stored securely (HSM, secure enclave, etc.)
- **Public Key**: Can be distributed to untrusted DataSources
- **Time-Specific Keys**: Temporary, can be destroyed after use
- **Key Rotation**: Generate new master keypair periodically

### Threat Model

✅ **Protected Against**:
- DataSource compromise (no decryption capability)
- Timestamp tampering (KDF binding)
- Data tampering (GCM authentication)
- Unauthorized decryption (requires KeyHolder authorization)

⚠️ **Not Protected Against**:
- Master private key compromise (grants access to all time periods)
- KeyHolder compromise (can authorize any access)
- Side-channel attacks (timing, power analysis)

### Best Practices

1. **Separate environments**: Run KeyHolder in isolated, highly secure environment
2. **Limit DataSource privileges**: DataSources should only have public key and repository access
3. **Audit log review**: Regularly review audit logs for suspicious access patterns
4. **Key rotation**: Implement periodic master keypair rotation
5. **Policy enforcement**: Use strict access control policies in production

## Contributing

Contributions welcome! Please ensure:
- All tests pass (`bun test`)
- Code follows existing style
- Security-sensitive changes include threat model analysis

## License

MIT

## Acknowledgments

ChronoCrypt implements industry-standard cryptographic primitives:
- **ECIES**: Elliptic Curve Integrated Encryption Scheme
- **ECDH**: Elliptic Curve Diffie-Hellman (P-256/secp256r1)
- **HKDF**: HMAC-based Key Derivation Function (RFC 5869)
- **AES-GCM**: Advanced Encryption Standard - Galois/Counter Mode
- **AES-KW**: AES Key Wrap (RFC 3394)

All cryptographic operations use the Web Crypto API for security and performance.
