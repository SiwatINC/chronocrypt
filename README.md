# ChronoCrypt

**Time-Based Granular Data Encryption System**

A cryptographic library for temporal data access control with zero-knowledge authorization. ChronoCrypt enables data sources to encrypt temporal data streams while allowing key holders to authorize selective decryption access for specific time periods without exposing the underlying data content.

[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue.svg)](https://www.typescriptlang.org/)
[![Bun](https://img.shields.io/badge/Bun-1.0+-orange.svg)](https://bun.sh/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Temporal Isolation**: Each time unit receives cryptographically independent treatment
- **Zero-Knowledge Authorization**: Key management entities operate without access to encrypted data content
- **Granular Access Control**: Authorization at the finest temporal resolution required
- **Forward Secrecy**: Compromise of past keys does not compromise future data security
- **Authenticated Encryption**: AES-256-CBC with HMAC-SHA256 authentication
- **Flexible Policy System**: Extensible access control policies
- **Comprehensive Audit Logging**: Full audit trail of all access authorization activities

## Installation

```bash
bun add @siwats/chronocrypt
```

## Quick Start

```typescript
import {
  generateMasterKey,
  createDataSource,
  createKeyHolder,
  createDataViewer,
  InMemoryEncryptedRepository,
  InMemoryAuditLog,
  createAllowAllPolicy
} from '@siwats/chronocrypt';

// Setup: Create master key and storage
const masterKey = generateMasterKey();
const repository = new InMemoryEncryptedRepository();
const auditLog = new InMemoryAuditLog();

// Data Source: Encrypt temporal data
const dataSource = createDataSource(repository, masterKey);
const data = new TextEncoder().encode('Sensitive temporal data');
const encrypted = await dataSource.encryptData(data);

// Key Holder: Authorize access
const keyHolder = createKeyHolder(masterKey, auditLog, [createAllowAllPolicy()]);
const authResponse = await keyHolder.authorizeAccess({
  requesterId: 'analyst-001',
  timeRange: { startTime: encrypted.timestamp, endTime: encrypted.timestamp },
  purpose: 'Data analysis'
});

// Data Viewer: Decrypt authorized data
const dataViewer = createDataViewer('analyst-001', auditLog);
dataViewer.loadAuthorizedKeys(authResponse.keys!);
const decrypted = await dataViewer.decryptFromRepository(repository, encrypted.timestamp);
```

## Testing

```bash
bun test
```

## License

MIT
