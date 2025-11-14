# Using Prisma with ChronoCrypt

This guide shows how to use Prisma (PostgreSQL or SQLite) as the storage backend for ChronoCrypt's encrypted data repository and audit logs.

## Overview

ChronoCrypt provides storage interfaces that can be implemented with any database solution. This directory contains reference implementations using Prisma ORM, supporting both PostgreSQL and SQLite.

## Setup

### 1. Install Dependencies

```bash
bun add @siwats/chronocrypt @prisma/client
bun add -d prisma
```

### 2. Initialize Prisma

Copy the schema file to your project:

```bash
mkdir -p prisma
cp examples/prisma/schema.prisma prisma/
```

### 3. Configure Database

**For PostgreSQL:**

Create a `.env` file:

```env
DATABASE_URL="postgresql://user:password@localhost:5432/chronocrypt?schema=public"
```

**For SQLite:**

Update `prisma/schema.prisma`:

```prisma
datasource db {
  provider = "sqlite"
  url      = env("DATABASE_URL")
}
```

Create a `.env` file:

```env
DATABASE_URL="file:./chronocrypt.db"
```

### 4. Generate Prisma Client and Run Migrations

```bash
bunx prisma generate
bunx prisma migrate dev --name init
```

## Implementation Files

Copy the implementation files to your project:

```bash
cp examples/prisma/prisma-encrypted-repository.ts src/storage/
cp examples/prisma/prisma-audit-log.ts src/storage/
```

## Usage Example

```typescript
import { PrismaClient } from '@prisma/client';
import {
  generateMasterKey,
  createDataSource,
  createKeyHolder,
  createDataViewer,
  createAllowAllPolicy
} from '@siwats/chronocrypt';
import { createPrismaRepository } from './storage/prisma-encrypted-repository';
import { createPrismaAuditLog } from './storage/prisma-audit-log';

// Initialize Prisma
const prisma = new PrismaClient();

// Create storage instances
const repository = createPrismaRepository(prisma);
const auditLog = createPrismaAuditLog(prisma);

// Use with ChronoCrypt
const masterKey = generateMasterKey();
const dataSource = createDataSource(repository, masterKey);
const keyHolder = createKeyHolder(masterKey, auditLog, [createAllowAllPolicy()]);
const dataViewer = createDataViewer('analyst-001', auditLog);

// Encrypt data
const data = new TextEncoder().encode('Sensitive temporal data');
const encrypted = await dataSource.encryptData(data);

// Authorize and decrypt
const authResponse = await keyHolder.authorizeAccess({
  requesterId: 'analyst-001',
  timeRange: {
    startTime: encrypted.timestamp,
    endTime: encrypted.timestamp
  },
  purpose: 'Data analysis'
});

dataViewer.loadAuthorizedKeys(authResponse.keys!);
const decrypted = await dataViewer.decryptFromRepository(
  repository,
  encrypted.timestamp
);

// Clean up
await prisma.$disconnect();
```

## Database Schema

### Encrypted Packages Table

Stores encrypted data with temporal metadata:

```sql
CREATE TABLE encrypted_packages (
  id TEXT PRIMARY KEY,
  timestamp BIGINT UNIQUE NOT NULL,
  encrypted_data BYTEA NOT NULL,
  iv BYTEA NOT NULL,
  auth_tag BYTEA NOT NULL,
  metadata JSONB,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_encrypted_packages_timestamp ON encrypted_packages(timestamp);
```

### Audit Log Entries Table

Stores audit trail for all operations:

```sql
CREATE TABLE audit_log_entries (
  id TEXT PRIMARY KEY,
  entry_id TEXT UNIQUE NOT NULL,
  timestamp BIGINT NOT NULL,
  event_type TEXT NOT NULL,
  actor TEXT NOT NULL,
  target TEXT,
  success BOOLEAN NOT NULL,
  range_start_time BIGINT,
  range_end_time BIGINT,
  details JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_audit_log_timestamp ON audit_log_entries(timestamp);
CREATE INDEX idx_audit_log_event_type ON audit_log_entries(event_type);
CREATE INDEX idx_audit_log_actor ON audit_log_entries(actor);
CREATE INDEX idx_audit_log_entry_id ON audit_log_entries(entry_id);
```

## Advanced Features

### Data Retention Policies

```typescript
// Delete encrypted data older than 90 days
const ninetyDaysAgo = Date.now() - 90 * 24 * 60 * 60 * 1000;
const deletedCount = await repository.deleteOlderThan(ninetyDaysAgo);
console.log(`Deleted ${deletedCount} old packages`);
```

### Audit Log Analytics

```typescript
// Get statistics
const stats = await auditLog.getStatistics();
console.log('Total entries:', stats.totalEntries);
console.log('Success rate:', (stats.successRate * 100).toFixed(2) + '%');
console.log('Entries by type:', stats.entriesByType);

// Monitor failed operations
const failures = await auditLog.getFailedOperations(10);
for (const failure of failures) {
  console.log(`Failed ${failure.eventType} by ${failure.actor}`);
}
```

### Bulk Operations

```typescript
// Encrypt batch data efficiently
const readings = [/* ... sensor readings ... */];
const packages = [];

for (const reading of readings) {
  const data = new TextEncoder().encode(JSON.stringify(reading));
  const pkg = await dataSource.encryptDataAtTimestamp(
    data,
    reading.timestamp,
    { sensorId: reading.id }
  );
  packages.push(pkg);
}

console.log(`Encrypted ${packages.length} packages`);
```

### Time Range Queries

```typescript
// Get all data from the last hour
const oneHourAgo = Date.now() - 60 * 60 * 1000;
const now = Date.now();

const recentPackages = await repository.retrieveRange({
  startTime: oneHourAgo,
  endTime: now
});

console.log(`Found ${recentPackages.length} packages from last hour`);
```

## Performance Optimization

### PostgreSQL

1. **Enable Connection Pooling:**

```typescript
const prisma = new PrismaClient({
  datasources: {
    db: {
      url: process.env.DATABASE_URL + '?connection_limit=10&pool_timeout=20'
    }
  }
});
```

2. **Add Indexes for Common Queries:**

```sql
-- For range queries
CREATE INDEX idx_packages_timestamp_range ON encrypted_packages(timestamp);

-- For audit queries
CREATE INDEX idx_audit_composite ON audit_log_entries(actor, event_type, timestamp);
```

3. **Use Prepared Transactions for Bulk Inserts:**

```typescript
await prisma.$transaction(
  packages.map(pkg =>
    prisma.encryptedPackage.create({ data: pkg })
  )
);
```

### SQLite

1. **Enable WAL Mode:**

```sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
```

2. **Increase Cache Size:**

```sql
PRAGMA cache_size=-64000;  -- 64MB cache
```

## Production Considerations

### Security

- **Never commit `.env` files** with database credentials
- Use **read-only replicas** for audit log queries
- Implement **row-level security** in PostgreSQL for multi-tenant scenarios
- Enable **SSL/TLS** for database connections
- Regularly **backup** encrypted data and audit logs

### Monitoring

```typescript
// Monitor database health
prisma.$on('query', (e) => {
  if (e.duration > 1000) {
    console.warn('Slow query detected:', e.query, e.duration + 'ms');
  }
});

// Monitor connection issues
prisma.$on('error', (e) => {
  console.error('Database error:', e);
});
```

### Backup and Recovery

```bash
# PostgreSQL backup
pg_dump -U user -d chronocrypt > backup.sql

# PostgreSQL restore
psql -U user -d chronocrypt < backup.sql

# SQLite backup
sqlite3 chronocrypt.db ".backup backup.db"
```

## Migration from In-Memory

To migrate from in-memory storage to Prisma:

```typescript
import { InMemoryEncryptedRepository } from '@siwats/chronocrypt';

// Old in-memory repository
const oldRepo = new InMemoryEncryptedRepository();

// New Prisma repository
const newRepo = createPrismaRepository(prisma);

// Migrate data
const allTimestamps = oldRepo.getAllTimestamps();
for (const timestamp of allTimestamps) {
  const pkg = await oldRepo.retrieve(timestamp);
  if (pkg) {
    await newRepo.store(pkg);
  }
}

console.log('Migration complete!');
```

## Troubleshooting

### Common Issues

**1. Connection Errors**

```
Error: Can't reach database server
```

Solution: Check your `DATABASE_URL` and ensure the database is running.

**2. Migration Failures**

```
Error: Unique constraint violation
```

Solution: Ensure timestamps are unique. Use `upsert` instead of `create`.

**3. Type Errors with BigInt**

```
Error: Cannot convert BigInt to number
```

Solution: Use `Number()` conversion as shown in the implementations.

## Testing

Create a test database for integration tests:

```typescript
import { PrismaClient } from '@prisma/client';

const testPrisma = new PrismaClient({
  datasources: {
    db: {
      url: 'postgresql://localhost:5432/chronocrypt_test'
    }
  }
});

// Run tests
beforeEach(async () => {
  await testPrisma.encryptedPackage.deleteMany();
  await testPrisma.auditLogEntry.deleteMany();
});

afterAll(async () => {
  await testPrisma.$disconnect();
});
```

## Additional Resources

- [Prisma Documentation](https://www.prisma.io/docs)
- [PostgreSQL Performance Tuning](https://www.postgresql.org/docs/current/performance-tips.html)
- [SQLite Optimization](https://www.sqlite.org/optoverview.html)
- [ChronoCrypt Documentation](../../README.md)

## License

These example implementations are provided as-is under the MIT license. Customize them for your production needs.
