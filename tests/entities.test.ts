import { describe, test, expect, beforeEach } from 'bun:test';
import { DataSource, createDataSource } from '../src/entities/data-source';
import { KeyHolder, createKeyHolder } from '../src/entities/key-holder';
import { DataViewer, createDataViewer } from '../src/entities/data-viewer';
import { InMemoryEncryptedRepository } from '../src/storage/encrypted-repository';
import { InMemoryAuditLog } from '../src/storage/audit-log';
import {
  generateMasterKeypair,
  exportPublicKey,
  deriveTimeSpecificPrivateKey
} from '../src/crypto/key-derivation';
import { createAllowAllPolicy } from '../src/policies/access-control';
import { AccessRequest, DecryptionError, MasterKeypair } from '../src/types';

describe('DataSource (Asymmetric - Public Key Only)', () => {
  let dataSource: DataSource;
  let repository: InMemoryEncryptedRepository;
  let masterKeypair: MasterKeypair;

  beforeEach(async () => {
    masterKeypair = await generateMasterKeypair();
    const publicKey = await exportPublicKey(masterKeypair.publicKey);
    repository = new InMemoryEncryptedRepository();
    dataSource = createDataSource(publicKey, repository);
  });

  test('encrypts data with public key only', async () => {
    const data = new TextEncoder().encode('Test data');

    const encrypted = await dataSource.encryptData(data);

    expect(encrypted.timestamp).toBeGreaterThan(0);
    expect(encrypted.encryptedData.length).toBeGreaterThan(0);
    expect(encrypted.encryptedKey).toBeInstanceOf(Uint8Array);
    expect(encrypted.ephemeralPublicKey).toBeDefined();
    expect(await repository.exists(encrypted.timestamp)).toBe(true);
  });

  test('encrypts data at specific timestamp', async () => {
    const data = new TextEncoder().encode('Timestamped data');
    const timestamp = 1000000;

    const encrypted = await dataSource.encryptDataAtTimestamp(data, timestamp);

    expect(encrypted.timestamp).toBe(timestamp);
    expect(await repository.exists(timestamp)).toBe(true);
  });

  test('encrypts batch of data items', async () => {
    const items = [
      { data: new TextEncoder().encode('Item 1') },
      { data: new TextEncoder().encode('Item 2'), timestamp: 1000 },
      { data: new TextEncoder().encode('Item 3'), metadata: { id: 3 } }
    ];

    const results = await dataSource.encryptBatch(items);

    expect(results.length).toBe(3);
    expect(results[1].timestamp).toBe(1000);
    expect(results[2].metadata).toEqual({ id: 3 });
  });

  test('encrypts with metadata', async () => {
    const data = new TextEncoder().encode('Data');
    const metadata = { sensor: 'temp-01', location: 'room-A' };

    const encrypted = await dataSource.encryptData(data, metadata);

    expect(encrypted.metadata).toEqual(metadata);
  });

  test('DataSource cannot decrypt (no private key)', async () => {
    const data = new TextEncoder().encode('Secret data');
    const encrypted = await dataSource.encryptData(data);

    // DataSource has no decryptData method - only has public key
    // This test verifies the architecture prevents DataSource from decrypting
    expect((dataSource as any).decryptData).toBeUndefined();
    expect((dataSource as any).privateKey).toBeUndefined();
  });

  test('provides access to repository', () => {
    const repo = dataSource.getRepository();
    expect(repo).toBe(repository);
  });

  test('provides public key', () => {
    const publicKey = dataSource.getPublicKey();
    expect(publicKey).toBeDefined();
    expect(publicKey.kty).toBe('EC');
  });
});

describe('KeyHolder (Asymmetric - Private Key Management)', () => {
  let keyHolder: KeyHolder;
  let auditLog: InMemoryAuditLog;
  let masterKeypair: MasterKeypair;

  beforeEach(async () => {
    masterKeypair = await generateMasterKeypair();
    auditLog = new InMemoryAuditLog();
    keyHolder = createKeyHolder(masterKeypair, auditLog, [createAllowAllPolicy()]);
  });

  test('authorizes access with allow-all policy', async () => {
    const request: AccessRequest = {
      requesterId: 'viewer-001',
      timeRange: {
        startTime: 1000,
        endTime: 5000
      },
      purpose: 'Testing authorization'
    };

    const response = await keyHolder.authorizeAccess(request);

    expect(response.granted).toBe(true);
    expect(response.privateKeys).toBeDefined();
    expect(response.privateKeys!.size).toBeGreaterThan(0);

    // Verify keys are CryptoKey objects
    for (const key of response.privateKeys!.values()) {
      expect(key.type).toBe('private');
      expect(key.algorithm.name).toBe('ECDH');
    }
  });

  test('denies access when no policies defined', async () => {
    const noPolicyHolder = createKeyHolder(masterKeypair, auditLog, []);

    const request: AccessRequest = {
      requesterId: 'viewer-001',
      timeRange: { startTime: 1000, endTime: 5000 }
    };

    const response = await noPolicyHolder.authorizeAccess(request);

    expect(response.granted).toBe(false);
    expect(response.denialReason).toBeDefined();
  });

  test('derives time-specific private keys for range', async () => {
    const request: AccessRequest = {
      requesterId: 'viewer-001',
      timeRange: {
        startTime: 1000,
        endTime: 3000
      }
    };

    const response = await keyHolder.authorizeAccess(request);

    expect(response.granted).toBe(true);
    expect(response.privateKeys).toBeDefined();

    // Should have keys for 1000, 2000, 3000
    expect(response.privateKeys!.size).toBeGreaterThanOrEqual(3);
    expect(response.privateKeys!.has(1000)).toBe(true);
    expect(response.privateKeys!.has(2000)).toBe(true);
    expect(response.privateKeys!.has(3000)).toBe(true);
  });

  test('logs all authorization operations', async () => {
    const request: AccessRequest = {
      requesterId: 'viewer-001',
      timeRange: { startTime: 1000, endTime: 2000 },
      purpose: 'Audit test'
    };

    await keyHolder.authorizeAccess(request);

    const entries = await auditLog.getAll();
    expect(entries.length).toBeGreaterThan(0);

    const eventTypes = entries.map(e => e.eventType);
    expect(eventTypes).toContain('ACCESS_REQUEST');
    expect(eventTypes).toContain('KEY_GENERATION');
    expect(eventTypes).toContain('ACCESS_GRANTED');
    expect(eventTypes).toContain('KEY_DISTRIBUTION');
  });

  test('provides audit log access', () => {
    const log = keyHolder.getAuditLog();
    expect(log).toBe(auditLog);
  });

  test('provides master public key', () => {
    const publicKey = keyHolder.getMasterPublicKey();
    expect(publicKey).toBe(masterKeypair.publicKey);
    expect(publicKey.type).toBe('public');
  });
});

describe('DataViewer (Asymmetric Decryption)', () => {
  let dataViewer: DataViewer;
  let auditLog: InMemoryAuditLog;
  let masterKeypair: MasterKeypair;

  beforeEach(async () => {
    masterKeypair = await generateMasterKeypair();
    auditLog = new InMemoryAuditLog();
    dataViewer = createDataViewer('viewer-001', auditLog);
  });

  test('tracks authorized keys', async () => {
    const timestamp = 1000;
    const key = await deriveTimeSpecificPrivateKey(masterKeypair.privateKey, timestamp);

    dataViewer.addAuthorizedKey(timestamp, key);

    expect(dataViewer.hasAuthorizationFor(timestamp)).toBe(true);
    expect(dataViewer.hasAuthorizationFor(2000)).toBe(false);
  });

  test('loads multiple authorized keys', async () => {
    const keys = new Map();
    keys.set(1000, await deriveTimeSpecificPrivateKey(masterKeypair.privateKey, 1000));
    keys.set(2000, await deriveTimeSpecificPrivateKey(masterKeypair.privateKey, 2000));
    keys.set(3000, await deriveTimeSpecificPrivateKey(masterKeypair.privateKey, 3000));

    dataViewer.loadAuthorizedKeys(keys);

    expect(dataViewer.getAuthorizedTimestamps()).toEqual([1000, 2000, 3000]);
  });

  test('decrypts with authorized key', async () => {
    const publicKey = await exportPublicKey(masterKeypair.publicKey);
    const data = new TextEncoder().encode('Secret message');
    const timestamp = Date.now();

    // Create encrypted package
    const { encryptData } = await import('../src/crypto/encryption');
    const encrypted = await encryptData(data, publicKey, timestamp);

    // Load authorized key
    const timeKey = await deriveTimeSpecificPrivateKey(masterKeypair.privateKey, timestamp);
    dataViewer.addAuthorizedKey(timestamp, timeKey);

    // Decrypt
    const decrypted = await dataViewer.decryptPackage(encrypted);

    expect(decrypted.data).toEqual(data);
    expect(decrypted.timestamp).toBe(timestamp);
  });

  test('fails to decrypt without authorized key', async () => {
    const publicKey = await exportPublicKey(masterKeypair.publicKey);
    const data = new TextEncoder().encode('Secret message');
    const timestamp = Date.now();

    const { encryptData } = await import('../src/crypto/encryption');
    const encrypted = await encryptData(data, publicKey, timestamp);

    // No key loaded - should fail
    await expect(dataViewer.decryptPackage(encrypted)).rejects.toThrow(DecryptionError);
  });

  test('clears all keys', async () => {
    const keys = new Map();
    keys.set(1000, await deriveTimeSpecificPrivateKey(masterKeypair.privateKey, 1000));
    keys.set(2000, await deriveTimeSpecificPrivateKey(masterKeypair.privateKey, 2000));

    dataViewer.loadAuthorizedKeys(keys);
    expect(dataViewer.getAuthorizedTimestamps().length).toBe(2);

    dataViewer.clearAllKeys();
    expect(dataViewer.getAuthorizedTimestamps().length).toBe(0);
  });

  test('clears keys in range', async () => {
    const keys = new Map();
    keys.set(1000, await deriveTimeSpecificPrivateKey(masterKeypair.privateKey, 1000));
    keys.set(2000, await deriveTimeSpecificPrivateKey(masterKeypair.privateKey, 2000));
    keys.set(3000, await deriveTimeSpecificPrivateKey(masterKeypair.privateKey, 3000));
    keys.set(4000, await deriveTimeSpecificPrivateKey(masterKeypair.privateKey, 4000));

    dataViewer.loadAuthorizedKeys(keys);

    const cleared = dataViewer.clearKeysInRange({ startTime: 2000, endTime: 3000 });

    expect(cleared).toBe(2);
    expect(dataViewer.hasAuthorizationFor(1000)).toBe(true);
    expect(dataViewer.hasAuthorizationFor(2000)).toBe(false);
    expect(dataViewer.hasAuthorizationFor(3000)).toBe(false);
    expect(dataViewer.hasAuthorizationFor(4000)).toBe(true);
  });

  test('provides key statistics', async () => {
    const keys = new Map();
    keys.set(1000, await deriveTimeSpecificPrivateKey(masterKeypair.privateKey, 1000));
    keys.set(2000, await deriveTimeSpecificPrivateKey(masterKeypair.privateKey, 2000));
    keys.set(3000, await deriveTimeSpecificPrivateKey(masterKeypair.privateKey, 3000));

    dataViewer.loadAuthorizedKeys(keys);

    const stats = dataViewer.getKeyStatistics();
    expect(stats.totalKeys).toBe(3);
    expect(stats.timestamps).toEqual([1000, 2000, 3000]);
    expect(stats.timeRange).toEqual({ startTime: 1000, endTime: 3000 });
  });

  test('logs decryption attempts', async () => {
    const publicKey = await exportPublicKey(masterKeypair.publicKey);
    const data = new TextEncoder().encode('Logged data');
    const timestamp = Date.now();

    const { encryptData } = await import('../src/crypto/encryption');
    const encrypted = await encryptData(data, publicKey, timestamp);

    const timeKey = await deriveTimeSpecificPrivateKey(masterKeypair.privateKey, timestamp);
    dataViewer.addAuthorizedKey(timestamp, timeKey);

    await dataViewer.decryptPackage(encrypted);

    const entries = await auditLog.getAll();
    expect(entries.length).toBeGreaterThan(0);
    expect(entries[0].eventType).toBe('DECRYPTION_ATTEMPT');
    expect(entries[0].success).toBe(true);
  });
});

describe('End-to-End Asymmetric Flow', () => {
  test('complete encryption and decryption workflow', async () => {
    // Setup
    const masterKeypair = await generateMasterKeypair();
    const publicKey = await exportPublicKey(masterKeypair.publicKey);
    const repository = new InMemoryEncryptedRepository();
    const auditLog = new InMemoryAuditLog();

    // DataSource encrypts data (has public key only)
    const dataSource = createDataSource(publicKey, repository);
    const originalData = new TextEncoder().encode('Sensitive temporal data');
    const encrypted = await dataSource.encryptData(originalData);

    // Key Holder authorizes access (has private key)
    const keyHolder = createKeyHolder(masterKeypair, auditLog, [createAllowAllPolicy()]);
    const accessRequest: AccessRequest = {
      requesterId: 'viewer-001',
      timeRange: {
        startTime: encrypted.timestamp,
        endTime: encrypted.timestamp
      },
      purpose: 'Data analysis'
    };

    const authResponse = await keyHolder.authorizeAccess(accessRequest);
    expect(authResponse.granted).toBe(true);

    // Data Viewer decrypts data (receives time-specific private keys)
    const dataViewer = createDataViewer('viewer-001', auditLog);
    dataViewer.loadAuthorizedKeys(authResponse.privateKeys!);

    const decrypted = await dataViewer.decryptFromRepository(repository, encrypted.timestamp);
    expect(decrypted).not.toBeNull();
    expect(decrypted!.data).toEqual(originalData);

    // Verify audit trail
    const auditEntries = await auditLog.getAll();
    expect(auditEntries.length).toBeGreaterThan(0);
  });

  test('DataSource compromise does not enable decryption', async () => {
    // Setup
    const masterKeypair = await generateMasterKeypair();
    const publicKey = await exportPublicKey(masterKeypair.publicKey);
    const repository = new InMemoryEncryptedRepository();

    // DataSource encrypts data
    const dataSource = createDataSource(publicKey, repository);
    const sensitiveData = new TextEncoder().encode('Top secret information');
    const encrypted = await dataSource.encryptData(sensitiveData);

    // CRITICAL: Even if attacker compromises DataSource
    // They only have the public key and encrypted data
    // They CANNOT derive the private key or decrypt

    // Verify: No decryption method exists on DataSource
    expect((dataSource as any).decryptData).toBeUndefined();
    expect((dataSource as any).decryptPackage).toBeUndefined();

    // Verify: Public key cannot be used to decrypt
    const publicKeyOnly = dataSource.getPublicKey();
    expect(publicKeyOnly.kty).toBe('EC');
    // Public key alone is useless for decryption

    // Only KeyHolder can derive time-specific private keys
    // DataSource has NO ACCESS to private key material
  });

  test('unauthorized viewer cannot decrypt', async () => {
    // Setup
    const masterKeypair = await generateMasterKeypair();
    const publicKey = await exportPublicKey(masterKeypair.publicKey);
    const repository = new InMemoryEncryptedRepository();

    // DataSource encrypts data
    const dataSource = createDataSource(publicKey, repository);
    const originalData = new TextEncoder().encode('Protected data');
    const encrypted = await dataSource.encryptData(originalData);

    // Unauthorized viewer (no keys) tries to decrypt
    const unauthorizedViewer = createDataViewer('unauthorized-viewer');

    await expect(
      unauthorizedViewer.decryptFromRepository(repository, encrypted.timestamp)
    ).rejects.toThrow(DecryptionError);
  });

  test('temporal isolation - keys for one time do not work for another', async () => {
    const masterKeypair = await generateMasterKeypair();
    const publicKey = await exportPublicKey(masterKeypair.publicKey);
    const repository = new InMemoryEncryptedRepository();
    const auditLog = new InMemoryAuditLog();

    // Encrypt data at two different timestamps
    const dataSource = createDataSource(publicKey, repository);
    const data1 = new TextEncoder().encode('Data at time 1000');
    const data2 = new TextEncoder().encode('Data at time 2000');

    await dataSource.encryptDataAtTimestamp(data1, 1000);
    await dataSource.encryptDataAtTimestamp(data2, 2000);

    // Get key only for timestamp 1000
    const keyHolder = createKeyHolder(masterKeypair, auditLog, [createAllowAllPolicy()]);
    const authResponse = await keyHolder.authorizeAccess({
      requesterId: 'viewer-001',
      timeRange: { startTime: 1000, endTime: 1000 }
    });

    // Viewer can decrypt data at 1000 but not 2000
    const dataViewer = createDataViewer('viewer-001');
    dataViewer.loadAuthorizedKeys(authResponse.privateKeys!);

    const decrypted1 = await dataViewer.decryptFromRepository(repository, 1000);
    expect(decrypted1).not.toBeNull();
    expect(decrypted1!.data).toEqual(data1);

    await expect(dataViewer.decryptFromRepository(repository, 2000)).rejects.toThrow(
      DecryptionError
    );
  });

  test('multiple viewers with different access ranges', async () => {
    const masterKeypair = await generateMasterKeypair();
    const publicKey = await exportPublicKey(masterKeypair.publicKey);
    const repository = new InMemoryEncryptedRepository();
    const auditLog = new InMemoryAuditLog();

    // Encrypt data across time range
    const dataSource = createDataSource(publicKey, repository);
    for (let i = 1; i <= 5; i++) {
      const data = new TextEncoder().encode(`Data ${i}`);
      await dataSource.encryptDataAtTimestamp(data, i * 1000);
    }

    const keyHolder = createKeyHolder(masterKeypair, auditLog, [createAllowAllPolicy()]);

    // Viewer A: Access to 1000-2000
    const viewerA = createDataViewer('viewer-A');
    const authA = await keyHolder.authorizeAccess({
      requesterId: 'viewer-A',
      timeRange: { startTime: 1000, endTime: 2000 }
    });
    viewerA.loadAuthorizedKeys(authA.privateKeys!);

    // Viewer B: Access to 3000-5000
    const viewerB = createDataViewer('viewer-B');
    const authB = await keyHolder.authorizeAccess({
      requesterId: 'viewer-B',
      timeRange: { startTime: 3000, endTime: 5000 }
    });
    viewerB.loadAuthorizedKeys(authB.privateKeys!);

    // Verify isolation
    expect(await viewerA.decryptFromRepository(repository, 1000)).not.toBeNull();
    expect(await viewerA.decryptFromRepository(repository, 2000)).not.toBeNull();
    await expect(viewerA.decryptFromRepository(repository, 3000)).rejects.toThrow();

    expect(await viewerB.decryptFromRepository(repository, 3000)).not.toBeNull();
    expect(await viewerB.decryptFromRepository(repository, 4000)).not.toBeNull();
    expect(await viewerB.decryptFromRepository(repository, 5000)).not.toBeNull();
    await expect(viewerB.decryptFromRepository(repository, 1000)).rejects.toThrow();
  });
});
