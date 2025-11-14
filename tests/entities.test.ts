import { describe, test, expect, beforeEach } from 'bun:test';
import { DataSource, createDataSource } from '../src/entities/data-source';
import { KeyHolder, createKeyHolder } from '../src/entities/key-holder';
import { DataViewer, createDataViewer } from '../src/entities/data-viewer';
import { InMemoryEncryptedRepository } from '../src/storage/encrypted-repository';
import { InMemoryAuditLog } from '../src/storage/audit-log';
import { generateMasterKey } from '../src/crypto/key-derivation';
import { createAllowAllPolicy, createDenyAllPolicy, createRequesterWhitelistPolicy } from '../src/policies/access-control';
import { AccessRequest, DecryptionError } from '../src/types';

describe('DataSource', () => {
  let dataSource: DataSource;
  let repository: InMemoryEncryptedRepository;
  let masterKey: Uint8Array;

  beforeEach(() => {
    masterKey = generateMasterKey();
    repository = new InMemoryEncryptedRepository();
    dataSource = createDataSource(repository, masterKey);
  });

  test('encrypts data and stores in repository', async () => {
    const data = new TextEncoder().encode('Test data');

    const encrypted = await dataSource.encryptData(data);

    expect(encrypted.timestamp).toBeGreaterThan(0);
    expect(encrypted.encryptedData.length).toBeGreaterThan(0);
    expect(await repository.exists(encrypted.timestamp)).toBe(true);
  });

  test('encrypts data at specific timestamp', async () => {
    const data = new TextEncoder().encode('Timestamped data');
    const timestamp = 1000000;

    const encrypted = await dataSource.encryptDataAtTimestamp(data, timestamp);

    expect(encrypted.timestamp).toBe(timestamp);
    expect(await repository.exists(timestamp)).toBe(true);
  });

  test('encrypts batch of data', async () => {
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

  test('provides access to repository', () => {
    const repo = dataSource.getRepository();
    expect(repo).toBe(repository);
  });
});

describe('KeyHolder', () => {
  let keyHolder: KeyHolder;
  let auditLog: InMemoryAuditLog;
  let masterKey: Uint8Array;

  beforeEach(() => {
    masterKey = generateMasterKey();
    auditLog = new InMemoryAuditLog();
    keyHolder = createKeyHolder(masterKey, auditLog, [createAllowAllPolicy()]);
  });

  test('authorizes access when policies allow', async () => {
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
    expect(response.keys).toBeDefined();
    expect(response.keys!.size).toBeGreaterThan(0);
  });

  test('denies access when policies deny', async () => {
    const denyHolder = createKeyHolder(masterKey, auditLog, [createDenyAllPolicy()]);

    const request: AccessRequest = {
      requesterId: 'viewer-001',
      timeRange: {
        startTime: 1000,
        endTime: 5000
      }
    };

    const response = await denyHolder.authorizeAccess(request);

    expect(response.granted).toBe(false);
    expect(response.denialReason).toBeDefined();
  });

  test('whitelist policy allows only authorized requesters', async () => {
    const whitelistHolder = createKeyHolder(
      masterKey,
      auditLog,
      [createRequesterWhitelistPolicy(['viewer-001', 'viewer-002'])]
    );

    const allowedRequest: AccessRequest = {
      requesterId: 'viewer-001',
      timeRange: { startTime: 1000, endTime: 2000 }
    };

    const deniedRequest: AccessRequest = {
      requesterId: 'viewer-999',
      timeRange: { startTime: 1000, endTime: 2000 }
    };

    const allowedResponse = await whitelistHolder.authorizeAccess(allowedRequest);
    const deniedResponse = await whitelistHolder.authorizeAccess(deniedRequest);

    expect(allowedResponse.granted).toBe(true);
    expect(deniedResponse.granted).toBe(false);
  });

  test('generates single key for timestamp', async () => {
    const timestamp = 1000;
    const requesterId = 'viewer-001';

    const key = await keyHolder.generateKeyForTimestamp(timestamp, requesterId);

    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(32); // 256-bit key
  });

  test('logs all access operations to audit log', async () => {
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
  });
});

describe('DataViewer', () => {
  let dataViewer: DataViewer;
  let auditLog: InMemoryAuditLog;

  beforeEach(() => {
    auditLog = new InMemoryAuditLog();
    dataViewer = createDataViewer('viewer-001', auditLog);
  });

  test('tracks authorized keys', () => {
    const key = generateMasterKey();
    const timestamp = 1000;

    dataViewer.addAuthorizedKey(timestamp, key);

    expect(dataViewer.hasAuthorizationFor(timestamp)).toBe(true);
    expect(dataViewer.hasAuthorizationFor(2000)).toBe(false);
  });

  test('loads multiple authorized keys', () => {
    const keys = new Map();
    keys.set(1000, generateMasterKey());
    keys.set(2000, generateMasterKey());
    keys.set(3000, generateMasterKey());

    dataViewer.loadAuthorizedKeys(keys);

    expect(dataViewer.getAuthorizedTimestamps()).toEqual([1000, 2000, 3000]);
  });

  test('destroys individual keys', () => {
    const key = generateMasterKey();
    const timestamp = 1000;

    dataViewer.addAuthorizedKey(timestamp, key);
    expect(dataViewer.hasAuthorizationFor(timestamp)).toBe(true);

    const destroyed = dataViewer.destroyKey(timestamp);
    expect(destroyed).toBe(true);
    expect(dataViewer.hasAuthorizationFor(timestamp)).toBe(false);
  });

  test('destroys all keys', () => {
    const keys = new Map();
    keys.set(1000, generateMasterKey());
    keys.set(2000, generateMasterKey());
    keys.set(3000, generateMasterKey());

    dataViewer.loadAuthorizedKeys(keys);
    expect(dataViewer.getAuthorizedTimestamps().length).toBe(3);

    dataViewer.destroyAllKeys();
    expect(dataViewer.getAuthorizedTimestamps().length).toBe(0);
  });

  test('provides key statistics', () => {
    const keys = new Map();
    keys.set(1000, generateMasterKey());
    keys.set(2000, generateMasterKey());
    keys.set(3000, generateMasterKey());

    dataViewer.loadAuthorizedKeys(keys);

    const stats = dataViewer.getKeyStatistics();
    expect(stats.totalKeys).toBe(3);
    expect(stats.timestamps).toEqual([1000, 2000, 3000]);
    expect(stats.timeRange).toEqual({ startTime: 1000, endTime: 3000 });
  });
});

describe('End-to-End Flow', () => {
  test('complete encryption and decryption workflow', async () => {
    // Setup
    const masterKey = generateMasterKey();
    const repository = new InMemoryEncryptedRepository();
    const auditLog = new InMemoryAuditLog();

    // Data Source encrypts data
    const dataSource = createDataSource(repository, masterKey);
    const originalData = new TextEncoder().encode('Sensitive temporal data');
    const encrypted = await dataSource.encryptData(originalData);

    // Key Holder authorizes access
    const keyHolder = createKeyHolder(masterKey, auditLog, [createAllowAllPolicy()]);
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

    // Data Viewer decrypts data
    const dataViewer = createDataViewer('viewer-001', auditLog);
    dataViewer.loadAuthorizedKeys(authResponse.keys!);

    const decrypted = await dataViewer.decryptFromRepository(repository, encrypted.timestamp);
    expect(decrypted).not.toBeNull();
    expect(decrypted!.data).toEqual(originalData);

    // Verify audit trail
    const auditEntries = await auditLog.getAll();
    expect(auditEntries.length).toBeGreaterThan(0);
  });

  test('unauthorized viewer cannot decrypt', async () => {
    // Setup
    const masterKey = generateMasterKey();
    const repository = new InMemoryEncryptedRepository();

    // Data Source encrypts data
    const dataSource = createDataSource(repository, masterKey);
    const originalData = new TextEncoder().encode('Protected data');
    const encrypted = await dataSource.encryptData(originalData);

    // Unauthorized viewer (no keys) tries to decrypt
    const unauthorizedViewer = createDataViewer('unauthorized-viewer');

    await expect(
      unauthorizedViewer.decryptFromRepository(repository, encrypted.timestamp)
    ).rejects.toThrow(DecryptionError);
  });

  test('temporal isolation - keys for one time do not work for another', async () => {
    const masterKey = generateMasterKey();
    const repository = new InMemoryEncryptedRepository();
    const auditLog = new InMemoryAuditLog();

    // Encrypt data at two different timestamps
    const dataSource = createDataSource(repository, masterKey);
    const data1 = new TextEncoder().encode('Data at time 1000');
    const data2 = new TextEncoder().encode('Data at time 2000');

    await dataSource.encryptDataAtTimestamp(data1, 1000);
    await dataSource.encryptDataAtTimestamp(data2, 2000);

    // Get key only for timestamp 1000
    const keyHolder = createKeyHolder(masterKey, auditLog, [createAllowAllPolicy()]);
    const authResponse = await keyHolder.authorizeAccess({
      requesterId: 'viewer-001',
      timeRange: { startTime: 1000, endTime: 1000 }
    });

    // Viewer can decrypt data at 1000 but not 2000
    const dataViewer = createDataViewer('viewer-001');
    dataViewer.loadAuthorizedKeys(authResponse.keys!);

    const decrypted1 = await dataViewer.decryptFromRepository(repository, 1000);
    expect(decrypted1).not.toBeNull();
    expect(decrypted1!.data).toEqual(data1);

    await expect(
      dataViewer.decryptFromRepository(repository, 2000)
    ).rejects.toThrow(DecryptionError);
  });
});
