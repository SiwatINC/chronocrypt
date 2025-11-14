import { describe, test, expect, beforeEach } from 'bun:test';
import { InMemoryEncryptedRepository } from '../src/storage/encrypted-repository';
import { InMemoryAuditLog, createAuditEntry } from '../src/storage/audit-log';
import { createAllowAllPolicy } from '../src/policies/access-control';
import { TimeRange } from '../src/types';
import { generateMasterKeypair, exportPublicKey } from '../src/crypto/key-derivation';
import { encryptData } from '../src/crypto/encryption';

describe('EncryptedRepository', () => {
  let repository: InMemoryEncryptedRepository;

  beforeEach(() => {
    repository = new InMemoryEncryptedRepository();
  });

  test('stores and retrieves encrypted packages', async () => {
    const keypair = await generateMasterKeypair();
    const publicKey = await exportPublicKey(keypair.publicKey);
    const timestamp = Date.now();
    const data = new TextEncoder().encode('Test data');
    const pkg = await encryptData(data, publicKey, timestamp);

    await repository.store(pkg);

    const retrieved = await repository.retrieve(timestamp);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.timestamp).toBe(timestamp);
    expect(retrieved!.encryptedData).toEqual(pkg.encryptedData);
  });

  test('returns null for non-existent timestamp', async () => {
    const result = await repository.retrieve(999999);
    expect(result).toBeNull();
  });

  test('retrieves packages in time range', async () => {
    const keypair = await generateMasterKeypair();
    const publicKey = await exportPublicKey(keypair.publicKey);

    // Store packages at different timestamps
    for (let i = 0; i < 5; i++) {
      const timestamp = 1000 + i * 1000;
      const data = new TextEncoder().encode(`Data ${i}`);
      const pkg = await encryptData(data, publicKey, timestamp);
      await repository.store(pkg);
    }

    const range: TimeRange = { startTime: 2000, endTime: 4000 };
    const packages = await repository.retrieveRange(range);

    expect(packages.length).toBe(3); // 2000, 3000, 4000
    expect(packages[0].timestamp).toBe(2000);
    expect(packages[2].timestamp).toBe(4000);
  });

  test('checks existence of data', async () => {
    const keypair = await generateMasterKeypair();
    const publicKey = await exportPublicKey(keypair.publicKey);
    const timestamp = 1000;
    const data = new TextEncoder().encode('Test');
    const pkg = await encryptData(data, publicKey, timestamp);

    expect(await repository.exists(timestamp)).toBe(false);
    await repository.store(pkg);
    expect(await repository.exists(timestamp)).toBe(true);
  });

  test('provides correct size', async () => {
    expect(repository.size()).toBe(0);

    const keypair = await generateMasterKeypair();
    const publicKey = await exportPublicKey(keypair.publicKey);
    const timestamp = 1000;
    const data = new TextEncoder().encode('Test');
    const pkg = await encryptData(data, publicKey, timestamp);
    await repository.store(pkg);

    expect(repository.size()).toBe(1);
  });

  test('provides time range of stored data', async () => {
    const keypair = await generateMasterKeypair();
    const publicKey = await exportPublicKey(keypair.publicKey);

    for (const timestamp of [1000, 2000, 3000]) {
      const data = new TextEncoder().encode('Data');
      const pkg = await encryptData(data, publicKey, timestamp);
      await repository.store(pkg);
    }

    const range = repository.getTimeRange();
    expect(range).toEqual({ startTime: 1000, endTime: 3000 });
  });

  test('returns null time range when empty', () => {
    const range = repository.getTimeRange();
    expect(range).toBeNull();
  });

  test('clears all packages', async () => {
    const keypair = await generateMasterKeypair();
    const publicKey = await exportPublicKey(keypair.publicKey);
    const data = new TextEncoder().encode('Test');
    const pkg = await encryptData(data, publicKey, 1000);
    await repository.store(pkg);

    expect(repository.size()).toBe(1);
    repository.clear();
    expect(repository.size()).toBe(0);
  });
});

describe('AuditLog', () => {
  let auditLog: InMemoryAuditLog;

  beforeEach(() => {
    auditLog = new InMemoryAuditLog();
  });

  test('appends and retrieves entries', async () => {
    const entry = createAuditEntry('ACCESS_REQUEST', 'viewer-001', true, {
      details: { purpose: 'test' }
    });

    await auditLog.append(entry);

    const entries = await auditLog.getAll();
    expect(entries.length).toBe(1);
    expect(entries[0].actor).toBe('viewer-001');
    expect(entries[0].eventType).toBe('ACCESS_REQUEST');
  });

  test('retrieves entries by time range', async () => {
    const entries = [
      createAuditEntry('ACCESS_REQUEST', 'viewer-001', true),
      createAuditEntry('KEY_GENERATION', 'key-holder', true),
      createAuditEntry('ACCESS_GRANTED', 'key-holder', true)
    ];

    // Manually set timestamps
    entries[0].timestamp = 1000;
    entries[1].timestamp = 2000;
    entries[2].timestamp = 3000;

    for (const entry of entries) {
      await auditLog.append(entry);
    }

    const range: TimeRange = { startTime: 1500, endTime: 2500 };
    const retrieved = await auditLog.retrieve(range);

    expect(retrieved.length).toBe(1);
    expect(retrieved[0].timestamp).toBe(2000);
  });

  test('retrieves entries by event type', async () => {
    await auditLog.append(createAuditEntry('ACCESS_REQUEST', 'viewer-001', true));
    await auditLog.append(createAuditEntry('KEY_GENERATION', 'key-holder', true));
    await auditLog.append(createAuditEntry('ACCESS_REQUEST', 'viewer-002', true));

    const requests = await auditLog.retrieveByEventType('ACCESS_REQUEST');
    expect(requests.length).toBe(2);
    expect(requests[0].eventType).toBe('ACCESS_REQUEST');
    expect(requests[1].eventType).toBe('ACCESS_REQUEST');
  });

  test('retrieves entries by actor', async () => {
    await auditLog.append(createAuditEntry('ACCESS_REQUEST', 'viewer-001', true));
    await auditLog.append(createAuditEntry('ACCESS_REQUEST', 'viewer-002', true));
    await auditLog.append(createAuditEntry('KEY_GENERATION', 'viewer-001', true));

    const viewer001Entries = await auditLog.retrieveByActor('viewer-001');
    expect(viewer001Entries.length).toBe(2);
    expect(viewer001Entries[0].actor).toBe('viewer-001');
    expect(viewer001Entries[1].actor).toBe('viewer-001');
  });

  test('provides statistics', async () => {
    await auditLog.append(createAuditEntry('ACCESS_REQUEST', 'viewer-001', true));
    await auditLog.append(createAuditEntry('ACCESS_GRANTED', 'key-holder', true));
    await auditLog.append(createAuditEntry('ACCESS_DENIED', 'key-holder', false));

    const stats = await auditLog.getStatistics();

    expect(stats.totalEntries).toBe(3);
    expect(stats.entriesByType['ACCESS_REQUEST']).toBe(1);
    expect(stats.entriesByType['ACCESS_GRANTED']).toBe(1);
    expect(stats.entriesByType['ACCESS_DENIED']).toBe(1);
    expect(stats.entriesByActor['viewer-001']).toBe(1);
    expect(stats.entriesByActor['key-holder']).toBe(2);
    expect(stats.successRate).toBeCloseTo(0.667, 2);
  });

  test('provides size', async () => {
    expect(auditLog.size()).toBe(0);
    await auditLog.append(createAuditEntry('ACCESS_REQUEST', 'viewer-001', true));
    expect(auditLog.size()).toBe(1);
  });

  test('clears all entries', async () => {
    await auditLog.append(createAuditEntry('ACCESS_REQUEST', 'viewer-001', true));
    await auditLog.append(createAuditEntry('KEY_GENERATION', 'key-holder', true));

    expect(auditLog.size()).toBe(2);
    auditLog.clear();
    expect(auditLog.size()).toBe(0);
  });

  test('createAuditEntry generates valid entries', () => {
    const entry = createAuditEntry('ACCESS_REQUEST', 'viewer-001', true, {
      target: 'key-holder',
      timeRange: { startTime: 1000, endTime: 2000 },
      details: { purpose: 'testing' }
    });

    expect(entry.id).toBeDefined();
    expect(entry.id).toMatch(/^audit-/);
    expect(entry.timestamp).toBeGreaterThan(0);
    expect(entry.eventType).toBe('ACCESS_REQUEST');
    expect(entry.actor).toBe('viewer-001');
    expect(entry.target).toBe('key-holder');
    expect(entry.timeRange).toEqual({ startTime: 1000, endTime: 2000 });
    expect(entry.success).toBe(true);
    expect(entry.details).toEqual({ purpose: 'testing' });
  });
});

describe('Access Control Policies', () => {
  test('createAllowAllPolicy creates valid policy', () => {
    const policy = createAllowAllPolicy();

    expect(policy.id).toBe('allow-all');
    expect(policy.name).toBe('Allow All');
    expect(policy.priority).toBe(-1000);
    expect(typeof policy.evaluate).toBe('function');
  });

  test('allow-all policy always returns true', async () => {
    const policy = createAllowAllPolicy();

    const request1 = {
      requesterId: 'viewer-001',
      timeRange: { startTime: 1000, endTime: 2000 }
    };

    const request2 = {
      requesterId: 'viewer-999',
      timeRange: { startTime: 0, endTime: 999999999 },
      purpose: 'Testing'
    };

    expect(await policy.evaluate(request1)).toBe(true);
    expect(await policy.evaluate(request2)).toBe(true);
  });
});
