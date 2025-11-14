import { describe, test, expect, beforeEach } from 'bun:test';
import { InMemoryEncryptedRepository } from '../src/storage/encrypted-repository';
import { InMemoryAuditLog, createAuditEntry } from '../src/storage/audit-log';
import {
  AccessControlPolicyManager,
  createMaxDurationPolicy,
  createPastOnlyPolicy,
  createTimeWindowPolicy,
  createPurposeRequiredPolicy,
  createCompositeAndPolicy,
  createCompositeOrPolicy
} from '../src/policies/access-control';
import { EncryptedPackage, AccessRequest, TimeRange } from '../src/types';
import { generateMasterKey, deriveTimeSpecificKey } from '../src/crypto/key-derivation';
import { encryptData } from '../src/crypto/encryption';

describe('EncryptedRepository', () => {
  let repository: InMemoryEncryptedRepository;

  beforeEach(() => {
    repository = new InMemoryEncryptedRepository();
  });

  test('stores and retrieves encrypted packages', async () => {
    const masterKey = generateMasterKey();
    const timestamp = Date.now();
    const data = new TextEncoder().encode('Test data');
    const timeKey = await deriveTimeSpecificKey(masterKey, timestamp);
    const pkg = await encryptData(data, timeKey, timestamp);

    await repository.store(pkg);

    const retrieved = await repository.retrieve(timestamp);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.timestamp).toBe(timestamp);
  });

  test('returns null for non-existent timestamp', async () => {
    const result = await repository.retrieve(999999);
    expect(result).toBeNull();
  });

  test('retrieves packages in time range', async () => {
    const masterKey = generateMasterKey();

    // Store packages at different timestamps
    for (let i = 0; i < 5; i++) {
      const timestamp = 1000 + i * 1000;
      const data = new TextEncoder().encode(`Data ${i}`);
      const timeKey = await deriveTimeSpecificKey(masterKey, timestamp);
      const pkg = await encryptData(data, timeKey, timestamp);
      await repository.store(pkg);
    }

    const range: TimeRange = { startTime: 2000, endTime: 4000 };
    const packages = await repository.retrieveRange(range);

    expect(packages.length).toBe(3); // 2000, 3000, 4000
    expect(packages[0].timestamp).toBe(2000);
    expect(packages[2].timestamp).toBe(4000);
  });

  test('checks existence of data', async () => {
    const masterKey = generateMasterKey();
    const timestamp = 1000;
    const data = new TextEncoder().encode('Test');
    const timeKey = await deriveTimeSpecificKey(masterKey, timestamp);
    const pkg = await encryptData(data, timeKey, timestamp);

    expect(await repository.exists(timestamp)).toBe(false);
    await repository.store(pkg);
    expect(await repository.exists(timestamp)).toBe(true);
  });

  test('provides correct size', async () => {
    expect(repository.size()).toBe(0);

    const masterKey = generateMasterKey();
    const timestamp = 1000;
    const data = new TextEncoder().encode('Test');
    const timeKey = await deriveTimeSpecificKey(masterKey, timestamp);
    const pkg = await encryptData(data, timeKey, timestamp);
    await repository.store(pkg);

    expect(repository.size()).toBe(1);
  });

  test('provides time range of stored data', async () => {
    const masterKey = generateMasterKey();

    for (const timestamp of [1000, 2000, 3000]) {
      const data = new TextEncoder().encode('Data');
      const timeKey = await deriveTimeSpecificKey(masterKey, timestamp);
      const pkg = await encryptData(data, timeKey, timestamp);
      await repository.store(pkg);
    }

    const range = repository.getTimeRange();
    expect(range).toEqual({ startTime: 1000, endTime: 3000 });
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
  });

  test('retrieves entries by actor', async () => {
    await auditLog.append(createAuditEntry('ACCESS_REQUEST', 'viewer-001', true));
    await auditLog.append(createAuditEntry('ACCESS_REQUEST', 'viewer-002', true));
    await auditLog.append(createAuditEntry('KEY_GENERATION', 'viewer-001', true));

    const viewer001Entries = await auditLog.retrieveByActor('viewer-001');
    expect(viewer001Entries.length).toBe(2);
  });

  test('provides statistics', async () => {
    await auditLog.append(createAuditEntry('ACCESS_REQUEST', 'viewer-001', true));
    await auditLog.append(createAuditEntry('ACCESS_GRANTED', 'key-holder', true));
    await auditLog.append(createAuditEntry('ACCESS_DENIED', 'key-holder', false));

    const stats = await auditLog.getStatistics();

    expect(stats.totalEntries).toBe(3);
    expect(stats.entriesByType['ACCESS_REQUEST']).toBe(1);
    expect(stats.entriesByActor['viewer-001']).toBe(1);
    expect(stats.successRate).toBeCloseTo(0.667, 2);
  });
});

describe('Access Control Policies', () => {
  let policyManager: AccessControlPolicyManager;

  beforeEach(() => {
    policyManager = new AccessControlPolicyManager();
  });

  test('denies when no policies defined', async () => {
    const request: AccessRequest = {
      requesterId: 'viewer-001',
      timeRange: { startTime: 1000, endTime: 2000 }
    };

    const result = await policyManager.evaluateRequest(request);
    expect(result.allow).toBe(false);
  });

  test('max duration policy', async () => {
    policyManager.addPolicy(createMaxDurationPolicy(5000)); // 5 seconds max

    const validRequest: AccessRequest = {
      requesterId: 'viewer-001',
      timeRange: { startTime: 1000, endTime: 5000 } // 4 seconds
    };

    const invalidRequest: AccessRequest = {
      requesterId: 'viewer-001',
      timeRange: { startTime: 1000, endTime: 7000 } // 6 seconds
    };

    expect((await policyManager.evaluateRequest(validRequest)).allow).toBe(true);
    expect((await policyManager.evaluateRequest(invalidRequest)).allow).toBe(false);
  });

  test('past only policy', async () => {
    policyManager.addPolicy(createPastOnlyPolicy());

    const pastRequest: AccessRequest = {
      requesterId: 'viewer-001',
      timeRange: {
        startTime: Date.now() - 10000,
        endTime: Date.now() - 5000
      }
    };

    const futureRequest: AccessRequest = {
      requesterId: 'viewer-001',
      timeRange: {
        startTime: Date.now() + 5000,
        endTime: Date.now() + 10000
      }
    };

    expect((await policyManager.evaluateRequest(pastRequest)).allow).toBe(true);
    expect((await policyManager.evaluateRequest(futureRequest)).allow).toBe(false);
  });

  test('time window policy', async () => {
    const allowedWindows: TimeRange[] = [
      { startTime: 1000, endTime: 5000 },
      { startTime: 10000, endTime: 15000 }
    ];

    policyManager.addPolicy(createTimeWindowPolicy(allowedWindows));

    const allowedRequest: AccessRequest = {
      requesterId: 'viewer-001',
      timeRange: { startTime: 2000, endTime: 4000 }
    };

    const deniedRequest: AccessRequest = {
      requesterId: 'viewer-001',
      timeRange: { startTime: 6000, endTime: 8000 }
    };

    expect((await policyManager.evaluateRequest(allowedRequest)).allow).toBe(true);
    expect((await policyManager.evaluateRequest(deniedRequest)).allow).toBe(false);
  });

  test('purpose required policy', async () => {
    policyManager.addPolicy(createPurposeRequiredPolicy(10));

    const withPurpose: AccessRequest = {
      requesterId: 'viewer-001',
      timeRange: { startTime: 1000, endTime: 2000 },
      purpose: 'This is a valid purpose'
    };

    const withoutPurpose: AccessRequest = {
      requesterId: 'viewer-001',
      timeRange: { startTime: 1000, endTime: 2000 }
    };

    const shortPurpose: AccessRequest = {
      requesterId: 'viewer-001',
      timeRange: { startTime: 1000, endTime: 2000 },
      purpose: 'Short'
    };

    expect((await policyManager.evaluateRequest(withPurpose)).allow).toBe(true);
    expect((await policyManager.evaluateRequest(withoutPurpose)).allow).toBe(false);
    expect((await policyManager.evaluateRequest(shortPurpose)).allow).toBe(false);
  });

  test('composite AND policy', async () => {
    const maxDuration = createMaxDurationPolicy(5000);
    const purposeRequired = createPurposeRequiredPolicy(10);
    const compositePolicy = createCompositeAndPolicy(
      [maxDuration, purposeRequired],
      'Duration AND Purpose'
    );

    policyManager.addPolicy(compositePolicy);

    const bothValid: AccessRequest = {
      requesterId: 'viewer-001',
      timeRange: { startTime: 1000, endTime: 4000 },
      purpose: 'Valid purpose here'
    };

    const onlyDurationValid: AccessRequest = {
      requesterId: 'viewer-001',
      timeRange: { startTime: 1000, endTime: 4000 }
    };

    expect((await policyManager.evaluateRequest(bothValid)).allow).toBe(true);
    expect((await policyManager.evaluateRequest(onlyDurationValid)).allow).toBe(false);
  });

  test('composite OR policy', async () => {
    const maxDuration = createMaxDurationPolicy(5000);
    const purposeRequired = createPurposeRequiredPolicy(10);
    const compositePolicy = createCompositeOrPolicy(
      [maxDuration, purposeRequired],
      'Duration OR Purpose'
    );

    policyManager.addPolicy(compositePolicy);

    const bothValid: AccessRequest = {
      requesterId: 'viewer-001',
      timeRange: { startTime: 1000, endTime: 4000 },
      purpose: 'Valid purpose here'
    };

    const onlyDurationValid: AccessRequest = {
      requesterId: 'viewer-001',
      timeRange: { startTime: 1000, endTime: 4000 }
    };

    const neitherValid: AccessRequest = {
      requesterId: 'viewer-001',
      timeRange: { startTime: 1000, endTime: 10000 }
    };

    expect((await policyManager.evaluateRequest(bothValid)).allow).toBe(true);
    expect((await policyManager.evaluateRequest(onlyDurationValid)).allow).toBe(true);
    expect((await policyManager.evaluateRequest(neitherValid)).allow).toBe(false);
  });

  test('policy priority order', async () => {
    const highPriority = {
      id: 'high',
      name: 'High Priority Deny',
      evaluate: async () => false,
      priority: 100
    };

    const lowPriority = {
      id: 'low',
      name: 'Low Priority Allow',
      evaluate: async () => true,
      priority: 1
    };

    policyManager.addPolicy(lowPriority);
    policyManager.addPolicy(highPriority);

    const request: AccessRequest = {
      requesterId: 'viewer-001',
      timeRange: { startTime: 1000, endTime: 2000 }
    };

    const result = await policyManager.evaluateRequest(request);
    expect(result.allow).toBe(false);
    expect(result.policy?.id).toBe('high');
  });
});
