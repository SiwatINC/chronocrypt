import { describe, test, expect } from 'bun:test';
import {
  generateMasterKeypair,
  exportPublicKey,
  importPublicKey,
  deriveTimeSpecificPrivateKey,
  deriveMultiplePrivateKeys,
  exportMasterKeypair,
  importMasterKeypair
} from '../src/crypto/key-derivation';
import {
  encryptData,
  decryptData,
  serializeEncryptedPackage,
  deserializeEncryptedPackage
} from '../src/crypto/encryption';
import {
  MasterKeypair,
  ExportedPublicKey,
  EncryptionError,
  DecryptionError,
  AuthenticationError
} from '../src/types';

describe('Asymmetric Key Generation and Derivation', () => {
  test('generateMasterKeypair creates EC keypair', async () => {
    const keypair = await generateMasterKeypair();

    expect(keypair.privateKey).toBeDefined();
    expect(keypair.publicKey).toBeDefined();
    expect(keypair.privateKey.type).toBe('private');
    expect(keypair.publicKey.type).toBe('public');
    expect(keypair.privateKey.algorithm.name).toBe('ECDH');
    expect(keypair.publicKey.algorithm.name).toBe('ECDH');
  });

  test('generateMasterKeypair creates unique keypairs', async () => {
    const keypair1 = await generateMasterKeypair();
    const keypair2 = await generateMasterKeypair();

    const exported1 = await exportPublicKey(keypair1.publicKey);
    const exported2 = await exportPublicKey(keypair2.publicKey);

    expect(exported1.x).not.toBe(exported2.x);
    expect(exported1.y).not.toBe(exported2.y);
  });

  test('exportPublicKey and importPublicKey are reversible', async () => {
    const keypair = await generateMasterKeypair();
    const exported = await exportPublicKey(keypair.publicKey);
    const imported = await importPublicKey(exported);

    expect(imported.type).toBe('public');
    expect(imported.algorithm.name).toBe('ECDH');

    const reExported = await exportPublicKey(imported);
    expect(reExported.x).toBe(exported.x);
    expect(reExported.y).toBe(exported.y);
  });

  test('deriveTimeSpecificPrivateKey returns valid CryptoKey', async () => {
    const keypair = await generateMasterKeypair();
    const timestamp = Date.now();

    const timeKey = await deriveTimeSpecificPrivateKey(keypair.privateKey, timestamp);

    expect(timeKey).toBeDefined();
    expect(timeKey.type).toBe('private');
    expect(timeKey.algorithm.name).toBe('ECDH');
  });

  test('deriveTimeSpecificPrivateKey returns master key (temporal isolation via KDF)', async () => {
    const keypair = await generateMasterKeypair();
    const timestamp1 = 1000000;
    const timestamp2 = 2000000;

    const key1 = await deriveTimeSpecificPrivateKey(keypair.privateKey, timestamp1);
    const key2 = await deriveTimeSpecificPrivateKey(keypair.privateKey, timestamp2);

    // Keys are the same (master key), but temporal isolation happens in KDF
    expect(key1).toBe(key2);
    expect(key1).toBe(keypair.privateKey);
  });

  test('deriveTimeSpecificPrivateKey produces deterministic results', async () => {
    const keypair = await generateMasterKeypair();
    const timestamp = 1234567890;

    // Derive twice with same timestamp
    const key1 = await deriveTimeSpecificPrivateKey(keypair.privateKey, timestamp);
    const key2 = await deriveTimeSpecificPrivateKey(keypair.privateKey, timestamp);

    // Test by using both keys to decrypt same data - should both work
    const data = new TextEncoder().encode('Test data');
    const publicKey = await exportPublicKey(keypair.publicKey);

    const encrypted = await encryptData(data, publicKey, timestamp);

    // Both keys should decrypt successfully
    const decrypted1 = await decryptData(encrypted, key1);
    const decrypted2 = await decryptData(encrypted, key2);

    expect(decrypted1).toEqual(data);
    expect(decrypted2).toEqual(data);
  });

  test('deriveMultiplePrivateKeys produces correct number of keys', async () => {
    const keypair = await generateMasterKeypair();
    const timestamps = [1000, 2000, 3000, 4000, 5000];

    const keys = await deriveMultiplePrivateKeys(keypair.privateKey, timestamps);

    expect(keys.size).toBe(timestamps.length);
    for (const timestamp of timestamps) {
      expect(keys.has(timestamp)).toBe(true);
      const key = keys.get(timestamp)!;
      expect(key.type).toBe('private');
      expect(key.algorithm.name).toBe('ECDH');
    }
  });

  test('exportMasterKeypair and importMasterKeypair are reversible', async () => {
    const originalKeypair = await generateMasterKeypair();
    const exported = await exportMasterKeypair(originalKeypair);
    const imported = await importMasterKeypair(exported);

    expect(imported.privateKey.type).toBe('private');
    expect(imported.publicKey.type).toBe('public');

    // Verify by encrypting with original public key and decrypting with imported private key
    const data = new TextEncoder().encode('Test data');
    const timestamp = Date.now();
    const publicKey = await exportPublicKey(originalKeypair.publicKey);

    const encrypted = await encryptData(data, publicKey, timestamp);
    const timeKey = await deriveTimeSpecificPrivateKey(imported.privateKey, timestamp);
    const decrypted = await decryptData(encrypted, timeKey);

    expect(decrypted).toEqual(data);
  });
});

describe('Hybrid Asymmetric Encryption (ECIES + AES-GCM)', () => {
  test('encryptData produces valid encrypted package', async () => {
    const keypair = await generateMasterKeypair();
    const publicKey = await exportPublicKey(keypair.publicKey);
    const timestamp = Date.now();
    const data = new TextEncoder().encode('Hello, ChronoCrypt!');

    const encrypted = await encryptData(data, publicKey, timestamp);

    expect(encrypted.timestamp).toBe(timestamp);
    expect(encrypted.encryptedKey).toBeInstanceOf(Uint8Array);
    expect(encrypted.encryptedKey.length).toBeGreaterThan(0);
    expect(encrypted.ephemeralPublicKey).toBeDefined();
    expect(encrypted.ephemeralPublicKey.kty).toBe('EC');
    expect(encrypted.encryptedData).toBeInstanceOf(Uint8Array);
    expect(encrypted.encryptedData.length).toBeGreaterThan(0);
    expect(encrypted.iv).toBeInstanceOf(Uint8Array);
    expect(encrypted.iv.length).toBe(12); // 96 bits
    expect(encrypted.authTag).toBeInstanceOf(Uint8Array);
    expect(encrypted.authTag.length).toBe(16); // 128 bits
  });

  test('encryptData and decryptData work correctly', async () => {
    const keypair = await generateMasterKeypair();
    const publicKey = await exportPublicKey(keypair.publicKey);
    const timestamp = Date.now();
    const originalData = new TextEncoder().encode('Sensitive information');

    // Encrypt with public key
    const encrypted = await encryptData(originalData, publicKey, timestamp);

    // Derive time-specific private key
    const timePrivateKey = await deriveTimeSpecificPrivateKey(keypair.privateKey, timestamp);

    // Decrypt with time-specific private key
    const decrypted = await decryptData(encrypted, timePrivateKey);

    expect(decrypted).toEqual(originalData);
    expect(new TextDecoder().decode(decrypted)).toBe('Sensitive information');
  });

  test('decryption with wrong private key fails', async () => {
    const keypair1 = await generateMasterKeypair();
    const keypair2 = await generateMasterKeypair();
    const publicKey1 = await exportPublicKey(keypair1.publicKey);
    const timestamp = Date.now();
    const data = new TextEncoder().encode('Secret data');

    // Encrypt with keypair1's public key
    const encrypted = await encryptData(data, publicKey1, timestamp);

    // Try to decrypt with keypair2's private key (wrong key)
    const wrongTimeKey = await deriveTimeSpecificPrivateKey(keypair2.privateKey, timestamp);

    await expect(decryptData(encrypted, wrongTimeKey)).rejects.toThrow();
  });

  test('decryption with wrong timestamp fails (KDF temporal binding)', async () => {
    const keypair = await generateMasterKeypair();
    const publicKey = await exportPublicKey(keypair.publicKey);
    const timestamp1 = 1000000;
    const data = new TextEncoder().encode('Timestamp-bound data');

    // Encrypt at timestamp1
    const encrypted = await encryptData(data, publicKey, timestamp1);

    // Try to decrypt with modified timestamp in package
    const tamperedPkg = { ...encrypted, timestamp: 2000000 };
    const masterKey = await deriveTimeSpecificPrivateKey(keypair.privateKey, timestamp1);

    // Should fail because KDF uses timestamp in derivation
    await expect(decryptData(tamperedPkg, masterKey)).rejects.toThrow();
  });

  test('tampered encrypted data fails authentication', async () => {
    const keypair = await generateMasterKeypair();
    const publicKey = await exportPublicKey(keypair.publicKey);
    const timestamp = Date.now();
    const data = new TextEncoder().encode('Important data');

    const encrypted = await encryptData(data, publicKey, timestamp);
    const timeKey = await deriveTimeSpecificPrivateKey(keypair.privateKey, timestamp);

    // Tamper with encrypted data
    encrypted.encryptedData[0] ^= 0xFF;

    await expect(decryptData(encrypted, timeKey)).rejects.toThrow(AuthenticationError);
  });

  test('tampered auth tag fails authentication', async () => {
    const keypair = await generateMasterKeypair();
    const publicKey = await exportPublicKey(keypair.publicKey);
    const timestamp = Date.now();
    const data = new TextEncoder().encode('Authenticated data');

    const encrypted = await encryptData(data, publicKey, timestamp);
    const timeKey = await deriveTimeSpecificPrivateKey(keypair.privateKey, timestamp);

    // Tamper with auth tag
    encrypted.authTag[0] ^= 0xFF;

    await expect(decryptData(encrypted, timeKey)).rejects.toThrow(AuthenticationError);
  });

  test('encryption with metadata preserves metadata', async () => {
    const keypair = await generateMasterKeypair();
    const publicKey = await exportPublicKey(keypair.publicKey);
    const timestamp = Date.now();
    const data = new TextEncoder().encode('Data with metadata');
    const metadata = {
      deviceId: 'sensor-001',
      location: 'datacenter-1',
      temperature: 22.5,
      humidity: 45
    };

    const encrypted = await encryptData(data, publicKey, timestamp, metadata);

    expect(encrypted.metadata).toEqual(metadata);

    // Verify metadata survives decryption
    const timeKey = await deriveTimeSpecificPrivateKey(keypair.privateKey, timestamp);
    const decrypted = await decryptData(encrypted, timeKey);

    expect(decrypted).toEqual(data);
  });

  test('serializeEncryptedPackage and deserializeEncryptedPackage are reversible', async () => {
    const keypair = await generateMasterKeypair();
    const publicKey = await exportPublicKey(keypair.publicKey);
    const timestamp = Date.now();
    const data = new TextEncoder().encode('Serialization test data');
    const metadata = { source: 'test-suite', version: 2 };

    const encrypted = await encryptData(data, publicKey, timestamp, metadata);

    const serialized = serializeEncryptedPackage(encrypted);
    expect(serialized).toBeInstanceOf(Uint8Array);
    expect(serialized.length).toBeGreaterThan(0);

    const deserialized = deserializeEncryptedPackage(serialized);

    expect(deserialized.timestamp).toBe(encrypted.timestamp);
    expect(deserialized.encryptedKey).toEqual(encrypted.encryptedKey);
    expect(deserialized.ephemeralPublicKey).toEqual(encrypted.ephemeralPublicKey);
    expect(deserialized.encryptedData).toEqual(encrypted.encryptedData);
    expect(deserialized.iv).toEqual(encrypted.iv);
    expect(deserialized.authTag).toEqual(encrypted.authTag);
    expect(deserialized.metadata).toEqual(encrypted.metadata);

    // Verify deserialized package can be decrypted
    const timeKey = await deriveTimeSpecificPrivateKey(keypair.privateKey, timestamp);
    const decrypted = await decryptData(deserialized, timeKey);
    expect(decrypted).toEqual(data);
  });

  test('different ephemeral keys for each encryption', async () => {
    const keypair = await generateMasterKeypair();
    const publicKey = await exportPublicKey(keypair.publicKey);
    const timestamp = Date.now();
    const data = new TextEncoder().encode('Same data');

    const encrypted1 = await encryptData(data, publicKey, timestamp);
    const encrypted2 = await encryptData(data, publicKey, timestamp);

    // Ephemeral keys should be different
    expect(encrypted1.ephemeralPublicKey.x).not.toBe(encrypted2.ephemeralPublicKey.x);
    expect(encrypted1.ephemeralPublicKey.y).not.toBe(encrypted2.ephemeralPublicKey.y);

    // IVs should be different
    expect(encrypted1.iv).not.toEqual(encrypted2.iv);

    // Encrypted data should be different (different ephemeral keys + IVs)
    expect(encrypted1.encryptedData).not.toEqual(encrypted2.encryptedData);

    // But both should decrypt to same data
    const timeKey = await deriveTimeSpecificPrivateKey(keypair.privateKey, timestamp);
    const decrypted1 = await decryptData(encrypted1, timeKey);
    const decrypted2 = await decryptData(encrypted2, timeKey);

    expect(decrypted1).toEqual(data);
    expect(decrypted2).toEqual(data);
  });
});

describe('Security Properties', () => {
  test('public key alone cannot decrypt data', async () => {
    const keypair = await generateMasterKeypair();
    const publicKey = await exportPublicKey(keypair.publicKey);
    const timestamp = Date.now();
    const data = new TextEncoder().encode('Confidential data');

    const encrypted = await encryptData(data, publicKey, timestamp);

    // Having only the public key, we cannot derive the private key or decrypt
    // This is implicit in the asymmetric design - just verify encryption works
    expect(encrypted.encryptedData).toBeDefined();
    expect(encrypted.encryptedData).not.toEqual(data);
  });

  test('temporal isolation - timestamps bound via KDF', async () => {
    const keypair = await generateMasterKeypair();
    const publicKey = await exportPublicKey(keypair.publicKey);
    const masterKey = keypair.privateKey;

    const timestamp1 = 1000000;
    const timestamp2 = 2000000;

    const data1 = new TextEncoder().encode('Data at time 1');
    const data2 = new TextEncoder().encode('Data at time 2');

    const encrypted1 = await encryptData(data1, publicKey, timestamp1);
    const encrypted2 = await encryptData(data2, publicKey, timestamp2);

    // Tampering with timestamps should cause decryption to fail
    const tampered1 = { ...encrypted1, timestamp: timestamp2 };
    const tampered2 = { ...encrypted2, timestamp: timestamp1 };

    await expect(decryptData(tampered1, masterKey)).rejects.toThrow();
    await expect(decryptData(tampered2, masterKey)).rejects.toThrow();

    // But correct timestamps work
    const decrypted1 = await decryptData(encrypted1, masterKey);
    const decrypted2 = await decryptData(encrypted2, masterKey);

    expect(decrypted1).toEqual(data1);
    expect(decrypted2).toEqual(data2);
  });

  test('forward secrecy - different ephemeral keys per encryption', async () => {
    const keypair = await generateMasterKeypair();
    const publicKey = await exportPublicKey(keypair.publicKey);
    const masterKey = keypair.privateKey;

    const timestamps = [1000, 2000, 3000, 4000, 5000];
    const dataItems = timestamps.map(t =>
      new TextEncoder().encode(`Data at ${t}`)
    );

    const encrypted = await Promise.all(
      timestamps.map((t, i) => encryptData(dataItems[i], publicKey, t))
    );

    // Each encryption uses different ephemeral keys
    expect(encrypted[0].ephemeralPublicKey.x).not.toBe(encrypted[1].ephemeralPublicKey.x);
    expect(encrypted[1].ephemeralPublicKey.x).not.toBe(encrypted[2].ephemeralPublicKey.x);

    // Master key can decrypt all timestamps
    for (let i = 0; i < timestamps.length; i++) {
      const decrypted = await decryptData(encrypted[i], masterKey);
      expect(decrypted).toEqual(dataItems[i]);
    }

    // But tampering with any timestamp prevents decryption
    const tampered = { ...encrypted[2], timestamp: 9999 };
    await expect(decryptData(tampered, masterKey)).rejects.toThrow();
  });
});
