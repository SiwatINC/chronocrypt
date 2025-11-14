import { describe, test, expect } from 'bun:test';
import {
  generateMasterKey,
  validateMasterKey,
  deriveTimeSpecificKey,
  deriveMultipleKeys,
  destroyKey,
  importMasterKeyFromHex,
  exportMasterKeyToHex,
  importMasterKeyFromBase64,
  exportMasterKeyToBase64,
  MASTER_KEY_SIZE
} from '../src/crypto/key-derivation';
import {
  encryptData,
  decryptData,
  verifyAuthentication,
  generateIV,
  serializeEncryptedPackage,
  deserializeEncryptedPackage,
  IV_SIZE
} from '../src/crypto/encryption';
import { InvalidKeyError, AuthenticationError } from '../src/types';

describe('Key Derivation', () => {
  test('generateMasterKey creates 256-bit key', () => {
    const key = generateMasterKey();
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(MASTER_KEY_SIZE);
  });

  test('generateMasterKey creates unique keys', () => {
    const key1 = generateMasterKey();
    const key2 = generateMasterKey();
    expect(key1).not.toEqual(key2);
  });

  test('validateMasterKey accepts valid keys', () => {
    const key = generateMasterKey();
    expect(() => validateMasterKey(key)).not.toThrow();
  });

  test('validateMasterKey rejects invalid key size', () => {
    const invalidKey = new Uint8Array(16); // Wrong size
    expect(() => validateMasterKey(invalidKey)).toThrow(InvalidKeyError);
  });

  test('validateMasterKey rejects all-zero keys', () => {
    const zeroKey = new Uint8Array(MASTER_KEY_SIZE);
    expect(() => validateMasterKey(zeroKey)).toThrow(InvalidKeyError);
  });

  test('deriveTimeSpecificKey produces deterministic results', async () => {
    const masterKey = generateMasterKey();
    const timestamp = Date.now();

    const key1 = await deriveTimeSpecificKey(masterKey, timestamp);
    const key2 = await deriveTimeSpecificKey(masterKey, timestamp);

    expect(key1).toEqual(key2);
  });

  test('deriveTimeSpecificKey produces different keys for different timestamps', async () => {
    const masterKey = generateMasterKey();
    const timestamp1 = 1000000;
    const timestamp2 = 2000000;

    const key1 = await deriveTimeSpecificKey(masterKey, timestamp1);
    const key2 = await deriveTimeSpecificKey(masterKey, timestamp2);

    expect(key1).not.toEqual(key2);
  });

  test('deriveMultipleKeys produces correct number of keys', async () => {
    const masterKey = generateMasterKey();
    const timestamps = [1000, 2000, 3000, 4000, 5000];

    const keys = await deriveMultipleKeys(masterKey, timestamps);

    expect(keys.size).toBe(timestamps.length);
    for (const timestamp of timestamps) {
      expect(keys.has(timestamp)).toBe(true);
    }
  });

  test('exportMasterKeyToHex and importMasterKeyFromHex are reversible', () => {
    const originalKey = generateMasterKey();
    const hex = exportMasterKeyToHex(originalKey);
    const importedKey = importMasterKeyFromHex(hex);

    expect(importedKey).toEqual(originalKey);
  });

  test('exportMasterKeyToBase64 and importMasterKeyFromBase64 are reversible', () => {
    const originalKey = generateMasterKey();
    const base64 = exportMasterKeyToBase64(originalKey);
    const importedKey = importMasterKeyFromBase64(base64);

    expect(importedKey).toEqual(originalKey);
  });

  test('destroyKey zeros out key data', () => {
    const key = generateMasterKey();
    destroyKey(key);

    const isAllZeros = key.every(byte => byte === 0);
    expect(isAllZeros).toBe(true);
  });
});

describe('Encryption and Decryption', () => {
  test('generateIV creates correct size', () => {
    const iv = generateIV();
    expect(iv).toBeInstanceOf(Uint8Array);
    expect(iv.length).toBe(IV_SIZE);
  });

  test('generateIV creates unique IVs', () => {
    const iv1 = generateIV();
    const iv2 = generateIV();
    expect(iv1).not.toEqual(iv2);
  });

  test('encryptData and decryptData work correctly', async () => {
    const masterKey = generateMasterKey();
    const timestamp = Date.now();
    const originalData = new TextEncoder().encode('Hello, ChronoCrypt!');

    const timeKey = await deriveTimeSpecificKey(masterKey, timestamp);
    const encrypted = await encryptData(originalData, timeKey, timestamp);

    expect(encrypted.timestamp).toBe(timestamp);
    expect(encrypted.encryptedData).not.toEqual(originalData);

    const decrypted = await decryptData(encrypted, timeKey);
    expect(decrypted).toEqual(originalData);

    destroyKey(timeKey);
  });

  test('decryption with wrong key fails', async () => {
    const masterKey = generateMasterKey();
    const wrongMasterKey = generateMasterKey();
    const timestamp = Date.now();
    const originalData = new TextEncoder().encode('Secret data');

    const timeKey = await deriveTimeSpecificKey(masterKey, timestamp);
    const encrypted = await encryptData(originalData, timeKey, timestamp);

    const wrongTimeKey = await deriveTimeSpecificKey(wrongMasterKey, timestamp);

    await expect(decryptData(encrypted, wrongTimeKey)).rejects.toThrow(AuthenticationError);

    destroyKey(timeKey);
    destroyKey(wrongTimeKey);
  });

  test('tampered data fails authentication', async () => {
    const masterKey = generateMasterKey();
    const timestamp = Date.now();
    const originalData = new TextEncoder().encode('Important data');

    const timeKey = await deriveTimeSpecificKey(masterKey, timestamp);
    const encrypted = await encryptData(originalData, timeKey, timestamp);

    // Tamper with encrypted data
    encrypted.encryptedData[0] ^= 0xFF;

    await expect(decryptData(encrypted, timeKey)).rejects.toThrow(AuthenticationError);

    destroyKey(timeKey);
  });

  test('verifyAuthentication works correctly', async () => {
    const masterKey = generateMasterKey();
    const timestamp = Date.now();
    const data = new TextEncoder().encode('Test data');

    const timeKey = await deriveTimeSpecificKey(masterKey, timestamp);
    const encrypted = await encryptData(data, timeKey, timestamp);

    const isValid = await verifyAuthentication(encrypted, timeKey);
    expect(isValid).toBe(true);

    destroyKey(timeKey);
  });

  test('serializeEncryptedPackage and deserializeEncryptedPackage are reversible', async () => {
    const masterKey = generateMasterKey();
    const timestamp = Date.now();
    const data = new TextEncoder().encode('Serialization test');
    const metadata = { source: 'test', version: 1 };

    const timeKey = await deriveTimeSpecificKey(masterKey, timestamp);
    const encrypted = await encryptData(data, timeKey, timestamp, metadata);

    const serialized = serializeEncryptedPackage(encrypted);
    const deserialized = deserializeEncryptedPackage(serialized);

    expect(deserialized.timestamp).toBe(encrypted.timestamp);
    expect(deserialized.encryptedData).toEqual(encrypted.encryptedData);
    expect(deserialized.iv).toEqual(encrypted.iv);
    expect(deserialized.authTag).toEqual(encrypted.authTag);
    expect(deserialized.metadata).toEqual(encrypted.metadata);

    destroyKey(timeKey);
  });

  test('encryption with metadata preserves metadata', async () => {
    const masterKey = generateMasterKey();
    const timestamp = Date.now();
    const data = new TextEncoder().encode('Data with metadata');
    const metadata = {
      deviceId: 'sensor-001',
      location: 'building-A',
      temperature: 22.5
    };

    const timeKey = await deriveTimeSpecificKey(masterKey, timestamp);
    const encrypted = await encryptData(data, timeKey, timestamp, metadata);

    expect(encrypted.metadata).toEqual(metadata);

    destroyKey(timeKey);
  });
});
