/**
 * Key Derivation Functions for ChronoCrypt
 *
 * Implements deterministic key derivation: DERIVED_KEY = HASH(MASTER_KEY || TIMESTAMP)
 * Using SHA-256 as the cryptographic hash function
 */

import {
  MasterKey,
  TimeSpecificKey,
  Timestamp,
  KeyDerivationError,
  InvalidKeyError
} from '~/types';

/**
 * Master key size in bytes (256-bit)
 */
export const MASTER_KEY_SIZE = 32;

/**
 * Derived key size in bytes (256-bit)
 */
export const DERIVED_KEY_SIZE = 32;

/**
 * Generate a cryptographically secure master key
 *
 * @returns A new 256-bit master key
 */
export function generateMasterKey(): MasterKey {
  const key = new Uint8Array(MASTER_KEY_SIZE);
  crypto.getRandomValues(key);
  return key;
}

/**
 * Validate that a master key meets security requirements
 *
 * @param key - The key to validate
 * @throws {InvalidKeyError} If the key is invalid
 */
export function validateMasterKey(key: MasterKey): void {
  if (!(key instanceof Uint8Array)) {
    throw new InvalidKeyError('Master key must be a Uint8Array');
  }

  if (key.length !== MASTER_KEY_SIZE) {
    throw new InvalidKeyError(
      `Master key must be exactly ${MASTER_KEY_SIZE} bytes (256 bits), got ${key.length} bytes`
    );
  }

  // Check that the key is not all zeros (weak key)
  const isAllZeros = key.every(byte => byte === 0);
  if (isAllZeros) {
    throw new InvalidKeyError('Master key must not be all zeros');
  }
}

/**
 * Derive a time-specific encryption key from master key and timestamp
 *
 * Implementation: DERIVED_KEY = SHA-256(MASTER_KEY || TIMESTAMP)
 *
 * @param masterKey - The master key (256-bit)
 * @param timestamp - Unix epoch timestamp in milliseconds
 * @returns Time-specific derived key (256-bit)
 * @throws {KeyDerivationError} If key derivation fails
 */
export async function deriveTimeSpecificKey(
  masterKey: MasterKey,
  timestamp: Timestamp
): Promise<TimeSpecificKey> {
  try {
    validateMasterKey(masterKey);

    // Convert timestamp to 8-byte big-endian representation
    const timestampBytes = new Uint8Array(8);
    const dataView = new DataView(timestampBytes.buffer);
    dataView.setBigUint64(0, BigInt(timestamp), false); // false = big-endian

    // Concatenate master key and timestamp
    const combined = new Uint8Array(masterKey.length + timestampBytes.length);
    combined.set(masterKey, 0);
    combined.set(timestampBytes, masterKey.length);

    // Hash the combined data using SHA-256
    const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
    const derivedKey = new Uint8Array(hashBuffer);

    // Securely zero out the combined buffer
    combined.fill(0);

    return derivedKey;
  } catch (error) {
    if (error instanceof InvalidKeyError) {
      throw error;
    }
    throw new KeyDerivationError(
      `Failed to derive time-specific key: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * Derive multiple time-specific keys for a range of timestamps
 *
 * @param masterKey - The master key
 * @param timestamps - Array of timestamps
 * @returns Map of timestamp to derived key
 */
export async function deriveMultipleKeys(
  masterKey: MasterKey,
  timestamps: Timestamp[]
): Promise<Map<Timestamp, TimeSpecificKey>> {
  const keys = new Map<Timestamp, TimeSpecificKey>();

  // Derive keys in parallel for better performance
  const derivations = timestamps.map(async (timestamp) => {
    const key = await deriveTimeSpecificKey(masterKey, timestamp);
    return { timestamp, key };
  });

  const results = await Promise.all(derivations);

  for (const { timestamp, key } of results) {
    keys.set(timestamp, key);
  }

  return keys;
}

/**
 * Securely destroy a key by overwriting its memory with zeros
 *
 * @param key - The key to destroy
 */
export function destroyKey(key: Uint8Array): void {
  key.fill(0);
}

/**
 * Import a master key from hex string representation
 *
 * @param hexString - Hex-encoded key string
 * @returns Master key as Uint8Array
 * @throws {InvalidKeyError} If the hex string is invalid
 */
export function importMasterKeyFromHex(hexString: string): MasterKey {
  // Remove any whitespace or separators
  const cleaned = hexString.replace(/[\s-:]/g, '');

  if (!/^[0-9a-fA-F]+$/.test(cleaned)) {
    throw new InvalidKeyError('Invalid hex string format');
  }

  if (cleaned.length !== MASTER_KEY_SIZE * 2) {
    throw new InvalidKeyError(
      `Hex string must represent ${MASTER_KEY_SIZE} bytes, got ${cleaned.length / 2} bytes`
    );
  }

  const key = new Uint8Array(MASTER_KEY_SIZE);
  for (let i = 0; i < MASTER_KEY_SIZE; i++) {
    key[i] = parseInt(cleaned.substr(i * 2, 2), 16);
  }

  validateMasterKey(key);
  return key;
}

/**
 * Export a master key to hex string representation
 *
 * @param key - The master key to export
 * @returns Hex-encoded string
 */
export function exportMasterKeyToHex(key: MasterKey): string {
  validateMasterKey(key);
  return Array.from(key)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Import a master key from base64 string representation
 *
 * @param base64String - Base64-encoded key string
 * @returns Master key as Uint8Array
 */
export function importMasterKeyFromBase64(base64String: string): MasterKey {
  try {
    // Bun has built-in Buffer support
    const buffer = Buffer.from(base64String, 'base64');
    const key = new Uint8Array(buffer);
    validateMasterKey(key);
    return key;
  } catch (error) {
    throw new InvalidKeyError(
      `Failed to import key from base64: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * Export a master key to base64 string representation
 *
 * @param key - The master key to export
 * @returns Base64-encoded string
 */
export function exportMasterKeyToBase64(key: MasterKey): string {
  validateMasterKey(key);
  return Buffer.from(key).toString('base64');
}
