/**
 * Authenticated Encryption Functions for ChronoCrypt
 *
 * Implements AES-256-CBC encryption with HMAC-SHA256 authentication
 */

import {
  TimeSpecificKey,
  IV,
  AuthenticationTag,
  EncryptedPackage,
  Timestamp,
  EncryptionError,
  DecryptionError,
  AuthenticationError
} from '../types';

/**
 * IV size for AES-CBC (128-bit / 16 bytes)
 */
export const IV_SIZE = 16;

/**
 * Authentication tag size for HMAC-SHA256 (256-bit / 32 bytes)
 */
export const AUTH_TAG_SIZE = 32;

/**
 * Generate a random initialization vector for AES-CBC
 *
 * @returns Random 16-byte IV
 */
export function generateIV(): IV {
  const iv = new Uint8Array(IV_SIZE);
  crypto.getRandomValues(iv);
  return iv;
}

/**
 * Import a cryptographic key for use with Web Crypto API
 *
 * @param keyBytes - Raw key bytes
 * @param algorithm - Algorithm to use the key with
 * @param usages - Key usage permissions
 * @returns CryptoKey object
 */
async function importKey(
  keyBytes: Uint8Array,
  algorithm: string,
  usages: KeyUsage[]
): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    'raw',
    keyBytes as BufferSource,
    { name: algorithm },
    false, // not extractable
    usages
  );
}

/**
 * Derive separate encryption and authentication keys from time-specific key
 *
 * Uses HKDF-like approach: separate keys from different hash contexts
 *
 * @param timeSpecificKey - The time-specific key
 * @returns Object with encryption and authentication keys
 */
async function deriveEncryptionAndAuthKeys(timeSpecificKey: TimeSpecificKey): Promise<{
  encryptionKey: CryptoKey;
  authenticationKey: Uint8Array;
}> {
  // Derive encryption key: SHA-256(timeSpecificKey || 0x01)
  const encKeyInput = new Uint8Array(timeSpecificKey.length + 1);
  encKeyInput.set(timeSpecificKey, 0);
  encKeyInput[timeSpecificKey.length] = 0x01;
  const encKeyHash = await crypto.subtle.digest('SHA-256', encKeyInput);
  const encKeyBytes = new Uint8Array(encKeyHash);

  // Derive authentication key: SHA-256(timeSpecificKey || 0x02)
  const authKeyInput = new Uint8Array(timeSpecificKey.length + 1);
  authKeyInput.set(timeSpecificKey, 0);
  authKeyInput[timeSpecificKey.length] = 0x02;
  const authKeyHash = await crypto.subtle.digest('SHA-256', authKeyInput);
  const authKeyBytes = new Uint8Array(authKeyHash);

  // Import encryption key for AES-CBC
  const encryptionKey = await importKey(encKeyBytes, 'AES-CBC', ['encrypt', 'decrypt']);

  // Clean up temporary buffers
  encKeyInput.fill(0);
  authKeyInput.fill(0);
  encKeyBytes.fill(0);

  return {
    encryptionKey,
    authenticationKey: authKeyBytes
  };
}

/**
 * Compute HMAC-SHA256 authentication tag
 *
 * @param authKey - Authentication key
 * @param data - Data to authenticate (encryptedData || IV || timestamp)
 * @returns Authentication tag
 */
async function computeHMAC(authKey: Uint8Array, data: Uint8Array): Promise<AuthenticationTag> {
  const key = await crypto.subtle.importKey(
    'raw',
    authKey as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', key, data as BufferSource);
  return new Uint8Array(signature);
}

/**
 * Verify HMAC-SHA256 authentication tag
 *
 * @param authKey - Authentication key
 * @param data - Data that was authenticated
 * @param tag - Authentication tag to verify
 * @returns True if tag is valid
 */
async function verifyHMAC(
  authKey: Uint8Array,
  data: Uint8Array,
  tag: AuthenticationTag
): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    'raw',
    authKey as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );

  return await crypto.subtle.verify('HMAC', key, tag as BufferSource, data as BufferSource);
}

/**
 * Encrypt data with authenticated encryption
 *
 * @param data - Data to encrypt
 * @param timeSpecificKey - Time-specific encryption key
 * @param timestamp - Timestamp for this encryption operation
 * @param metadata - Optional metadata to include
 * @returns Encrypted package with authentication
 * @throws {EncryptionError} If encryption fails
 */
export async function encryptData(
  data: Uint8Array,
  timeSpecificKey: TimeSpecificKey,
  timestamp: Timestamp,
  metadata?: Record<string, unknown>
): Promise<EncryptedPackage> {
  try {
    // Derive separate encryption and authentication keys
    const { encryptionKey, authenticationKey } = await deriveEncryptionAndAuthKeys(timeSpecificKey);

    // Generate random IV
    const iv = generateIV();

    // Encrypt data using AES-256-CBC
    const encryptedBuffer = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv: iv as BufferSource },
      encryptionKey,
      data as BufferSource
    );
    const encryptedData = new Uint8Array(encryptedBuffer);

    // Prepare data for authentication: encryptedData || IV || timestamp
    const timestampBytes = new Uint8Array(8);
    new DataView(timestampBytes.buffer).setBigUint64(0, BigInt(timestamp), false);

    const authData = new Uint8Array(
      encryptedData.length + iv.length + timestampBytes.length
    );
    authData.set(encryptedData, 0);
    authData.set(iv, encryptedData.length);
    authData.set(timestampBytes, encryptedData.length + iv.length);

    // Compute HMAC authentication tag
    const authTag = await computeHMAC(authenticationKey, authData);

    // Clean up sensitive data
    authenticationKey.fill(0);
    authData.fill(0);
    timestampBytes.fill(0);

    return {
      timestamp,
      encryptedData,
      iv,
      authTag,
      metadata
    };
  } catch (error) {
    throw new EncryptionError(
      `Encryption failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * Decrypt and verify authenticated encrypted data
 *
 * @param pkg - Encrypted package
 * @param timeSpecificKey - Time-specific decryption key
 * @returns Decrypted data
 * @throws {DecryptionError} If decryption fails
 * @throws {AuthenticationError} If authentication verification fails
 */
export async function decryptData(
  pkg: EncryptedPackage,
  timeSpecificKey: TimeSpecificKey
): Promise<Uint8Array> {
  try {
    // Derive separate encryption and authentication keys
    const { encryptionKey, authenticationKey } = await deriveEncryptionAndAuthKeys(timeSpecificKey);

    // Verify authentication tag first
    const timestampBytes = new Uint8Array(8);
    new DataView(timestampBytes.buffer).setBigUint64(0, BigInt(pkg.timestamp), false);

    const authData = new Uint8Array(
      pkg.encryptedData.length + pkg.iv.length + timestampBytes.length
    );
    authData.set(pkg.encryptedData, 0);
    authData.set(pkg.iv, pkg.encryptedData.length);
    authData.set(timestampBytes, pkg.encryptedData.length + pkg.iv.length);

    const isValid = await verifyHMAC(authenticationKey, authData, pkg.authTag);

    // Clean up auth data
    authenticationKey.fill(0);
    authData.fill(0);
    timestampBytes.fill(0);

    if (!isValid) {
      throw new AuthenticationError(
        'Authentication verification failed - data may have been tampered with'
      );
    }

    // Decrypt data using AES-256-CBC
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-CBC', iv: pkg.iv as BufferSource },
      encryptionKey,
      pkg.encryptedData as BufferSource
    );

    return new Uint8Array(decryptedBuffer);
  } catch (error) {
    if (error instanceof AuthenticationError) {
      throw error;
    }
    throw new DecryptionError(
      `Decryption failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * Verify the authenticity of an encrypted package without decrypting
 *
 * @param pkg - Encrypted package to verify
 * @param timeSpecificKey - Time-specific key
 * @returns True if authentication is valid
 */
export async function verifyAuthentication(
  pkg: EncryptedPackage,
  timeSpecificKey: TimeSpecificKey
): Promise<boolean> {
  try {
    const { authenticationKey } = await deriveEncryptionAndAuthKeys(timeSpecificKey);

    const timestampBytes = new Uint8Array(8);
    new DataView(timestampBytes.buffer).setBigUint64(0, BigInt(pkg.timestamp), false);

    const authData = new Uint8Array(
      pkg.encryptedData.length + pkg.iv.length + timestampBytes.length
    );
    authData.set(pkg.encryptedData, 0);
    authData.set(pkg.iv, pkg.encryptedData.length);
    authData.set(timestampBytes, pkg.encryptedData.length + pkg.iv.length);

    const isValid = await verifyHMAC(authenticationKey, authData, pkg.authTag);

    // Clean up
    authenticationKey.fill(0);
    authData.fill(0);
    timestampBytes.fill(0);

    return isValid;
  } catch {
    return false;
  }
}

/**
 * Serialize an encrypted package to a portable format
 *
 * Format: [timestamp(8)] [ivLength(2)] [iv] [tagLength(2)] [tag] [encDataLength(4)] [encData] [metadata]
 *
 * @param pkg - Encrypted package
 * @returns Serialized bytes
 */
export function serializeEncryptedPackage(pkg: EncryptedPackage): Uint8Array {
  const metadataBytes = pkg.metadata
    ? new TextEncoder().encode(JSON.stringify(pkg.metadata))
    : new Uint8Array(0);

  const totalSize =
    8 + // timestamp
    2 + pkg.iv.length + // IV length + IV
    2 + pkg.authTag.length + // tag length + tag
    4 + pkg.encryptedData.length + // data length + data
    4 + metadataBytes.length; // metadata length + metadata

  const buffer = new Uint8Array(totalSize);
  const view = new DataView(buffer.buffer);
  let offset = 0;

  // Write timestamp
  view.setBigUint64(offset, BigInt(pkg.timestamp), false);
  offset += 8;

  // Write IV
  view.setUint16(offset, pkg.iv.length, false);
  offset += 2;
  buffer.set(pkg.iv, offset);
  offset += pkg.iv.length;

  // Write auth tag
  view.setUint16(offset, pkg.authTag.length, false);
  offset += 2;
  buffer.set(pkg.authTag, offset);
  offset += pkg.authTag.length;

  // Write encrypted data
  view.setUint32(offset, pkg.encryptedData.length, false);
  offset += 4;
  buffer.set(pkg.encryptedData, offset);
  offset += pkg.encryptedData.length;

  // Write metadata
  view.setUint32(offset, metadataBytes.length, false);
  offset += 4;
  buffer.set(metadataBytes, offset);

  return buffer;
}

/**
 * Deserialize an encrypted package from portable format
 *
 * @param bytes - Serialized bytes
 * @returns Encrypted package
 * @throws {DecryptionError} If deserialization fails
 */
export function deserializeEncryptedPackage(bytes: Uint8Array): EncryptedPackage {
  try {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let offset = 0;

    // Read timestamp
    const timestamp = Number(view.getBigUint64(offset, false));
    offset += 8;

    // Read IV
    const ivLength = view.getUint16(offset, false);
    offset += 2;
    const iv = bytes.slice(offset, offset + ivLength);
    offset += ivLength;

    // Read auth tag
    const tagLength = view.getUint16(offset, false);
    offset += 2;
    const authTag = bytes.slice(offset, offset + tagLength);
    offset += tagLength;

    // Read encrypted data
    const dataLength = view.getUint32(offset, false);
    offset += 4;
    const encryptedData = bytes.slice(offset, offset + dataLength);
    offset += dataLength;

    // Read metadata
    const metadataLength = view.getUint32(offset, false);
    offset += 4;
    let metadata: Record<string, unknown> | undefined;
    if (metadataLength > 0) {
      const metadataBytes = bytes.slice(offset, offset + metadataLength);
      const metadataStr = new TextDecoder().decode(metadataBytes);
      metadata = JSON.parse(metadataStr);
    }

    return {
      timestamp,
      encryptedData,
      iv,
      authTag,
      metadata
    };
  } catch (error) {
    throw new DecryptionError(
      `Failed to deserialize encrypted package: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}
