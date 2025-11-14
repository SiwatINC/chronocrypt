/**
 * Hybrid Asymmetric Encryption for ChronoCrypt
 *
 * Uses ECIES (Elliptic Curve Integrated Encryption Scheme) + AES-256-GCM
 * - Generate ephemeral EC keypair
 * - Derive shared secret via ECDH with recipient's public key
 * - Use shared secret to encrypt symmetric key (key wrapping)
 * - Encrypt data with AES-256-GCM using symmetric key
 */

import { importPublicKey } from './key-derivation';
import {
  ExportedPublicKey,
  TimeSpecificPrivateKey,
  EncryptedPackage,
  Timestamp,
  EncryptionError,
  DecryptionError,
  AuthenticationError
} from '../types/index';

/**
 * AES-GCM parameters
 */
const AES_KEY_LENGTH = 256;
const AES_IV_LENGTH = 12; // 96 bits recommended for GCM
const AES_TAG_LENGTH = 128; // 128 bits

/**
 * Generate random IV for AES-GCM
 */
function generateIV(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(AES_IV_LENGTH));
}

/**
 * Encrypt data using hybrid encryption (ECIES + AES-GCM)
 *
 * Process:
 * 1. Generate random symmetric key K
 * 2. Encrypt data with AES-256-GCM using K
 * 3. Generate ephemeral ECDH keypair
 * 4. Derive shared secret with recipient's public key
 * 5. Wrap (encrypt) K using shared secret
 *
 * @param data - Data to encrypt
 * @param recipientPublicKey - Recipient's master public key (JWK format)
 * @param timestamp - Timestamp for time-based key derivation
 * @param metadata - Optional metadata
 * @returns Encrypted package
 */
export async function encryptData(
  data: Uint8Array,
  recipientPublicKey: ExportedPublicKey,
  timestamp: Timestamp,
  metadata?: Record<string, unknown>
): Promise<EncryptedPackage> {
  try {
    // 1. Generate random symmetric key for AES-GCM
    const symmetricKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: AES_KEY_LENGTH },
      true, // extractable
      ['encrypt']
    );

    // 2. Encrypt data with AES-GCM
    const dataIv = generateIV();
    const encryptedData = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: dataIv as BufferSource,
        tagLength: AES_TAG_LENGTH
      },
      symmetricKey,
      data as BufferSource
    );

    // Extract ciphertext and auth tag (GCM includes tag in output)
    const encryptedBytes = new Uint8Array(encryptedData);
    const tagStart = encryptedBytes.length - (AES_TAG_LENGTH / 8);
    const ciphertext = encryptedBytes.slice(0, tagStart);
    const authTag = encryptedBytes.slice(tagStart);

    // 3. Generate ephemeral ECDH keypair
    const ephemeralKeypair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );

    // 4. Import recipient public key and derive shared secret
    const recipientKey = await importPublicKey(recipientPublicKey);

    // Derive ECDH shared secret as raw bits
    const ecdhSharedSecret = await crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: recipientKey
      },
      ephemeralKeypair.privateKey,
      256 // 256 bits
    );

    // Incorporate timestamp into KDF for temporal binding
    // Derive wrapping key: HKDF(ecdh_secret, salt=timestamp)
    const timestampBytes = new Uint8Array(8);
    new DataView(timestampBytes.buffer).setBigUint64(0, BigInt(timestamp), false);

    // Combine ECDH secret with timestamp for HKDF
    const ikm = new Uint8Array(ecdhSharedSecret);
    const info = new TextEncoder().encode('ChronoCrypt-Wrap-v1');

    // Import secret for HKDF
    const baseKey = await crypto.subtle.importKey(
      'raw',
      ikm,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );

    // Derive time-bound wrapping key using HKDF with timestamp as salt
    const wrapKey = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: timestampBytes,
        info: info
      },
      baseKey,
      { name: 'AES-KW', length: 256 },
      false,
      ['wrapKey']
    );

    // 5. Wrap (encrypt) the symmetric key
    const wrappedKey = await crypto.subtle.wrapKey(
      'raw',
      symmetricKey,
      wrapKey,
      { name: 'AES-KW' }
    );

    // Export ephemeral public key for decryption
    const ephemeralPublicJwk = await crypto.subtle.exportKey('jwk', ephemeralKeypair.publicKey);

    return {
      timestamp,
      encryptedKey: new Uint8Array(wrappedKey),
      ephemeralPublicKey: ephemeralPublicJwk,
      encryptedData: ciphertext,
      iv: dataIv,
      authTag: authTag,
      metadata
    };
  } catch (error) {
    throw new EncryptionError(
      `Encryption failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * Decrypt data using time-specific private key
 *
 * Process:
 * 1. Derive shared secret using ephemeral public key and time-specific private key
 * 2. Unwrap (decrypt) symmetric key K
 * 3. Decrypt data using K and AES-GCM
 *
 * @param pkg - Encrypted package
 * @param timeSpecificPrivateKey - Time-specific private key for this timestamp
 * @returns Decrypted data
 */
export async function decryptData(
  pkg: EncryptedPackage,
  timeSpecificPrivateKey: TimeSpecificPrivateKey
): Promise<Uint8Array> {
  try {
    // 1. Import ephemeral public key
    const ephemeralPublicKey = await crypto.subtle.importKey(
      'jwk',
      pkg.ephemeralPublicKey,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    // 2. Derive ECDH shared secret as raw bits
    const ecdhSharedSecret = await crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: ephemeralPublicKey
      },
      timeSpecificPrivateKey,
      256
    );

    // 3. Incorporate timestamp into KDF (same as encryption)
    const timestampBytes = new Uint8Array(8);
    new DataView(timestampBytes.buffer).setBigUint64(0, BigInt(pkg.timestamp), false);

    const ikm = new Uint8Array(ecdhSharedSecret);
    const info = new TextEncoder().encode('ChronoCrypt-Wrap-v1');

    // Import secret for HKDF
    const baseKey = await crypto.subtle.importKey(
      'raw',
      ikm,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );

    // Derive time-bound unwrapping key using HKDF with timestamp as salt
    const unwrapKey = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: timestampBytes,
        info: info
      },
      baseKey,
      { name: 'AES-KW', length: 256 },
      false,
      ['unwrapKey']
    );

    // 4. Unwrap (decrypt) the symmetric key
    const symmetricKey = await crypto.subtle.unwrapKey(
      'raw',
      pkg.encryptedKey as BufferSource,
      unwrapKey,
      { name: 'AES-KW' },
      { name: 'AES-GCM', length: AES_KEY_LENGTH },
      false,
      ['decrypt']
    );

    // 5. Reconstruct encrypted data with auth tag
    const encryptedWithTag = new Uint8Array(pkg.encryptedData.length + pkg.authTag.length);
    encryptedWithTag.set(pkg.encryptedData, 0);
    encryptedWithTag.set(pkg.authTag, pkg.encryptedData.length);

    // 6. Decrypt data with AES-GCM
    const decryptedData = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: pkg.iv as BufferSource,
        tagLength: AES_TAG_LENGTH
      },
      symmetricKey,
      encryptedWithTag as BufferSource
    );

    return new Uint8Array(decryptedData);
  } catch (error) {
    // GCM authentication failure
    // Web Crypto throws "operation failed" for GCM auth failures
    if (error instanceof Error &&
        (error.message.includes('authentication') ||
         error.message.includes('operation failed') ||
         error.name === 'OperationError')) {
      throw new AuthenticationError('Data authentication failed - data may be tampered');
    }
    throw new DecryptionError(
      `Decryption failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * Serialize encrypted package to portable format
 *
 * @param pkg - Encrypted package
 * @returns Serialized bytes
 */
export function serializeEncryptedPackage(pkg: EncryptedPackage): Uint8Array {
  const ephemeralKeyStr = JSON.stringify(pkg.ephemeralPublicKey);
  const ephemeralKeyBytes = new TextEncoder().encode(ephemeralKeyStr);
  const metadataBytes = pkg.metadata
    ? new TextEncoder().encode(JSON.stringify(pkg.metadata))
    : new Uint8Array(0);

  const totalSize =
    8 + // timestamp
    4 + pkg.encryptedKey.length + // encrypted key length + data
    4 + ephemeralKeyBytes.length + // ephemeral key length + data
    4 + pkg.encryptedData.length + // encrypted data length + data
    4 + pkg.iv.length + // IV length + data
    4 + pkg.authTag.length + // tag length + data
    4 + metadataBytes.length; // metadata length + data

  const buffer = new Uint8Array(totalSize);
  const view = new DataView(buffer.buffer);
  let offset = 0;

  // Write timestamp
  view.setBigUint64(offset, BigInt(pkg.timestamp), false);
  offset += 8;

  // Write encrypted key
  view.setUint32(offset, pkg.encryptedKey.length, false);
  offset += 4;
  buffer.set(pkg.encryptedKey, offset);
  offset += pkg.encryptedKey.length;

  // Write ephemeral public key
  view.setUint32(offset, ephemeralKeyBytes.length, false);
  offset += 4;
  buffer.set(ephemeralKeyBytes, offset);
  offset += ephemeralKeyBytes.length;

  // Write encrypted data
  view.setUint32(offset, pkg.encryptedData.length, false);
  offset += 4;
  buffer.set(pkg.encryptedData, offset);
  offset += pkg.encryptedData.length;

  // Write IV
  view.setUint32(offset, pkg.iv.length, false);
  offset += 4;
  buffer.set(pkg.iv, offset);
  offset += pkg.iv.length;

  // Write auth tag
  view.setUint32(offset, pkg.authTag.length, false);
  offset += 4;
  buffer.set(pkg.authTag, offset);
  offset += pkg.authTag.length;

  // Write metadata
  view.setUint32(offset, metadataBytes.length, false);
  offset += 4;
  buffer.set(metadataBytes, offset);

  return buffer;
}

/**
 * Deserialize encrypted package from portable format
 *
 * @param bytes - Serialized bytes
 * @returns Encrypted package
 */
export function deserializeEncryptedPackage(bytes: Uint8Array): EncryptedPackage {
  try {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let offset = 0;

    // Read timestamp
    const timestamp = Number(view.getBigUint64(offset, false));
    offset += 8;

    // Read encrypted key
    const encKeyLen = view.getUint32(offset, false);
    offset += 4;
    const encryptedKey = bytes.slice(offset, offset + encKeyLen);
    offset += encKeyLen;

    // Read ephemeral public key
    const ephKeyLen = view.getUint32(offset, false);
    offset += 4;
    const ephKeyBytes = bytes.slice(offset, offset + ephKeyLen);
    const ephemeralPublicKey = JSON.parse(new TextDecoder().decode(ephKeyBytes));
    offset += ephKeyLen;

    // Read encrypted data
    const dataLen = view.getUint32(offset, false);
    offset += 4;
    const encryptedData = bytes.slice(offset, offset + dataLen);
    offset += dataLen;

    // Read IV
    const ivLen = view.getUint32(offset, false);
    offset += 4;
    const iv = bytes.slice(offset, offset + ivLen);
    offset += ivLen;

    // Read auth tag
    const tagLen = view.getUint32(offset, false);
    offset += 4;
    const authTag = bytes.slice(offset, offset + tagLen);
    offset += tagLen;

    // Read metadata
    const metaLen = view.getUint32(offset, false);
    offset += 4;
    let metadata: Record<string, unknown> | undefined;
    if (metaLen > 0) {
      const metaBytes = bytes.slice(offset, offset + metaLen);
      metadata = JSON.parse(new TextDecoder().decode(metaBytes));
    }

    return {
      timestamp,
      encryptedKey,
      ephemeralPublicKey,
      encryptedData,
      iv,
      authTag,
      metadata
    };
  } catch (error) {
    throw new DecryptionError(
      `Failed to deserialize package: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}
