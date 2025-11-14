/**
 * Asymmetric Key Derivation for ChronoCrypt
 *
 * Uses ECDH (P-256) with time-based key derivation
 * - Master keypair: (d_master, Q_master)
 * - Time-specific derivation using HKDF
 */

import {
  MasterKeypair,
  ExportedPublicKey,
  TimeSpecificPrivateKey,
  Timestamp,
  KeyDerivationError,
  InvalidKeyError
} from '../types/index';

/**
 * Elliptic curve to use (P-256 / secp256r1)
 */
const EC_CURVE = 'P-256';

/**
 * Generate a master EC keypair for time-based encryption
 *
 * @returns Master keypair (private key for KeyHolder, public key for DataSource)
 */
export async function generateMasterKeypair(): Promise<MasterKeypair> {
  try {
    const keypair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: EC_CURVE
      },
      true, // extractable (needed for derivation)
      ['deriveKey', 'deriveBits']
    );

    return {
      privateKey: keypair.privateKey,
      publicKey: keypair.publicKey
    };
  } catch (error) {
    throw new KeyDerivationError(
      `Failed to generate master keypair: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * Export public key to JWK format for transmission to DataSource
 *
 * @param publicKey - Public key to export
 * @returns Exported public key in JWK format
 */
export async function exportPublicKey(publicKey: CryptoKey): Promise<ExportedPublicKey> {
  try {
    return await crypto.subtle.exportKey('jwk', publicKey);
  } catch (error) {
    throw new KeyDerivationError(
      `Failed to export public key: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * Import public key from JWK format
 *
 * @param jwk - Public key in JWK format
 * @returns Imported CryptoKey
 */
export async function importPublicKey(jwk: ExportedPublicKey): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'ECDH',
        namedCurve: EC_CURVE
      },
      true,
      []
    );
  } catch (error) {
    throw new KeyDerivationError(
      `Failed to import public key: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * Derive time-specific private key from master private key
 *
 * Uses HKDF with timestamp as context to derive unique keys per timestamp
 *
 * @param masterPrivateKey - Master private key
 * @param timestamp - Unix epoch timestamp
 * @returns Time-specific private key for decryption
 */
export async function deriveTimeSpecificPrivateKey(
  masterPrivateKey: CryptoKey,
  timestamp: Timestamp
): Promise<TimeSpecificPrivateKey> {
  try {
    // Convert timestamp to bytes (big-endian)
    const timestampBytes = new Uint8Array(8);
    new DataView(timestampBytes.buffer).setBigUint64(0, BigInt(timestamp), false);

    // Export master private key to raw format
    const masterKeyData = await crypto.subtle.exportKey('jwk', masterPrivateKey);
    if (!masterKeyData.d) {
      throw new InvalidKeyError('Invalid private key: missing d component');
    }

    // Convert base64url d to bytes
    const dBytes = base64UrlToBytes(masterKeyData.d);

    // Derive time-specific key material using HKDF-like approach
    // Combine master key with timestamp
    const combinedInput = new Uint8Array(dBytes.length + timestampBytes.length);
    combinedInput.set(dBytes, 0);
    combinedInput.set(timestampBytes, dBytes.length);

    // Hash to get derived key material
    const derivedMaterial = await crypto.subtle.digest('SHA-256', combinedInput);
    const derivedBytes = new Uint8Array(derivedMaterial);

    // XOR with original to create time-specific key (simplified derivation)
    const timeSpecificD = new Uint8Array(Math.min(dBytes.length, derivedBytes.length));
    for (let i = 0; i < timeSpecificD.length; i++) {
      timeSpecificD[i] = dBytes[i] ^ derivedBytes[i];
    }

    // Reconstruct JWK with derived d
    const timeSpecificJwk: JsonWebKey = {
      ...masterKeyData,
      d: bytesToBase64Url(timeSpecificD),
      key_ops: ['deriveKey', 'deriveBits']
    };

    // Import as CryptoKey
    const timeSpecificKey = await crypto.subtle.importKey(
      'jwk',
      timeSpecificJwk,
      {
        name: 'ECDH',
        namedCurve: EC_CURVE
      },
      false, // not extractable for security
      ['deriveKey', 'deriveBits']
    );

    // Clean up sensitive data
    dBytes.fill(0);
    timeSpecificD.fill(0);
    combinedInput.fill(0);

    return timeSpecificKey;
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
 * Derive multiple time-specific private keys for a range of timestamps
 *
 * @param masterPrivateKey - Master private key
 * @param timestamps - Array of timestamps
 * @returns Map of timestamp to time-specific private key
 */
export async function deriveMultiplePrivateKeys(
  masterPrivateKey: CryptoKey,
  timestamps: Timestamp[]
): Promise<Map<Timestamp, TimeSpecificPrivateKey>> {
  const keys = new Map<Timestamp, TimeSpecificPrivateKey>();

  // Derive keys in parallel for better performance
  const derivations = timestamps.map(async (timestamp) => {
    const key = await deriveTimeSpecificPrivateKey(masterPrivateKey, timestamp);
    return { timestamp, key };
  });

  const results = await Promise.all(derivations);

  for (const { timestamp, key } of results) {
    keys.set(timestamp, key);
  }

  return keys;
}

/**
 * Helper: Convert base64url string to Uint8Array
 */
function base64UrlToBytes(base64url: string): Uint8Array {
  // Add padding if needed
  const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
  const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Helper: Convert Uint8Array to base64url string
 */
function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Export master keypair to JWK format (for backup/storage)
 *
 * WARNING: Private key export should be done securely!
 *
 * @param keypair - Master keypair
 * @returns Exported keypair in JWK format
 */
export async function exportMasterKeypair(keypair: MasterKeypair): Promise<{
  privateKey: JsonWebKey;
  publicKey: JsonWebKey;
}> {
  const [privateJwk, publicJwk] = await Promise.all([
    crypto.subtle.exportKey('jwk', keypair.privateKey),
    crypto.subtle.exportKey('jwk', keypair.publicKey)
  ]);

  return {
    privateKey: privateJwk,
    publicKey: publicJwk
  };
}

/**
 * Import master keypair from JWK format
 *
 * @param jwks - Exported keypair in JWK format
 * @returns Master keypair
 */
export async function importMasterKeypair(jwks: {
  privateKey: JsonWebKey;
  publicKey: JsonWebKey;
}): Promise<MasterKeypair> {
  const [privateKey, publicKey] = await Promise.all([
    crypto.subtle.importKey(
      'jwk',
      jwks.privateKey,
      { name: 'ECDH', namedCurve: EC_CURVE },
      true,
      ['deriveKey', 'deriveBits']
    ),
    crypto.subtle.importKey(
      'jwk',
      jwks.publicKey,
      { name: 'ECDH', namedCurve: EC_CURVE },
      true,
      []
    )
  ]);

  return { privateKey, publicKey };
}
