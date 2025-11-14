/**
 * Data Source Entity - Asymmetric Encryption Only
 *
 * SECURITY MODEL:
 * - DataSource is in UNTRUSTED zone (could be compromised)
 * - Has ONLY public key - can encrypt but CANNOT decrypt
 * - Never sees or stores private/master key
 * - If DataSource is compromised, attacker cannot decrypt any data
 */

import { encryptData } from '../crypto/encryption';
import {
  DataSourceConfig,
  EncryptedPackage,
  EncryptedDataRepository,
  Timestamp,
  ExportedPublicKey
} from '../types/index';

/**
 * Data Source Entity - Encrypts temporal data streams
 *
 * Core Responsibilities:
 * - Encrypt data using master PUBLIC key only
 * - Store encrypted data with temporal metadata
 * - CANNOT decrypt any data (no private key access)
 *
 * Security Guarantees:
 * - Compromise of DataSource does NOT expose decryption capability
 * - Zero-knowledge: DataSource never sees plaintext after encryption
 * - Forward secrecy: Each timestamp uses derived public key
 */
export class DataSource {
  private publicKey: ExportedPublicKey;
  private repository: EncryptedDataRepository;
  private timestampGenerator: () => Timestamp;

  constructor(config: DataSourceConfig, repository: EncryptedDataRepository) {
    this.publicKey = config.publicKey; // PUBLIC KEY ONLY - cannot decrypt!
    this.repository = repository;
    this.timestampGenerator = config.timestampGenerator || (() => Date.now());
  }

  /**
   * Encrypt data with current timestamp
   *
   * Workflow:
   * 1. Generate timestamp for data payload
   * 2. Encrypt using public key + timestamp (hybrid ECIES + AES)
   * 3. Store encrypted data in repository
   *
   * DataSource CANNOT decrypt this data - only has public key
   *
   * @param data - Data to encrypt
   * @param metadata - Optional metadata to associate with encrypted data
   * @returns Encrypted package
   */
  async encryptData(
    data: Uint8Array,
    metadata?: Record<string, unknown>
  ): Promise<EncryptedPackage> {
    const timestamp = this.timestampGenerator();
    const encrypted = await encryptData(data, this.publicKey, timestamp, metadata);
    await this.repository.store(encrypted);
    return encrypted;
  }

  /**
   * Encrypt data with explicit timestamp
   *
   * @param data - Data to encrypt
   * @param timestamp - Explicit timestamp to use
   * @param metadata - Optional metadata
   * @returns Encrypted package
   */
  async encryptDataAtTimestamp(
    data: Uint8Array,
    timestamp: Timestamp,
    metadata?: Record<string, unknown>
  ): Promise<EncryptedPackage> {
    const encrypted = await encryptData(data, this.publicKey, timestamp, metadata);
    await this.repository.store(encrypted);
    return encrypted;
  }

  /**
   * Encrypt multiple data items in batch
   *
   * @param items - Array of data items with optional timestamps
   * @returns Array of encrypted packages
   */
  async encryptBatch(
    items: Array<{
      data: Uint8Array;
      timestamp?: Timestamp;
      metadata?: Record<string, unknown>;
    }>
  ): Promise<EncryptedPackage[]> {
    const results: EncryptedPackage[] = [];

    for (const item of items) {
      const pkg = item.timestamp
        ? await this.encryptDataAtTimestamp(item.data, item.timestamp, item.metadata)
        : await this.encryptData(item.data, item.metadata);

      results.push(pkg);
    }

    return results;
  }

  /**
   * Check if encrypted data exists for a specific timestamp
   *
   * @param timestamp - Timestamp to check
   * @returns True if data exists
   */
  async hasDataAtTimestamp(timestamp: Timestamp): Promise<boolean> {
    return await this.repository.exists(timestamp);
  }

  /**
   * Get the encrypted data repository (read-only access)
   */
  getRepository(): EncryptedDataRepository {
    return this.repository;
  }

  /**
   * Get the public key being used for encryption
   *
   * @returns Public key in JWK format
   */
  getPublicKey(): ExportedPublicKey {
    return this.publicKey;
  }
}

/**
 * Helper function to create a data source
 *
 * @param publicKey - Master public key (from KeyHolder)
 * @param repository - Encrypted data repository
 * @param timestampGenerator - Optional custom timestamp generator
 * @returns New data source instance
 */
export function createDataSource(
  publicKey: ExportedPublicKey,
  repository: EncryptedDataRepository,
  timestampGenerator?: () => Timestamp
): DataSource {
  return new DataSource(
    {
      publicKey,
      timestampGenerator
    },
    repository
  );
}
