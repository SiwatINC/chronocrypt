/**
 * Data Source Entity
 *
 * Encrypts temporal data streams using time-derived cryptographic keys
 */

import { deriveTimeSpecificKey, destroyKey } from '../crypto/key-derivation';
import { encryptData } from '../crypto/encryption';
import {
  DataSourceConfig,
  EncryptedPackage,
  EncryptedDataRepository,
  Timestamp,
  MasterKey
} from '../types';

/**
 * Data Source Entity - Primary Function: Encrypts temporal data streams
 *
 * Core Responsibilities:
 * - Generate time-specific encryption keys from master cryptographic material
 * - Apply authenticated encryption to data payloads with temporal metadata
 * - Store encrypted data with associated timestamp and authentication information
 * - Maintain encrypted data repository accessible to authorized data consumers
 *
 * Operational Constraints:
 * - Must not retain decryption capabilities for stored data
 * - Must implement cryptographically secure key derivation functions
 * - Must associate each encrypted payload with precise temporal identifiers
 */
export class DataSource {
  private masterKey: MasterKey;
  private repository: EncryptedDataRepository;
  private timestampGenerator: () => Timestamp;

  constructor(config: DataSourceConfig, repository: EncryptedDataRepository) {
    this.masterKey = config.masterKey;
    this.repository = repository;
    this.timestampGenerator = config.timestampGenerator || (() => Date.now());
  }

  /**
   * Encrypt data with current timestamp
   *
   * Workflow:
   * 1. Generate timestamp for data payload
   * 2. Derive time-specific encryption key from master key and timestamp
   * 3. Apply authenticated encryption to data payload using derived key
   * 4. Store encrypted data with timestamp, IV, and authentication information
   * 5. Securely destroy derived encryption key from memory
   *
   * @param data - Data to encrypt
   * @param metadata - Optional metadata to associate with encrypted data
   * @returns Encrypted package
   */
  async encryptData(
    data: Uint8Array,
    metadata?: Record<string, unknown>
  ): Promise<EncryptedPackage> {
    // Step 1: Generate timestamp
    const timestamp = this.timestampGenerator();

    // Step 2: Derive time-specific encryption key
    const timeSpecificKey = await deriveTimeSpecificKey(this.masterKey, timestamp);

    try {
      // Step 3: Apply authenticated encryption
      const encryptedPackage = await encryptData(data, timeSpecificKey, timestamp, metadata);

      // Step 4: Store encrypted data
      await this.repository.store(encryptedPackage);

      return encryptedPackage;
    } finally {
      // Step 5: Securely destroy derived key
      destroyKey(timeSpecificKey);
    }
  }

  /**
   * Encrypt data with explicit timestamp (for batch operations or specific time periods)
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
    // Derive time-specific encryption key
    const timeSpecificKey = await deriveTimeSpecificKey(this.masterKey, timestamp);

    try {
      // Apply authenticated encryption
      const encryptedPackage = await encryptData(data, timeSpecificKey, timestamp, metadata);

      // Store encrypted data
      await this.repository.store(encryptedPackage);

      return encryptedPackage;
    } finally {
      // Securely destroy derived key
      destroyKey(timeSpecificKey);
    }
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
   *
   * This allows external entities to retrieve encrypted data without
   * having access to decryption capabilities
   */
  getRepository(): EncryptedDataRepository {
    return this.repository;
  }

  /**
   * Securely destroy this data source and clean up sensitive material
   *
   * Note: This does not destroy the encrypted data in the repository,
   * only the master key held by this data source instance
   */
  destroy(): void {
    destroyKey(this.masterKey);
  }
}

/**
 * Helper function to create a data source with a new master key
 *
 * @param repository - Encrypted data repository
 * @param timestampGenerator - Optional custom timestamp generator
 * @returns New data source instance
 */
export function createDataSource(
  repository: EncryptedDataRepository,
  masterKey: MasterKey,
  timestampGenerator?: () => Timestamp
): DataSource {
  return new DataSource(
    {
      masterKey,
      timestampGenerator
    },
    repository
  );
}
