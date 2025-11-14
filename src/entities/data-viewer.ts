/**
 * Data Viewer Entity
 *
 * Decrypts authorized data using time-specific keys received from key holder entities
 */

import { decryptData, verifyAuthentication } from '~/crypto/encryption';
import { destroyKey } from '~/crypto/key-derivation';
import { createAuditEntry } from '~/storage/audit-log';
import {
  DataViewerConfig,
  EncryptedPackage,
  EncryptedDataRepository,
  DecryptedData,
  TimeSpecificKey,
  Timestamp,
  TimeRange,
  AuditLogStorage,
  DecryptionError,
  AuthenticationError
} from '~/types';

/**
 * Data Viewer Entity - Primary Function: Decrypts authorized data
 *
 * Core Responsibilities:
 * - Receive and securely store time-specific decryption keys
 * - Retrieve encrypted data from data source repositories
 * - Perform authenticated decryption of authorized temporal data
 * - Implement secure key lifecycle management including key destruction
 *
 * Operational Constraints:
 * - Must only attempt decryption of data for which valid keys exist
 * - Must verify data authenticity before processing decrypted content
 * - Must implement secure key storage and destruction procedures
 * - Must respect temporal boundaries defined by available decryption keys
 */
export class DataViewer {
  private viewerId: string;
  private authorizedKeys: Map<Timestamp, TimeSpecificKey>;
  private auditLog?: AuditLogStorage;

  constructor(config: DataViewerConfig, auditLog?: AuditLogStorage) {
    this.viewerId = config.viewerId;
    this.authorizedKeys = new Map();
    this.auditLog = auditLog;
  }

  /**
   * Load authorized keys received from key holder
   *
   * @param keys - Map of timestamp to time-specific keys
   */
  loadAuthorizedKeys(keys: Map<Timestamp, TimeSpecificKey>): void {
    for (const [timestamp, key] of keys) {
      this.authorizedKeys.set(timestamp, key);
    }
  }

  /**
   * Add a single authorized key
   *
   * @param timestamp - Timestamp for the key
   * @param key - Time-specific decryption key
   */
  addAuthorizedKey(timestamp: Timestamp, key: TimeSpecificKey): void {
    this.authorizedKeys.set(timestamp, key);
  }

  /**
   * Check if viewer has authorization for a specific timestamp
   *
   * @param timestamp - Timestamp to check
   * @returns True if authorized key exists
   */
  hasAuthorizationFor(timestamp: Timestamp): boolean {
    return this.authorizedKeys.has(timestamp);
  }

  /**
   * Get all authorized timestamps
   *
   * @returns Array of timestamps for which keys are available
   */
  getAuthorizedTimestamps(): Timestamp[] {
    return Array.from(this.authorizedKeys.keys()).sort((a, b) => a - b);
  }

  /**
   * Decrypt a single encrypted package
   *
   * Workflow:
   * 1. Key Validation: Verify possession of valid decryption key for target timestamp
   * 2. Data Retrieval: Obtain encrypted data payload from data source repository
   * 3. Authentication Verification: Validate data integrity using authentication information
   * 4. Decryption: Apply decryption operation using time-specific key
   *
   * @param pkg - Encrypted package to decrypt
   * @returns Decrypted data
   * @throws {DecryptionError} If decryption key is not available
   * @throws {AuthenticationError} If authentication verification fails
   */
  async decryptPackage(pkg: EncryptedPackage): Promise<DecryptedData> {
    // Step 1: Verify we have the key
    const key = this.authorizedKeys.get(pkg.timestamp);

    if (!key) {
      if (this.auditLog) {
        await this.auditLog.append(
          createAuditEntry('DECRYPTION_ATTEMPT', this.viewerId, false, {
            details: {
              timestamp: pkg.timestamp,
              reason: 'No authorized key for timestamp'
            }
          })
        );
      }

      throw new DecryptionError(
        `No authorized key available for timestamp ${pkg.timestamp}`
      );
    }

    try {
      // Step 2 & 3: Decrypt (includes authentication verification)
      const decryptedData = await decryptData(pkg, key);

      // Log successful decryption
      if (this.auditLog) {
        await this.auditLog.append(
          createAuditEntry('DECRYPTION_ATTEMPT', this.viewerId, true, {
            details: {
              timestamp: pkg.timestamp,
              dataSize: decryptedData.length
            }
          })
        );
      }

      return {
        timestamp: pkg.timestamp,
        data: decryptedData,
        metadata: pkg.metadata
      };
    } catch (error) {
      if (this.auditLog) {
        await this.auditLog.append(
          createAuditEntry('DECRYPTION_ATTEMPT', this.viewerId, false, {
            details: {
              timestamp: pkg.timestamp,
              error: error instanceof Error ? error.message : String(error)
            }
          })
        );
      }

      throw error;
    }
  }

  /**
   * Decrypt data from a repository for a specific timestamp
   *
   * @param repository - Encrypted data repository
   * @param timestamp - Timestamp to decrypt
   * @returns Decrypted data or null if not found
   */
  async decryptFromRepository(
    repository: EncryptedDataRepository,
    timestamp: Timestamp
  ): Promise<DecryptedData | null> {
    const pkg = await repository.retrieve(timestamp);

    if (!pkg) {
      return null;
    }

    return await this.decryptPackage(pkg);
  }

  /**
   * Decrypt multiple packages from a repository within a time range
   *
   * @param repository - Encrypted data repository
   * @param range - Time range to decrypt
   * @returns Array of decrypted data (only includes successfully decrypted items)
   */
  async decryptRange(
    repository: EncryptedDataRepository,
    range: TimeRange
  ): Promise<DecryptedData[]> {
    const packages = await repository.retrieveRange(range);
    const decrypted: DecryptedData[] = [];

    for (const pkg of packages) {
      try {
        const data = await this.decryptPackage(pkg);
        decrypted.push(data);
      } catch (error) {
        // Skip packages we can't decrypt (no key or authentication failed)
        // Errors are already logged in decryptPackage
        continue;
      }
    }

    return decrypted;
  }

  /**
   * Verify authentication of encrypted package without decrypting
   *
   * Useful for checking data integrity without accessing the content
   *
   * @param pkg - Encrypted package to verify
   * @returns True if authentication is valid
   */
  async verifyPackageAuthentication(pkg: EncryptedPackage): Promise<boolean> {
    const key = this.authorizedKeys.get(pkg.timestamp);

    if (!key) {
      return false;
    }

    return await verifyAuthentication(pkg, key);
  }

  /**
   * Destroy a specific authorized key
   *
   * @param timestamp - Timestamp of key to destroy
   * @returns True if key existed and was destroyed
   */
  destroyKey(timestamp: Timestamp): boolean {
    const key = this.authorizedKeys.get(timestamp);

    if (!key) {
      return false;
    }

    destroyKey(key);
    this.authorizedKeys.delete(timestamp);
    return true;
  }

  /**
   * Destroy all authorized keys
   *
   * Should be called when viewer is done processing data
   */
  destroyAllKeys(): void {
    for (const key of this.authorizedKeys.values()) {
      destroyKey(key);
    }

    this.authorizedKeys.clear();
  }

  /**
   * Destroy keys for a specific time range
   *
   * @param range - Time range of keys to destroy
   * @returns Number of keys destroyed
   */
  destroyKeysInRange(range: TimeRange): number {
    let count = 0;

    for (const [timestamp, key] of this.authorizedKeys) {
      if (timestamp >= range.startTime && timestamp <= range.endTime) {
        destroyKey(key);
        this.authorizedKeys.delete(timestamp);
        count++;
      }
    }

    return count;
  }

  /**
   * Get the viewer ID
   */
  getViewerId(): string {
    return this.viewerId;
  }

  /**
   * Get statistics about authorized keys
   */
  getKeyStatistics(): {
    totalKeys: number;
    timestamps: Timestamp[];
    timeRange: TimeRange | null;
  } {
    const timestamps = this.getAuthorizedTimestamps();

    return {
      totalKeys: this.authorizedKeys.size,
      timestamps,
      timeRange:
        timestamps.length > 0
          ? {
              startTime: timestamps[0],
              endTime: timestamps[timestamps.length - 1]
            }
          : null
    };
  }
}

/**
 * Helper function to create a data viewer
 *
 * @param viewerId - Identifier for this viewer
 * @param auditLog - Optional audit log for tracking decryption attempts
 * @returns New data viewer instance
 */
export function createDataViewer(
  viewerId: string,
  auditLog?: AuditLogStorage
): DataViewer {
  return new DataViewer({ viewerId }, auditLog);
}
