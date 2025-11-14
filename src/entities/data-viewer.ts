/**
 * Data Viewer Entity - Authorized Decryption
 *
 * Decrypts authorized data using time-specific private keys from KeyHolder
 */

import { decryptData } from '../crypto/encryption';
import {
  DataViewerConfig,
  EncryptedPackage,
  EncryptedDataRepository,
  DecryptedData,
  TimeSpecificPrivateKey,
  Timestamp,
  TimeRange,
  AuditLogStorage,
  DecryptionError
} from '../types/index';

/**
 * Data Viewer Entity - Decrypts authorized data
 *
 * Core Responsibilities:
 * - Receive time-specific private keys from KeyHolder
 * - Retrieve encrypted data from repository
 * - Perform authenticated decryption
 * - Manage secure key lifecycle
 *
 * Operational Constraints:
 * - Can only decrypt data for which valid private keys exist
 * - Must respect temporal boundaries defined by available keys
 */
export class DataViewer {
  private viewerId: string;
  private authorizedKeys: Map<Timestamp, TimeSpecificPrivateKey>;
  private auditLog?: AuditLogStorage;

  constructor(config: DataViewerConfig, auditLog?: AuditLogStorage) {
    this.viewerId = config.viewerId;
    this.authorizedKeys = new Map();
    this.auditLog = auditLog;
  }

  /**
   * Load authorized private keys received from key holder
   *
   * @param keys - Map of timestamp to time-specific private keys
   */
  loadAuthorizedKeys(keys: Map<Timestamp, TimeSpecificPrivateKey>): void {
    for (const [timestamp, key] of keys) {
      this.authorizedKeys.set(timestamp, key);
    }
  }

  /**
   * Add a single authorized private key
   *
   * @param timestamp - Timestamp for the key
   * @param key - Time-specific private key
   */
  addAuthorizedKey(timestamp: Timestamp, key: TimeSpecificPrivateKey): void {
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
   * @param pkg - Encrypted package to decrypt
   * @returns Decrypted data
   * @throws {DecryptionError} If decryption key is not available
   */
  async decryptPackage(pkg: EncryptedPackage): Promise<DecryptedData> {
    // Verify we have the private key for this timestamp
    const privateKey = this.authorizedKeys.get(pkg.timestamp);

    if (!privateKey) {
      if (this.auditLog) {
        await this.auditLog.append({
          id: this.generateAuditId(),
          timestamp: Date.now(),
          eventType: 'DECRYPTION_ATTEMPT',
          actor: this.viewerId,
          success: false,
          details: {
            timestamp: pkg.timestamp,
            reason: 'No authorized key for timestamp'
          }
        });
      }

      throw new DecryptionError(
        `No authorized key available for timestamp ${pkg.timestamp}`
      );
    }

    try {
      // Decrypt using time-specific private key
      const decryptedData = await decryptData(pkg, privateKey);

      // Log successful decryption
      if (this.auditLog) {
        await this.auditLog.append({
          id: this.generateAuditId(),
          timestamp: Date.now(),
          eventType: 'DECRYPTION_ATTEMPT',
          actor: this.viewerId,
          success: true,
          details: {
            timestamp: pkg.timestamp,
            dataSize: decryptedData.length
          }
        });
      }

      return {
        timestamp: pkg.timestamp,
        data: decryptedData,
        metadata: pkg.metadata
      };
    } catch (error) {
      if (this.auditLog) {
        await this.auditLog.append({
          id: this.generateAuditId(),
          timestamp: Date.now(),
          eventType: 'DECRYPTION_ATTEMPT',
          actor: this.viewerId,
          success: false,
          details: {
            timestamp: pkg.timestamp,
            error: error instanceof Error ? error.message : String(error)
          }
        });
      }

      throw error;
    }
  }

  /**
   * Decrypt data from repository for specific timestamp
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
   * Decrypt multiple packages from repository within time range
   *
   * @param repository - Encrypted data repository
   * @param range - Time range to decrypt
   * @returns Array of decrypted data (only successfully decrypted items)
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
        // Skip packages we can't decrypt (logged in decryptPackage)
        continue;
      }
    }

    return decrypted;
  }

  /**
   * Clear all authorized keys (for security when done)
   */
  clearAllKeys(): void {
    this.authorizedKeys.clear();
  }

  /**
   * Clear keys for specific time range
   *
   * @param range - Time range of keys to clear
   * @returns Number of keys cleared
   */
  clearKeysInRange(range: TimeRange): number {
    let count = 0;

    for (const timestamp of this.authorizedKeys.keys()) {
      if (timestamp >= range.startTime && timestamp <= range.endTime) {
        this.authorizedKeys.delete(timestamp);
        count++;
      }
    }

    return count;
  }

  /**
   * Get viewer ID
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

  /**
   * Generate unique audit entry ID
   */
  private generateAuditId(): string {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2, 15);
    return `audit-${timestamp}-${random}`;
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
