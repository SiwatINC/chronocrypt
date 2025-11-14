/**
 * Encrypted Data Repository Implementation
 *
 * In-memory storage for encrypted data packages with timestamp-based indexing
 */

import {
  EncryptedPackage,
  EncryptedDataRepository,
  Timestamp,
  TimeRange
} from '~/types';

/**
 * In-memory implementation of encrypted data repository
 *
 * Note: This is a reference implementation. For production use,
 * implement persistent storage (database, file system, cloud storage, etc.)
 */
export class InMemoryEncryptedRepository implements EncryptedDataRepository {
  private storage: Map<Timestamp, EncryptedPackage>;

  constructor() {
    this.storage = new Map();
  }

  /**
   * Store an encrypted data package
   */
  async store(pkg: EncryptedPackage): Promise<void> {
    this.storage.set(pkg.timestamp, pkg);
  }

  /**
   * Retrieve encrypted data for a specific timestamp
   */
  async retrieve(timestamp: Timestamp): Promise<EncryptedPackage | null> {
    return this.storage.get(timestamp) ?? null;
  }

  /**
   * Retrieve all encrypted data packages within a time range
   */
  async retrieveRange(range: TimeRange): Promise<EncryptedPackage[]> {
    const packages: EncryptedPackage[] = [];

    for (const [timestamp, pkg] of this.storage) {
      if (timestamp >= range.startTime && timestamp <= range.endTime) {
        packages.push(pkg);
      }
    }

    // Sort by timestamp ascending
    return packages.sort((a, b) => a.timestamp - b.timestamp);
  }

  /**
   * Check if data exists for a specific timestamp
   */
  async exists(timestamp: Timestamp): Promise<boolean> {
    return this.storage.has(timestamp);
  }

  /**
   * Get the total number of stored packages
   */
  size(): number {
    return this.storage.size;
  }

  /**
   * Clear all stored data
   */
  clear(): void {
    this.storage.clear();
  }

  /**
   * Get all timestamps in the repository
   */
  getAllTimestamps(): Timestamp[] {
    return Array.from(this.storage.keys()).sort((a, b) => a - b);
  }

  /**
   * Get the time range covered by stored data
   */
  getTimeRange(): TimeRange | null {
    const timestamps = this.getAllTimestamps();
    if (timestamps.length === 0) {
      return null;
    }
    return {
      startTime: timestamps[0],
      endTime: timestamps[timestamps.length - 1]
    };
  }
}

/**
 * File system-based encrypted data repository
 *
 * Stores encrypted packages as individual files organized by timestamp
 */
export class FileSystemEncryptedRepository implements EncryptedDataRepository {
  private baseDir: string;

  constructor(baseDir: string) {
    this.baseDir = baseDir;
  }

  private getFilePath(timestamp: Timestamp): string {
    // Organize by year/month/day/timestamp for better file system performance
    const date = new Date(timestamp);
    const year = date.getUTCFullYear();
    const month = String(date.getUTCMonth() + 1).padStart(2, '0');
    const day = String(date.getUTCDate()).padStart(2, '0');

    return `${this.baseDir}/${year}/${month}/${day}/${timestamp}.enc`;
  }

  async store(pkg: EncryptedPackage): Promise<void> {
    const filePath = this.getFilePath(pkg.timestamp);

    // Create directory structure
    const dirPath = filePath.substring(0, filePath.lastIndexOf('/'));
    await Bun.write(filePath, JSON.stringify({
      timestamp: pkg.timestamp,
      encryptedData: Array.from(pkg.encryptedData),
      iv: Array.from(pkg.iv),
      authTag: Array.from(pkg.authTag),
      metadata: pkg.metadata
    }));
  }

  async retrieve(timestamp: Timestamp): Promise<EncryptedPackage | null> {
    try {
      const filePath = this.getFilePath(timestamp);
      const file = Bun.file(filePath);

      if (!(await file.exists())) {
        return null;
      }

      const data = await file.json();
      return {
        timestamp: data.timestamp,
        encryptedData: new Uint8Array(data.encryptedData),
        iv: new Uint8Array(data.iv),
        authTag: new Uint8Array(data.authTag),
        metadata: data.metadata
      };
    } catch {
      return null;
    }
  }

  async retrieveRange(range: TimeRange): Promise<EncryptedPackage[]> {
    const packages: EncryptedPackage[] = [];

    // Generate all possible timestamps in range
    // This is a simplified implementation; in production, you'd want to
    // walk the directory structure more efficiently
    for (let ts = range.startTime; ts <= range.endTime; ts += 1000) {
      const pkg = await this.retrieve(ts);
      if (pkg) {
        packages.push(pkg);
      }
    }

    return packages;
  }

  async exists(timestamp: Timestamp): Promise<boolean> {
    const filePath = this.getFilePath(timestamp);
    const file = Bun.file(filePath);
    return await file.exists();
  }
}
