import { EncryptedPackage, EncryptedDataRepository, Timestamp, TimeRange } from '../types/index';

export class InMemoryEncryptedRepository implements EncryptedDataRepository {
  private storage: Map<Timestamp, EncryptedPackage>;

  constructor() {
    this.storage = new Map();
  }

  async store(pkg: EncryptedPackage): Promise<void> {
    this.storage.set(pkg.timestamp, pkg);
  }

  async retrieve(timestamp: Timestamp): Promise<EncryptedPackage | null> {
    return this.storage.get(timestamp) ?? null;
  }

  async retrieveRange(range: TimeRange): Promise<EncryptedPackage[]> {
    const packages: EncryptedPackage[] = [];
    for (const [timestamp, pkg] of this.storage) {
      if (timestamp >= range.startTime && timestamp <= range.endTime) {
        packages.push(pkg);
      }
    }
    return packages.sort((a, b) => a.timestamp - b.timestamp);
  }

  async exists(timestamp: Timestamp): Promise<boolean> {
    return this.storage.has(timestamp);
  }

  /**
   * Get number of stored packages
   */
  size(): number {
    return this.storage.size;
  }

  /**
   * Get time range of stored data
   */
  getTimeRange(): TimeRange | null {
    if (this.storage.size === 0) {
      return null;
    }

    const timestamps = Array.from(this.storage.keys()).sort((a, b) => a - b);
    return {
      startTime: timestamps[0],
      endTime: timestamps[timestamps.length - 1]
    };
  }

  /**
   * Clear all stored packages (for testing)
   */
  clear(): void {
    this.storage.clear();
  }
}
