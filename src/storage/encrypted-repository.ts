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
}
