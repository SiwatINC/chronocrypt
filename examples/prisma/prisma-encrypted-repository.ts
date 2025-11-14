/**
 * Example Prisma Implementation: Encrypted Data Repository
 *
 * This is a reference implementation showing how to use Prisma with ChronoCrypt.
 * Copy this file to your project and customize as needed.
 *
 * Setup:
 * 1. Install dependencies: bun add @prisma/client prisma
 * 2. Copy schema.prisma to your project's prisma directory
 * 3. Run: bunx prisma generate
 * 4. Run migrations: bunx prisma migrate dev
 */

import type { PrismaClient } from '@prisma/client';
import type {
  EncryptedPackage,
  EncryptedDataRepository,
  Timestamp,
  TimeRange
} from '@siwats/chronocrypt';

/**
 * Prisma-based encrypted data repository
 *
 * Supports both PostgreSQL and SQLite through Prisma
 */
export class PrismaEncryptedRepository implements EncryptedDataRepository {
  constructor(private prisma: PrismaClient) {}

  /**
   * Store an encrypted data package
   */
  async store(pkg: EncryptedPackage): Promise<void> {
    await this.prisma.encryptedPackage.upsert({
      where: {
        timestamp: BigInt(pkg.timestamp)
      },
      create: {
        timestamp: BigInt(pkg.timestamp),
        encryptedData: Buffer.from(pkg.encryptedData),
        iv: Buffer.from(pkg.iv),
        authTag: Buffer.from(pkg.authTag),
        metadata: pkg.metadata || null
      },
      update: {
        encryptedData: Buffer.from(pkg.encryptedData),
        iv: Buffer.from(pkg.iv),
        authTag: Buffer.from(pkg.authTag),
        metadata: pkg.metadata || null
      }
    });
  }

  /**
   * Retrieve encrypted data for a specific timestamp
   */
  async retrieve(timestamp: Timestamp): Promise<EncryptedPackage | null> {
    const record = await this.prisma.encryptedPackage.findUnique({
      where: {
        timestamp: BigInt(timestamp)
      }
    });

    if (!record) {
      return null;
    }

    return this.recordToPackage(record);
  }

  /**
   * Retrieve all encrypted data packages within a time range
   */
  async retrieveRange(range: TimeRange): Promise<EncryptedPackage[]> {
    const records = await this.prisma.encryptedPackage.findMany({
      where: {
        timestamp: {
          gte: BigInt(range.startTime),
          lte: BigInt(range.endTime)
        }
      },
      orderBy: {
        timestamp: 'asc'
      }
    });

    return records.map(record => this.recordToPackage(record));
  }

  /**
   * Check if data exists for a specific timestamp
   */
  async exists(timestamp: Timestamp): Promise<boolean> {
    const count = await this.prisma.encryptedPackage.count({
      where: {
        timestamp: BigInt(timestamp)
      }
    });

    return count > 0;
  }

  /**
   * Get the total number of stored packages
   */
  async size(): Promise<number> {
    return await this.prisma.encryptedPackage.count();
  }

  /**
   * Get all timestamps in the repository
   */
  async getAllTimestamps(): Promise<Timestamp[]> {
    const records = await this.prisma.encryptedPackage.findMany({
      select: {
        timestamp: true
      },
      orderBy: {
        timestamp: 'asc'
      }
    });

    return records.map(r => Number(r.timestamp));
  }

  /**
   * Get the time range covered by stored data
   */
  async getTimeRange(): Promise<TimeRange | null> {
    const [first, last] = await Promise.all([
      this.prisma.encryptedPackage.findFirst({
        orderBy: { timestamp: 'asc' },
        select: { timestamp: true }
      }),
      this.prisma.encryptedPackage.findFirst({
        orderBy: { timestamp: 'desc' },
        select: { timestamp: true }
      })
    ]);

    if (!first || !last) {
      return null;
    }

    return {
      startTime: Number(first.timestamp),
      endTime: Number(last.timestamp)
    };
  }

  /**
   * Delete all stored packages (use with caution!)
   */
  async clear(): Promise<void> {
    await this.prisma.encryptedPackage.deleteMany();
  }

  /**
   * Delete packages older than a specific timestamp
   * Useful for data retention policies
   */
  async deleteOlderThan(timestamp: Timestamp): Promise<number> {
    const result = await this.prisma.encryptedPackage.deleteMany({
      where: {
        timestamp: {
          lt: BigInt(timestamp)
        }
      }
    });

    return result.count;
  }

  /**
   * Convert Prisma record to EncryptedPackage
   */
  private recordToPackage(record: any): EncryptedPackage {
    return {
      timestamp: Number(record.timestamp),
      encryptedData: new Uint8Array(record.encryptedData),
      iv: new Uint8Array(record.iv),
      authTag: new Uint8Array(record.authTag),
      metadata: record.metadata ? (record.metadata as Record<string, unknown>) : undefined
    };
  }
}

/**
 * Helper function to create a Prisma-based repository
 */
export function createPrismaRepository(prisma: PrismaClient): PrismaEncryptedRepository {
  return new PrismaEncryptedRepository(prisma);
}
