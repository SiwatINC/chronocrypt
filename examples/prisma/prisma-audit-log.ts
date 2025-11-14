/**
 * Example Prisma Implementation: Audit Log Storage
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
import type { AuditLogEntry, AuditLogStorage, TimeRange } from '@siwats/chronocrypt';

/**
 * Prisma-based audit log storage
 *
 * Supports both PostgreSQL and SQLite through Prisma
 * Provides tamper-evident, append-only audit logging
 */
export class PrismaAuditLog implements AuditLogStorage {
  constructor(private prisma: PrismaClient) {}

  /**
   * Append a new entry to the audit log
   */
  async append(entry: AuditLogEntry): Promise<void> {
    await this.prisma.auditLogEntry.create({
      data: {
        entryId: entry.id,
        timestamp: BigInt(entry.timestamp),
        eventType: entry.eventType,
        actor: entry.actor,
        target: entry.target || null,
        success: entry.success,
        rangeStartTime: entry.timeRange ? BigInt(entry.timeRange.startTime) : null,
        rangeEndTime: entry.timeRange ? BigInt(entry.timeRange.endTime) : null,
        details: entry.details || null
      }
    });
  }

  /**
   * Retrieve audit log entries within a time range
   */
  async retrieve(range: TimeRange): Promise<AuditLogEntry[]> {
    const records = await this.prisma.auditLogEntry.findMany({
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

    return records.map(record => this.recordToEntry(record));
  }

  /**
   * Retrieve audit log entries by event type
   */
  async retrieveByEventType(
    eventType: AuditLogEntry['eventType']
  ): Promise<AuditLogEntry[]> {
    const records = await this.prisma.auditLogEntry.findMany({
      where: {
        eventType
      },
      orderBy: {
        timestamp: 'asc'
      }
    });

    return records.map(record => this.recordToEntry(record));
  }

  /**
   * Retrieve audit log entries by actor
   */
  async retrieveByActor(actor: string): Promise<AuditLogEntry[]> {
    const records = await this.prisma.auditLogEntry.findMany({
      where: {
        actor
      },
      orderBy: {
        timestamp: 'asc'
      }
    });

    return records.map(record => this.recordToEntry(record));
  }

  /**
   * Get all audit log entries
   */
  async getAll(): Promise<AuditLogEntry[]> {
    const records = await this.prisma.auditLogEntry.findMany({
      orderBy: {
        timestamp: 'asc'
      }
    });

    return records.map(record => this.recordToEntry(record));
  }

  /**
   * Get the total number of entries
   */
  async size(): Promise<number> {
    return await this.prisma.auditLogEntry.count();
  }

  /**
   * Get statistics about audit log entries
   */
  async getStatistics(): Promise<{
    totalEntries: number;
    entriesByType: Record<string, number>;
    entriesByActor: Record<string, number>;
    successRate: number;
  }> {
    const [total, byType, byActor, successCount] = await Promise.all([
      this.prisma.auditLogEntry.count(),
      this.prisma.auditLogEntry.groupBy({
        by: ['eventType'],
        _count: true
      }),
      this.prisma.auditLogEntry.groupBy({
        by: ['actor'],
        _count: true
      }),
      this.prisma.auditLogEntry.count({
        where: { success: true }
      })
    ]);

    const entriesByType: Record<string, number> = {};
    for (const item of byType) {
      entriesByType[item.eventType] = item._count;
    }

    const entriesByActor: Record<string, number> = {};
    for (const item of byActor) {
      entriesByActor[item.actor] = item._count;
    }

    return {
      totalEntries: total,
      entriesByType,
      entriesByActor,
      successRate: total > 0 ? successCount / total : 0
    };
  }

  /**
   * Delete audit log entries older than a specific timestamp
   * Use with extreme caution - may violate audit requirements!
   */
  async deleteOlderThan(timestamp: number): Promise<number> {
    const result = await this.prisma.auditLogEntry.deleteMany({
      where: {
        timestamp: {
          lt: BigInt(timestamp)
        }
      }
    });

    return result.count;
  }

  /**
   * Clear all audit log entries (use with extreme caution!)
   * In production, this should likely be disabled or require special authorization
   */
  async clear(): Promise<void> {
    await this.prisma.auditLogEntry.deleteMany();
  }

  /**
   * Get entries by target entity
   */
  async retrieveByTarget(target: string): Promise<AuditLogEntry[]> {
    const records = await this.prisma.auditLogEntry.findMany({
      where: {
        target
      },
      orderBy: {
        timestamp: 'asc'
      }
    });

    return records.map(record => this.recordToEntry(record));
  }

  /**
   * Get failed operations for security monitoring
   */
  async getFailedOperations(limit?: number): Promise<AuditLogEntry[]> {
    const records = await this.prisma.auditLogEntry.findMany({
      where: {
        success: false
      },
      orderBy: {
        timestamp: 'desc'
      },
      take: limit
    });

    return records.map(record => this.recordToEntry(record));
  }

  /**
   * Convert Prisma record to AuditLogEntry
   */
  private recordToEntry(record: any): AuditLogEntry {
    return {
      id: record.entryId,
      timestamp: Number(record.timestamp),
      eventType: record.eventType as AuditLogEntry['eventType'],
      actor: record.actor,
      target: record.target || undefined,
      success: record.success,
      timeRange:
        record.rangeStartTime && record.rangeEndTime
          ? {
              startTime: Number(record.rangeStartTime),
              endTime: Number(record.rangeEndTime)
            }
          : undefined,
      details: record.details ? (record.details as Record<string, unknown>) : undefined
    };
  }
}

/**
 * Helper function to create a Prisma-based audit log
 */
export function createPrismaAuditLog(prisma: PrismaClient): PrismaAuditLog {
  return new PrismaAuditLog(prisma);
}
