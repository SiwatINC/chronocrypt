import { AuditLogEntry, AuditLogStorage, TimeRange } from '../types/index';

export class InMemoryAuditLog implements AuditLogStorage {
  private entries: AuditLogEntry[];

  constructor() {
    this.entries = [];
  }

  async append(entry: AuditLogEntry): Promise<void> {
    this.entries.push(entry);
  }

  async retrieve(range: TimeRange): Promise<AuditLogEntry[]> {
    return this.entries.filter(
      entry => entry.timestamp >= range.startTime && entry.timestamp <= range.endTime
    );
  }

  async retrieveByEventType(eventType: AuditLogEntry['eventType']): Promise<AuditLogEntry[]> {
    return this.entries.filter(entry => entry.eventType === eventType);
  }

  async retrieveByActor(actor: string): Promise<AuditLogEntry[]> {
    return this.entries.filter(entry => entry.actor === actor);
  }

  /**
   * Get all audit log entries
   */
  async getAll(): Promise<AuditLogEntry[]> {
    return [...this.entries];
  }

  /**
   * Get statistics about audit log
   */
  async getStatistics(): Promise<{
    totalEntries: number;
    entriesByType: Record<string, number>;
    entriesByActor: Record<string, number>;
    successRate: number;
  }> {
    const entriesByType: Record<string, number> = {};
    const entriesByActor: Record<string, number> = {};
    let successCount = 0;

    for (const entry of this.entries) {
      // Count by type
      entriesByType[entry.eventType] = (entriesByType[entry.eventType] || 0) + 1;

      // Count by actor
      entriesByActor[entry.actor] = (entriesByActor[entry.actor] || 0) + 1;

      // Count successes
      if (entry.success) {
        successCount++;
      }
    }

    return {
      totalEntries: this.entries.length,
      entriesByType,
      entriesByActor,
      successRate: this.entries.length > 0 ? successCount / this.entries.length : 0
    };
  }

  /**
   * Get number of entries
   */
  size(): number {
    return this.entries.length;
  }

  /**
   * Clear all entries (for testing)
   */
  clear(): void {
    this.entries = [];
  }
}

/**
 * Helper to create audit entry with generated ID
 */
export function createAuditEntry(
  eventType: AuditLogEntry['eventType'],
  actor: string,
  success: boolean,
  options?: {
    target?: string;
    timeRange?: TimeRange;
    details?: Record<string, unknown>;
  }
): AuditLogEntry {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 15);

  return {
    id: `audit-${timestamp}-${random}`,
    timestamp,
    eventType,
    actor,
    target: options?.target,
    timeRange: options?.timeRange,
    success,
    details: options?.details
  };
}
