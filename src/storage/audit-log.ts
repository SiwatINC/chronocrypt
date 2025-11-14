/**
 * Audit Log Storage Implementation
 *
 * Stores audit log entries for access control and key management operations
 */

import { AuditLogEntry, AuditLogStorage, TimeRange, Timestamp } from '~/types';

/**
 * In-memory implementation of audit log storage
 *
 * Note: This is a reference implementation. For production use,
 * implement persistent, tamper-evident storage (append-only database, blockchain, etc.)
 */
export class InMemoryAuditLog implements AuditLogStorage {
  private entries: AuditLogEntry[];

  constructor() {
    this.entries = [];
  }

  /**
   * Append a new entry to the audit log
   */
  async append(entry: AuditLogEntry): Promise<void> {
    // Ensure entries are stored in chronological order
    this.entries.push(entry);
  }

  /**
   * Retrieve audit log entries within a time range
   */
  async retrieve(range: TimeRange): Promise<AuditLogEntry[]> {
    return this.entries.filter(
      entry => entry.timestamp >= range.startTime && entry.timestamp <= range.endTime
    );
  }

  /**
   * Retrieve audit log entries by event type
   */
  async retrieveByEventType(eventType: AuditLogEntry['eventType']): Promise<AuditLogEntry[]> {
    return this.entries.filter(entry => entry.eventType === eventType);
  }

  /**
   * Retrieve audit log entries by actor
   */
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
   * Get the total number of entries
   */
  size(): number {
    return this.entries.length;
  }

  /**
   * Clear all audit log entries (use with extreme caution!)
   */
  clear(): void {
    this.entries = [];
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
}

/**
 * File-based append-only audit log implementation
 *
 * Stores audit log entries in a JSON Lines format for durability
 */
export class FileBasedAuditLog implements AuditLogStorage {
  private filePath: string;
  private cache: AuditLogEntry[];
  private cacheLoaded: boolean;

  constructor(filePath: string) {
    this.filePath = filePath;
    this.cache = [];
    this.cacheLoaded = false;
  }

  /**
   * Load cache from file if not already loaded
   */
  private async ensureCacheLoaded(): Promise<void> {
    if (this.cacheLoaded) {
      return;
    }

    try {
      const file = Bun.file(this.filePath);
      if (await file.exists()) {
        const content = await file.text();
        const lines = content.trim().split('\n').filter(line => line.length > 0);
        this.cache = lines.map(line => JSON.parse(line));
      }
      this.cacheLoaded = true;
    } catch (error) {
      // If file doesn't exist or is empty, start with empty cache
      this.cache = [];
      this.cacheLoaded = true;
    }
  }

  /**
   * Append a new entry to the audit log
   */
  async append(entry: AuditLogEntry): Promise<void> {
    await this.ensureCacheLoaded();

    // Append to file
    const line = JSON.stringify(entry) + '\n';
    const file = Bun.file(this.filePath);

    if (await file.exists()) {
      const existingContent = await file.text();
      await Bun.write(this.filePath, existingContent + line);
    } else {
      await Bun.write(this.filePath, line);
    }

    // Update cache
    this.cache.push(entry);
  }

  async retrieve(range: TimeRange): Promise<AuditLogEntry[]> {
    await this.ensureCacheLoaded();
    return this.cache.filter(
      entry => entry.timestamp >= range.startTime && entry.timestamp <= range.endTime
    );
  }

  async retrieveByEventType(eventType: AuditLogEntry['eventType']): Promise<AuditLogEntry[]> {
    await this.ensureCacheLoaded();
    return this.cache.filter(entry => entry.eventType === eventType);
  }

  async retrieveByActor(actor: string): Promise<AuditLogEntry[]> {
    await this.ensureCacheLoaded();
    return this.cache.filter(entry => entry.actor === actor);
  }
}

/**
 * Generate a unique audit entry ID
 */
export function generateAuditEntryId(): string {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 15);
  return `audit-${timestamp}-${random}`;
}

/**
 * Create an audit log entry
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
  return {
    id: generateAuditEntryId(),
    timestamp: Date.now(),
    eventType,
    actor,
    success,
    target: options?.target,
    timeRange: options?.timeRange,
    details: options?.details
  };
}
