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
}
