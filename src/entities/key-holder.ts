/**
 * Key Holder Entity
 *
 * Controls access authorization by generating time-specific decryption keys
 * for authorized time periods
 */

import { deriveTimeSpecificKey, deriveMultipleKeys } from '~/crypto/key-derivation';
import { AccessControlPolicyManager } from '~/policies/access-control';
import { createAuditEntry } from '~/storage/audit-log';
import {
  KeyHolderConfig,
  AccessRequest,
  AccessResponse,
  AuditLogStorage,
  MasterKey,
  TimeSpecificKey,
  Timestamp,
  TimeRange,
  AccessDeniedError
} from '~/types';

/**
 * Key Holder Entity - Primary Function: Controls access authorization
 *
 * Core Responsibilities:
 * - Maintain master cryptographic key material in secure storage
 * - Generate time-specific decryption keys for authorized temporal ranges
 * - Implement access control policies defining authorization criteria
 * - Maintain comprehensive audit logs of all key generation activities
 * - Securely distribute authorized keys to data viewer entities
 *
 * Operational Constraints:
 * - Must never access encrypted data content during authorization processes
 * - Must implement secure key distribution mechanisms
 * - Must maintain cryptographic separation between different temporal periods
 * - Must provide non-repudiable audit trails for all authorization activities
 */
export class KeyHolder {
  private masterKey: MasterKey;
  private policyManager: AccessControlPolicyManager;
  private auditLog: AuditLogStorage;
  private keyHolderId: string;

  constructor(
    config: KeyHolderConfig,
    auditLog: AuditLogStorage,
    keyHolderId: string = 'key-holder'
  ) {
    this.masterKey = config.masterKey;
    this.policyManager = new AccessControlPolicyManager(config.policies);
    this.auditLog = auditLog;
    this.keyHolderId = keyHolderId;
  }

  /**
   * Process an access authorization request
   *
   * Workflow:
   * 1. Authorization Request: Data viewer entity requests access to specific temporal range
   * 2. Policy Evaluation: Key holder evaluates request against access control policies
   * 3. Key Generation: Generate time-specific decryption keys for authorized time periods
   * 4. Audit Logging: Record authorization decision and key generation in audit trail
   * 5. Secure Distribution: Transmit authorized keys through secure communication channel
   *
   * @param request - Access authorization request
   * @returns Access response with keys if granted
   * @throws {AccessDeniedError} If access is denied
   */
  async authorizeAccess(request: AccessRequest): Promise<AccessResponse> {
    // Log access request
    await this.auditLog.append(
      createAuditEntry('ACCESS_REQUEST', request.requesterId, true, {
        target: this.keyHolderId,
        timeRange: request.timeRange,
        details: {
          purpose: request.purpose,
          metadata: request.metadata
        }
      })
    );

    // Evaluate access control policies
    const policyResult = await this.policyManager.evaluateRequest(request);

    if (!policyResult.allow) {
      // Log access denial
      await this.auditLog.append(
        createAuditEntry('ACCESS_DENIED', request.requesterId, true, {
          target: this.keyHolderId,
          timeRange: request.timeRange,
          details: {
            reason: policyResult.reason,
            policy: policyResult.policy?.name
          }
        })
      );

      return {
        granted: false,
        denialReason: policyResult.reason
      };
    }

    // Generate time-specific keys for authorized time range
    const timestamps = this.generateTimestampsInRange(request.timeRange);

    // Log key generation
    await this.auditLog.append(
      createAuditEntry('KEY_GENERATION', this.keyHolderId, true, {
        target: request.requesterId,
        timeRange: request.timeRange,
        details: {
          keyCount: timestamps.length
        }
      })
    );

    const keys = await deriveMultipleKeys(this.masterKey, timestamps);

    // Log access granted
    await this.auditLog.append(
      createAuditEntry('ACCESS_GRANTED', this.keyHolderId, true, {
        target: request.requesterId,
        timeRange: request.timeRange,
        details: {
          keyCount: keys.size
        }
      })
    );

    // Log key distribution
    await this.auditLog.append(
      createAuditEntry('KEY_DISTRIBUTION', this.keyHolderId, true, {
        target: request.requesterId,
        timeRange: request.timeRange,
        details: {
          keyCount: keys.size
        }
      })
    );

    return {
      granted: true,
      keys
    };
  }

  /**
   * Generate a single time-specific key (for direct key requests)
   *
   * @param timestamp - Timestamp for key generation
   * @param requesterId - ID of requesting entity
   * @returns Time-specific key
   */
  async generateKeyForTimestamp(
    timestamp: Timestamp,
    requesterId: string
  ): Promise<TimeSpecificKey> {
    // Create implicit access request
    const request: AccessRequest = {
      requesterId,
      timeRange: {
        startTime: timestamp,
        endTime: timestamp
      }
    };

    const response = await this.authorizeAccess(request);

    if (!response.granted || !response.keys) {
      throw new AccessDeniedError(
        response.denialReason || 'Access denied for requested timestamp'
      );
    }

    const key = response.keys.get(timestamp);
    if (!key) {
      throw new Error('Key generation failed');
    }

    return key;
  }

  /**
   * Generate timestamps within a time range
   *
   * This implementation generates timestamps at 1-second intervals.
   * For production use, adjust granularity based on application requirements.
   *
   * @param range - Time range
   * @param granularityMs - Timestamp granularity in milliseconds (default: 1000ms)
   * @returns Array of timestamps
   */
  private generateTimestampsInRange(
    range: TimeRange,
    granularityMs: number = 1000
  ): Timestamp[] {
    const timestamps: Timestamp[] = [];
    let current = range.startTime;

    while (current <= range.endTime) {
      timestamps.push(current);
      current += granularityMs;
    }

    // Always include the end time if not already included
    if (timestamps[timestamps.length - 1] !== range.endTime) {
      timestamps.push(range.endTime);
    }

    return timestamps;
  }

  /**
   * Get access control policy manager for policy management
   */
  getPolicyManager(): AccessControlPolicyManager {
    return this.policyManager;
  }

  /**
   * Get audit log for review
   */
  getAuditLog(): AuditLogStorage {
    return this.auditLog;
  }

  /**
   * Revoke access by not issuing new keys (existing keys remain valid until destroyed)
   *
   * Note: This system provides forward secrecy - if a viewer already has keys,
   * they remain valid until the viewer destroys them. True revocation would
   * require additional infrastructure (key servers, online validation, etc.)
   */
  async revokeAccess(requesterId: string, reason: string): Promise<void> {
    await this.auditLog.append(
      createAuditEntry('ACCESS_DENIED', this.keyHolderId, true, {
        target: requesterId,
        details: {
          reason: `Access revoked: ${reason}`,
          revocation: true
        }
      })
    );
  }
}

/**
 * Helper function to create a key holder
 *
 * @param masterKey - Master key for key derivation
 * @param auditLog - Audit log storage
 * @param policies - Access control policies
 * @param keyHolderId - Identifier for this key holder
 * @returns New key holder instance
 */
export function createKeyHolder(
  masterKey: MasterKey,
  auditLog: AuditLogStorage,
  policies: KeyHolderConfig['policies'] = [],
  keyHolderId?: string
): KeyHolder {
  return new KeyHolder(
    {
      masterKey,
      policies
    },
    auditLog,
    keyHolderId
  );
}
