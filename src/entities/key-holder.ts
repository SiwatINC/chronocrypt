/**
 * Key Holder Entity - Private Key Management & Access Control
 *
 * SECURITY MODEL:
 * - KeyHolder is in TRUSTED zone (secure key management infrastructure)
 * - Has master PRIVATE key - can derive time-specific private keys
 * - Never communicates with DataSource at runtime
 * - Authorizes DataViewer access by providing time-specific private keys
 */

import { deriveMultiplePrivateKeys } from '../crypto/key-derivation';
import {
  KeyHolderConfig,
  AccessRequest,
  AccessResponse,
  AuditLogStorage,
  MasterKeypair,
  TimeSpecificPrivateKey,
  Timestamp,
  TimeRange,
  AccessControlPolicy,
  AccessDeniedError
} from '../types/index';

/**
 * Access control policy evaluation result
 */
interface PolicyEvaluationResult {
  allow: boolean;
  policy?: AccessControlPolicy;
  reason?: string;
}

/**
 * Access control policy manager
 */
class AccessControlPolicyManager {
  private policies: AccessControlPolicy[];

  constructor(policies: AccessControlPolicy[] = []) {
    this.policies = [...policies];
    this.sortPolicies();
  }

  private sortPolicies(): void {
    this.policies.sort((a, b) => {
      const priorityA = a.priority ?? 0;
      const priorityB = b.priority ?? 0;
      return priorityB - priorityA;
    });
  }

  async evaluateRequest(request: AccessRequest): Promise<PolicyEvaluationResult> {
    if (this.policies.length === 0) {
      return {
        allow: false,
        reason: 'No access control policies defined'
      };
    }

    for (const policy of this.policies) {
      try {
        const result = await policy.evaluate(request);
        if (!result) {
          return {
            allow: false,
            policy,
            reason: `Access denied by policy: ${policy.name}`
          };
        }
      } catch (error) {
        return {
          allow: false,
          policy,
          reason: `Policy evaluation error: ${error instanceof Error ? error.message : String(error)}`
        };
      }
    }

    return {
      allow: true,
      reason: 'All policies passed'
    };
  }
}

/**
 * Key Holder Entity - Controls access authorization via private key derivation
 *
 * Core Responsibilities:
 * - Maintain master private key in secure storage
 * - Generate time-specific PRIVATE keys for authorized temporal ranges
 * - Implement access control policies
 * - Maintain comprehensive audit logs
 * - Securely distribute authorized private keys to data viewers
 *
 * Security Guarantees:
 * - Never accesses encrypted data content
 * - Zero runtime communication with DataSource
 * - Temporal isolation: each timestamp gets unique private key
 * - Audit trail for all authorization activities
 */
export class KeyHolder {
  private masterKeypair: MasterKeypair;
  private policyManager: AccessControlPolicyManager;
  private auditLog: AuditLogStorage;
  private keyHolderId: string;

  constructor(
    config: KeyHolderConfig,
    auditLog: AuditLogStorage,
    keyHolderId: string = 'key-holder'
  ) {
    this.masterKeypair = config.masterKeypair;
    this.policyManager = new AccessControlPolicyManager(config.policies);
    this.auditLog = auditLog;
    this.keyHolderId = keyHolderId;
  }

  /**
   * Process an access authorization request
   *
   * Workflow:
   * 1. Log access request
   * 2. Evaluate against access control policies
   * 3. If granted: derive time-specific private keys
   * 4. Audit log authorization decision
   * 5. Return private keys to authorized viewer
   *
   * @param request - Access authorization request
   * @returns Access response with private keys if granted
   */
  async authorizeAccess(request: AccessRequest): Promise<AccessResponse> {
    // Log access request
    await this.auditLog.append({
      id: this.generateAuditId(),
      timestamp: Date.now(),
      eventType: 'ACCESS_REQUEST',
      actor: request.requesterId,
      target: this.keyHolderId,
      timeRange: request.timeRange,
      success: true,
      details: {
        purpose: request.purpose,
        metadata: request.metadata
      }
    });

    // Evaluate access control policies
    const policyResult = await this.policyManager.evaluateRequest(request);

    if (!policyResult.allow) {
      // Log access denial
      await this.auditLog.append({
        id: this.generateAuditId(),
        timestamp: Date.now(),
        eventType: 'ACCESS_DENIED',
        actor: request.requesterId,
        target: this.keyHolderId,
        timeRange: request.timeRange,
        success: true,
        details: {
          reason: policyResult.reason,
          policy: policyResult.policy?.name
        }
      });

      return {
        granted: false,
        denialReason: policyResult.reason
      };
    }

    // Generate timestamps in range
    const timestamps = this.generateTimestampsInRange(request.timeRange);

    // Log key generation
    await this.auditLog.append({
      id: this.generateAuditId(),
      timestamp: Date.now(),
      eventType: 'KEY_GENERATION',
      actor: this.keyHolderId,
      target: request.requesterId,
      timeRange: request.timeRange,
      success: true,
      details: {
        keyCount: timestamps.length
      }
    });

    // Derive time-specific PRIVATE keys
    const privateKeys = await deriveMultiplePrivateKeys(
      this.masterKeypair.privateKey,
      timestamps
    );

    // Log access granted
    await this.auditLog.append({
      id: this.generateAuditId(),
      timestamp: Date.now(),
      eventType: 'ACCESS_GRANTED',
      actor: this.keyHolderId,
      target: request.requesterId,
      timeRange: request.timeRange,
      success: true,
      details: {
        keyCount: privateKeys.size
      }
    });

    // Log key distribution
    await this.auditLog.append({
      id: this.generateAuditId(),
      timestamp: Date.now(),
      eventType: 'KEY_DISTRIBUTION',
      actor: this.keyHolderId,
      target: request.requesterId,
      timeRange: request.timeRange,
      success: true,
      details: {
        keyCount: privateKeys.size
      }
    });

    return {
      granted: true,
      privateKeys
    };
  }

  /**
   * Generate timestamps within a time range
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
    if (timestamps.length === 0 || timestamps[timestamps.length - 1] !== range.endTime) {
      timestamps.push(range.endTime);
    }

    return timestamps;
  }

  /**
   * Generate unique audit entry ID
   */
  private generateAuditId(): string {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2, 15);
    return `audit-${timestamp}-${random}`;
  }

  /**
   * Get audit log for review
   */
  getAuditLog(): AuditLogStorage {
    return this.auditLog;
  }

  /**
   * Get the master public key (for distribution to DataSource)
   *
   * @returns Master public key from the keypair
   */
  getMasterPublicKey(): CryptoKey {
    return this.masterKeypair.publicKey;
  }
}

/**
 * Helper function to create a key holder
 *
 * @param masterKeypair - Master EC keypair
 * @param auditLog - Audit log storage
 * @param policies - Access control policies
 * @param keyHolderId - Identifier for this key holder
 * @returns New key holder instance
 */
export function createKeyHolder(
  masterKeypair: MasterKeypair,
  auditLog: AuditLogStorage,
  policies: AccessControlPolicy[] = [],
  keyHolderId?: string
): KeyHolder {
  return new KeyHolder(
    {
      masterKeypair,
      policies
    },
    auditLog,
    keyHolderId
  );
}
