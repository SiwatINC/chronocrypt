/**
 * Access Control Policy System
 *
 * Provides flexible policy-based access control for time-based encryption
 */

import { AccessControlPolicy, AccessRequest, TimeRange } from '../types';

/**
 * Policy evaluation result
 */
export interface PolicyEvaluationResult {
  allow: boolean;
  policy?: AccessControlPolicy;
  reason?: string;
}

/**
 * Access control policy manager
 */
export class AccessControlPolicyManager {
  private policies: AccessControlPolicy[];

  constructor(policies: AccessControlPolicy[] = []) {
    this.policies = [...policies];
    // Sort by priority (highest first)
    this.sortPolicies();
  }

  /**
   * Add a policy to the manager
   */
  addPolicy(policy: AccessControlPolicy): void {
    this.policies.push(policy);
    this.sortPolicies();
  }

  /**
   * Remove a policy by ID
   */
  removePolicy(policyId: string): boolean {
    const initialLength = this.policies.length;
    this.policies = this.policies.filter(p => p.id !== policyId);
    return this.policies.length < initialLength;
  }

  /**
   * Get all policies
   */
  getPolicies(): AccessControlPolicy[] {
    return [...this.policies];
  }

  /**
   * Sort policies by priority (highest first)
   */
  private sortPolicies(): void {
    this.policies.sort((a, b) => {
      const priorityA = a.priority ?? 0;
      const priorityB = b.priority ?? 0;
      return priorityB - priorityA; // Descending order
    });
  }

  /**
   * Evaluate all policies for an access request
   *
   * Policies are evaluated in priority order. First policy to return false denies access.
   * If all policies return true (or there are no policies), access is granted.
   */
  async evaluateRequest(request: AccessRequest): Promise<PolicyEvaluationResult> {
    // If no policies are defined, deny by default for security
    if (this.policies.length === 0) {
      return {
        allow: false,
        reason: 'No access control policies defined'
      };
    }

    // Evaluate each policy in priority order
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
        // If a policy throws an error, treat it as denial
        return {
          allow: false,
          policy,
          reason: `Policy evaluation error: ${error instanceof Error ? error.message : String(error)}`
        };
      }
    }

    // All policies passed
    return {
      allow: true,
      reason: 'All policies passed'
    };
  }
}

/**
 * Built-in policy: Allow all requests (for testing/development only)
 */
export function createAllowAllPolicy(): AccessControlPolicy {
  return {
    id: 'allow-all',
    name: 'Allow All (Development Only)',
    evaluate: async () => true,
    priority: -1000 // Very low priority
  };
}

/**
 * Built-in policy: Deny all requests
 */
export function createDenyAllPolicy(): AccessControlPolicy {
  return {
    id: 'deny-all',
    name: 'Deny All',
    evaluate: async () => false,
    priority: 1000 // Very high priority
  };
}

/**
 * Built-in policy: Whitelist of allowed requester IDs
 */
export function createRequesterWhitelistPolicy(allowedIds: string[]): AccessControlPolicy {
  return {
    id: 'requester-whitelist',
    name: 'Requester Whitelist',
    evaluate: async (request: AccessRequest) => {
      return allowedIds.includes(request.requesterId);
    },
    priority: 100,
    metadata: { allowedIds }
  };
}

/**
 * Built-in policy: Time range maximum duration limit
 */
export function createMaxDurationPolicy(maxDurationMs: number): AccessControlPolicy {
  return {
    id: 'max-duration',
    name: 'Maximum Duration Limit',
    evaluate: async (request: AccessRequest) => {
      const duration = request.timeRange.endTime - request.timeRange.startTime;
      return duration <= maxDurationMs;
    },
    priority: 50,
    metadata: { maxDurationMs }
  };
}

/**
 * Built-in policy: Only allow access to past time periods (not future)
 */
export function createPastOnlyPolicy(): AccessControlPolicy {
  return {
    id: 'past-only',
    name: 'Past Time Periods Only',
    evaluate: async (request: AccessRequest) => {
      const now = Date.now();
      return request.timeRange.endTime <= now;
    },
    priority: 75
  };
}

/**
 * Built-in policy: Restrict access to specific time windows
 */
export function createTimeWindowPolicy(allowedWindows: TimeRange[]): AccessControlPolicy {
  return {
    id: 'time-window',
    name: 'Allowed Time Windows',
    evaluate: async (request: AccessRequest) => {
      // Check if requested time range falls within any allowed window
      return allowedWindows.some(window => {
        return (
          request.timeRange.startTime >= window.startTime &&
          request.timeRange.endTime <= window.endTime
        );
      });
    },
    priority: 80,
    metadata: { allowedWindows }
  };
}

/**
 * Built-in policy: Rate limiting per requester
 */
export function createRateLimitPolicy(
  maxRequestsPerMinute: number
): AccessControlPolicy {
  const requestCounts = new Map<string, { count: number; windowStart: number }>();

  return {
    id: 'rate-limit',
    name: 'Rate Limiting',
    evaluate: async (request: AccessRequest) => {
      const now = Date.now();
      const windowDuration = 60000; // 1 minute

      const existing = requestCounts.get(request.requesterId);

      if (!existing || now - existing.windowStart > windowDuration) {
        // Start new window
        requestCounts.set(request.requesterId, {
          count: 1,
          windowStart: now
        });
        return true;
      }

      // Within existing window
      if (existing.count >= maxRequestsPerMinute) {
        return false; // Rate limit exceeded
      }

      existing.count++;
      return true;
    },
    priority: 90,
    metadata: { maxRequestsPerMinute }
  };
}

/**
 * Built-in policy: Require purpose/justification in request
 */
export function createPurposeRequiredPolicy(
  minPurposeLength: number = 10
): AccessControlPolicy {
  return {
    id: 'purpose-required',
    name: 'Purpose Required',
    evaluate: async (request: AccessRequest) => {
      return !!(
        request.purpose &&
        request.purpose.trim().length >= minPurposeLength
      );
    },
    priority: 60,
    metadata: { minPurposeLength }
  };
}

/**
 * Built-in policy: Business hours only
 */
export function createBusinessHoursPolicy(
  startHour: number = 9,
  endHour: number = 17,
  timezone: string = 'UTC'
): AccessControlPolicy {
  return {
    id: 'business-hours',
    name: 'Business Hours Only',
    evaluate: async () => {
      const now = new Date();
      const hour = now.getUTCHours(); // Simplified - doesn't handle timezones properly

      return hour >= startHour && hour < endHour;
    },
    priority: 40,
    metadata: { startHour, endHour, timezone }
  };
}

/**
 * Built-in policy: Combine multiple policies with AND logic
 */
export function createCompositeAndPolicy(
  policies: AccessControlPolicy[],
  name: string = 'Composite AND Policy'
): AccessControlPolicy {
  return {
    id: `composite-and-${Date.now()}`,
    name,
    evaluate: async (request: AccessRequest) => {
      for (const policy of policies) {
        const result = await policy.evaluate(request);
        if (!result) {
          return false;
        }
      }
      return true;
    },
    priority: 0,
    metadata: { policies: policies.map(p => p.id) }
  };
}

/**
 * Built-in policy: Combine multiple policies with OR logic
 */
export function createCompositeOrPolicy(
  policies: AccessControlPolicy[],
  name: string = 'Composite OR Policy'
): AccessControlPolicy {
  return {
    id: `composite-or-${Date.now()}`,
    name,
    evaluate: async (request: AccessRequest) => {
      for (const policy of policies) {
        const result = await policy.evaluate(request);
        if (result) {
          return true;
        }
      }
      return false;
    },
    priority: 0,
    metadata: { policies: policies.map(p => p.id) }
  };
}
