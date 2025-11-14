/**
 * ChronoCrypt - Time-Based Granular Data Encryption System
 *
 * A cryptographic library for temporal data access control with zero-knowledge authorization
 *
 * @packageDocumentation
 */

// Export all type definitions
export * from '~/types';

// Export cryptographic primitives
export {
  generateMasterKey,
  validateMasterKey,
  deriveTimeSpecificKey,
  deriveMultipleKeys,
  destroyKey,
  importMasterKeyFromHex,
  exportMasterKeyToHex,
  importMasterKeyFromBase64,
  exportMasterKeyToBase64,
  MASTER_KEY_SIZE,
  DERIVED_KEY_SIZE
} from '~/crypto/key-derivation';

export {
  encryptData,
  decryptData,
  verifyAuthentication,
  generateIV,
  serializeEncryptedPackage,
  deserializeEncryptedPackage,
  IV_SIZE,
  AUTH_TAG_SIZE
} from '~/crypto/encryption';

// Export entities
export { DataSource, createDataSource } from '~/entities/data-source';
export { KeyHolder, createKeyHolder } from '~/entities/key-holder';
export { DataViewer, createDataViewer } from '~/entities/data-viewer';

// Export storage implementations
export {
  InMemoryEncryptedRepository,
  FileSystemEncryptedRepository
} from '~/storage/encrypted-repository';

export {
  InMemoryAuditLog,
  FileBasedAuditLog,
  generateAuditEntryId,
  createAuditEntry
} from '~/storage/audit-log';

// Export access control policies
export {
  AccessControlPolicyManager,
  createAllowAllPolicy,
  createDenyAllPolicy,
  createRequesterWhitelistPolicy,
  createMaxDurationPolicy,
  createPastOnlyPolicy,
  createTimeWindowPolicy,
  createRateLimitPolicy,
  createPurposeRequiredPolicy,
  createBusinessHoursPolicy,
  createCompositeAndPolicy,
  createCompositeOrPolicy
} from '~/policies/access-control';

export type { PolicyEvaluationResult } from '~/policies/access-control';
