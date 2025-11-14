/**
 * Type definitions for ChronoCrypt - Asymmetric Time-Based Encryption
 *
 * Security Model:
 * - DataSource (untrusted): Has PUBLIC key only - can encrypt, cannot decrypt
 * - KeyHolder (trusted): Has PRIVATE key - derives time-specific private keys
 * - DataViewer: Gets time-specific private keys from KeyHolder
 */

/**
 * Master keypair for time-based encryption
 */
export interface MasterKeypair {
  /** Private key (kept secret by KeyHolder only) */
  privateKey: CryptoKey;
  /** Public key (given to untrusted DataSource) */
  publicKey: CryptoKey;
}

/**
 * Exportable master public key (JWK format)
 */
export type ExportedPublicKey = JsonWebKey;

/**
 * Time-specific private key for decryption
 */
export type TimeSpecificPrivateKey = CryptoKey;

/**
 * Timestamp representation - Unix epoch in milliseconds
 */
export type Timestamp = number;

/**
 * Encrypted data package using hybrid encryption
 *
 * Structure:
 * - Symmetric key K encrypted with time-based public key (ECIES)
 * - Data encrypted with symmetric key K (AES-256-GCM)
 */
export interface EncryptedPackage {
  /** Timestamp when data was encrypted */
  timestamp: Timestamp;
  /** Encrypted symmetric key (ECIES encrypted) */
  encryptedKey: Uint8Array;
  /** Ephemeral public key used for ECDH key agreement */
  ephemeralPublicKey: JsonWebKey;
  /** Encrypted data payload (AES-256-GCM) */
  encryptedData: Uint8Array;
  /** Initialization vector for AES-GCM */
  iv: Uint8Array;
  /** Authentication tag from AES-GCM */
  authTag: Uint8Array;
  /** Optional application-specific metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Decrypted data with associated metadata
 */
export interface DecryptedData {
  /** Original timestamp from encryption */
  timestamp: Timestamp;
  /** Decrypted data payload */
  data: Uint8Array;
  /** Optional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Time range for access authorization
 */
export interface TimeRange {
  /** Start of time range (inclusive) */
  startTime: Timestamp;
  /** End of time range (inclusive) */
  endTime: Timestamp;
}

/**
 * Access authorization request
 */
export interface AccessRequest {
  /** Identifier of requesting entity */
  requesterId: string;
  /** Requested time range */
  timeRange: TimeRange;
  /** Purpose or justification for access */
  purpose?: string;
  /** Additional request metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Access authorization response with time-specific private keys
 */
export interface AccessResponse {
  /** Whether access was granted */
  granted: boolean;
  /** Time-specific private keys for authorized time periods */
  privateKeys?: Map<Timestamp, TimeSpecificPrivateKey>;
  /** Reason for denial if not granted */
  denialReason?: string;
  /** Authorization metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Audit log entry for access authorization
 */
export interface AuditLogEntry {
  /** Unique identifier for this audit entry */
  id: string;
  /** Timestamp when event occurred */
  timestamp: Timestamp;
  /** Type of event */
  eventType: 'KEY_GENERATION' | 'ACCESS_REQUEST' | 'ACCESS_GRANTED' | 'ACCESS_DENIED' | 'KEY_DISTRIBUTION' | 'DECRYPTION_ATTEMPT';
  /** Entity that initiated the action */
  actor: string;
  /** Target entity or resource */
  target?: string;
  /** Time range involved in the event */
  timeRange?: TimeRange;
  /** Whether the action was successful */
  success: boolean;
  /** Additional details about the event */
  details?: Record<string, unknown>;
}

/**
 * Access control policy definition
 */
export interface AccessControlPolicy {
  /** Unique identifier for the policy */
  id: string;
  /** Human-readable policy name */
  name: string;
  /** Policy evaluation function */
  evaluate: (request: AccessRequest) => Promise<boolean>;
  /** Policy priority (higher = evaluated first) */
  priority?: number;
  /** Optional policy metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Configuration options for Data Source Entity
 */
export interface DataSourceConfig {
  /** Master PUBLIC key for encryption (DataSource never sees private key) */
  publicKey: ExportedPublicKey;
  /** Optional custom timestamp generator */
  timestampGenerator?: () => Timestamp;
}

/**
 * Configuration options for Key Holder Entity
 */
export interface KeyHolderConfig {
  /** Master keypair (private key for deriving time-specific keys) */
  masterKeypair: MasterKeypair;
  /** Access control policies */
  policies?: AccessControlPolicy[];
}

/**
 * Configuration options for Data Viewer Entity
 */
export interface DataViewerConfig {
  /** Identifier for this viewer entity */
  viewerId: string;
}

/**
 * Storage interface for encrypted data repository
 */
export interface EncryptedDataRepository {
  /** Store encrypted data package */
  store(pkg: EncryptedPackage): Promise<void>;
  /** Retrieve encrypted data for specific timestamp */
  retrieve(timestamp: Timestamp): Promise<EncryptedPackage | null>;
  /** Retrieve encrypted data for time range */
  retrieveRange(range: TimeRange): Promise<EncryptedPackage[]>;
  /** Check if data exists for timestamp */
  exists(timestamp: Timestamp): Promise<boolean>;
}

/**
 * Storage interface for audit logs
 */
export interface AuditLogStorage {
  /** Append entry to audit log */
  append(entry: AuditLogEntry): Promise<void>;
  /** Retrieve audit log entries for time range */
  retrieve(range: TimeRange): Promise<AuditLogEntry[]>;
  /** Retrieve audit log entries by event type */
  retrieveByEventType(eventType: AuditLogEntry['eventType']): Promise<AuditLogEntry[]>;
  /** Retrieve audit log entries by actor */
  retrieveByActor(actor: string): Promise<AuditLogEntry[]>;
}

/**
 * Error types for ChronoCrypt operations
 */
export class ChronoCryptError extends Error {
  constructor(message: string, public readonly code: string) {
    super(message);
    this.name = 'ChronoCryptError';
  }
}

export class KeyDerivationError extends ChronoCryptError {
  constructor(message: string) {
    super(message, 'KEY_DERIVATION_ERROR');
    this.name = 'KeyDerivationError';
  }
}

export class EncryptionError extends ChronoCryptError {
  constructor(message: string) {
    super(message, 'ENCRYPTION_ERROR');
    this.name = 'EncryptionError';
  }
}

export class DecryptionError extends ChronoCryptError {
  constructor(message: string) {
    super(message, 'DECRYPTION_ERROR');
    this.name = 'DecryptionError';
  }
}

export class AuthenticationError extends ChronoCryptError {
  constructor(message: string) {
    super(message, 'AUTHENTICATION_ERROR');
    this.name = 'AuthenticationError';
  }
}

export class AccessDeniedError extends ChronoCryptError {
  constructor(message: string) {
    super(message, 'ACCESS_DENIED');
    this.name = 'AccessDeniedError';
  }
}

export class InvalidKeyError extends ChronoCryptError {
  constructor(message: string) {
    super(message, 'INVALID_KEY');
    this.name = 'InvalidKeyError';
  }
}
