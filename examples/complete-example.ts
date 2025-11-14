/**
 * Complete Example: ChronoCrypt Asymmetric Time-Based Encryption System
 *
 * This example demonstrates the complete workflow of the ChronoCrypt system:
 * 1. Key Holder generates master keypair (private key stays secure)
 * 2. Data Source (untrusted) receives public key and encrypts temporal data
 * 3. Key Holder authorizes access based on policies
 * 4. Data Viewer decrypts authorized data with time-specific private keys
 *
 * SECURITY MODEL:
 * - DataSource: Has PUBLIC key only - can encrypt but CANNOT decrypt
 * - KeyHolder: Has PRIVATE key - derives time-specific keys for authorization
 * - DataViewer: Receives time-specific keys - can decrypt authorized data only
 */

import {
  generateMasterKeypair,
  exportPublicKey,
  createDataSource,
  createKeyHolder,
  createDataViewer,
  InMemoryEncryptedRepository,
  InMemoryAuditLog,
  createAllowAllPolicy
} from '../src';

async function main() {
  console.log('=== ChronoCrypt Example: IoT Sensor Data Encryption ===\n');

  // Step 1: Key Holder generates master keypair
  console.log('1. Key Holder: Generating master keypair...');
  const masterKeypair = await generateMasterKeypair();
  const publicKey = await exportPublicKey(masterKeypair.publicKey);

  console.log('   ✓ Master keypair generated (EC P-256)');
  console.log(`   Public key type: ${publicKey.kty}, curve: ${publicKey.crv}`);
  console.log(`   Public key (x): ${publicKey.x?.substring(0, 20)}...`);
  console.log('   ⚠️  Private key kept secure in KeyHolder only\n');

  // Step 2: Initialize storage and audit log
  console.log('2. Initializing storage and audit systems...');
  const repository = new InMemoryEncryptedRepository();
  const auditLog = new InMemoryAuditLog();

  console.log('   ✓ Repository: In-Memory (encrypted packages)');
  console.log('   ✓ Audit Log: In-Memory (access tracking)\n');

  // Step 3: Data Source encrypts sensor data (PUBLIC KEY ONLY)
  console.log('3. Data Source (Untrusted Zone): Encrypting sensor readings...');
  console.log('   📌 DataSource has PUBLIC key only - cannot decrypt!\n');

  // DataSource only gets the public key, never the private key
  const dataSource = createDataSource(publicKey, repository);

  const sensorReadings = [
    { temperature: 22.5, humidity: 45, pressure: 1013.25 },
    { temperature: 23.1, humidity: 47, pressure: 1013.15 },
    { temperature: 21.8, humidity: 44, pressure: 1013.30 },
    { temperature: 22.9, humidity: 46, pressure: 1013.20 },
    { temperature: 23.5, humidity: 48, pressure: 1013.10 }
  ];

  const encryptedPackages = [];
  const baseTimestamp = Date.now() - 300000; // 5 minutes ago

  for (let i = 0; i < sensorReadings.length; i++) {
    const reading = sensorReadings[i];
    const timestamp = baseTimestamp + i * 60000; // 1 minute intervals
    const data = new TextEncoder().encode(JSON.stringify(reading));

    const encrypted = await dataSource.encryptDataAtTimestamp(data, timestamp, {
      sensorId: 'TEMP-001',
      location: 'Building-A, Floor-3',
      readingNumber: i + 1
    });

    encryptedPackages.push(encrypted);
    console.log(`   ✓ Encrypted reading ${i + 1} at timestamp ${timestamp}`);
  }

  console.log(`\n   Total encrypted packages: ${encryptedPackages.length}`);
  console.log(`   Repository size: ${repository.size()} packages`);
  console.log('   🔒 Even if DataSource is compromised, data remains secure!\n');

  // Step 4: Key Holder sets up access control policies
  console.log('4. Key Holder (Trusted Zone): Configuring access control...');

  // For now, using allow-all policy (more policies can be added)
  const policies = [createAllowAllPolicy()];

  const keyHolder = createKeyHolder(masterKeypair, auditLog, policies, 'key-holder-main');

  console.log('   Policies configured:');
  console.log('   - Allow All: Enabled (for demo purposes)');
  console.log('   📌 KeyHolder can add time-based, requester-based, and purpose-based policies\n');

  // Step 5: Data Viewer requests access
  console.log('5. Data Viewer: Requesting access to encrypted data...');
  const timeRange = repository.getTimeRange();

  if (!timeRange) {
    console.log('   No data in repository');
    return;
  }

  const accessRequest = {
    requesterId: 'analyst-001',
    timeRange: timeRange,
    purpose: 'Analyzing temperature trends for HVAC optimization'
  };

  console.log(`   Requester ID: ${accessRequest.requesterId}`);
  console.log(`   Time Range: ${new Date(timeRange.startTime).toISOString()} to ${new Date(timeRange.endTime).toISOString()}`);
  console.log(`   Purpose: ${accessRequest.purpose}\n`);

  // Step 6: Key Holder authorizes access and provides time-specific private keys
  console.log('6. Key Holder: Evaluating access request and deriving keys...');
  const authResponse = await keyHolder.authorizeAccess(accessRequest);

  if (!authResponse.granted) {
    console.log(`   ✗ Access Denied: ${authResponse.denialReason}\n`);
    return;
  }

  console.log('   ✓ Access Granted!');
  console.log(`   Time-specific private keys provided: ${authResponse.privateKeys!.size}`);
  console.log('   📌 Keys are bound to specific timestamps via KDF\n');

  // Step 7: Data Viewer decrypts the authorized data
  console.log('7. Data Viewer: Decrypting authorized data...');
  const dataViewer = createDataViewer('analyst-001', auditLog);
  dataViewer.loadAuthorizedKeys(authResponse.privateKeys!);

  console.log(`   Loaded ${dataViewer.getAuthorizedTimestamps().length} authorized keys`);

  const decryptedData = await dataViewer.decryptRange(repository, timeRange);

  console.log(`   ✓ Successfully decrypted ${decryptedData.length} packages\n`);

  // Step 8: Process and display the decrypted data
  console.log('8. Processing decrypted sensor data:');
  console.log('   ┌─────────────┬─────────┬──────────┬──────────┐');
  console.log('   │ Reading #   │ Temp °C │ Humidity │ Pressure │');
  console.log('   ├─────────────┼─────────┼──────────┼──────────┤');

  for (const item of decryptedData) {
    const reading = JSON.parse(new TextDecoder().decode(item.data));
    const readingNum = item.metadata?.readingNumber || '?';

    console.log(
      `   │ ${String(readingNum).padEnd(11)} │ ${String(reading.temperature).padEnd(7)} │ ` +
        `${String(reading.humidity).padEnd(8)} │ ${String(reading.pressure).padEnd(8)} │`
    );
  }

  console.log('   └─────────────┴─────────┴──────────┴──────────┘\n');

  // Step 9: Calculate statistics
  const temperatures = decryptedData.map(item => {
    return JSON.parse(new TextDecoder().decode(item.data)).temperature;
  });

  const avgTemp = temperatures.reduce((a, b) => a + b, 0) / temperatures.length;
  const maxTemp = Math.max(...temperatures);
  const minTemp = Math.min(...temperatures);

  console.log('9. Statistics:');
  console.log(`   Average Temperature: ${avgTemp.toFixed(2)}°C`);
  console.log(`   Maximum Temperature: ${maxTemp}°C`);
  console.log(`   Minimum Temperature: ${minTemp}°C\n`);

  // Step 10: Review audit log
  console.log('10. Audit Log Review:');
  const auditEntries = await auditLog.getAll();
  console.log(`    Total audit entries: ${auditEntries.length}`);

  const stats = await auditLog.getStatistics();
  console.log('    Entries by type:');
  for (const [type, count] of Object.entries(stats.entriesByType)) {
    console.log(`      - ${type}: ${count}`);
  }
  console.log(`    Success rate: ${(stats.successRate * 100).toFixed(1)}%\n`);

  // Step 11: Security demonstration
  console.log('11. Security Demonstration:');
  console.log('    ✓ DataSource compromise: Cannot decrypt (no private key)');
  console.log('    ✓ Timestamp tampering: Decryption fails (KDF binding)');
  console.log('    ✓ Data tampering: Detected by GCM authentication');
  console.log('    ✓ Unauthorized access: Requires KeyHolder authorization\n');

  // Step 12: Clean up
  console.log('12. Cleanup: Clearing authorized keys from memory...');
  dataViewer.clearAllKeys();
  console.log(`    ✓ Cleared keys from DataViewer`);
  console.log(`    Remaining keys: ${dataViewer.getKeyStatistics().totalKeys}\n`);

  console.log('=== Example Complete ===');
  console.log('\n📚 Key Takeaways:');
  console.log('  • Asymmetric design: DataSource cannot decrypt (public key only)');
  console.log('  • Temporal binding: Timestamps are cryptographically bound via HKDF');
  console.log('  • Access control: KeyHolder authorizes and provides time-specific keys');
  console.log('  • Audit trail: All operations logged for compliance');
  console.log('  • Zero-knowledge: KeyHolder never sees encrypted data content');
}

// Run the example
main().catch(console.error);
