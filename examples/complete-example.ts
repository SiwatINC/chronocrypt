/**
 * Complete Example: ChronoCrypt Time-Based Encryption System
 *
 * This example demonstrates the complete workflow of the ChronoCrypt system:
 * 1. Data Source encrypts temporal data
 * 2. Key Holder authorizes access based on policies
 * 3. Data Viewer decrypts authorized data
 */

import {
  generateMasterKey,
  createDataSource,
  createKeyHolder,
  createDataViewer,
  InMemoryEncryptedRepository,
  InMemoryAuditLog,
  createRequesterWhitelistPolicy,
  createMaxDurationPolicy,
  createPastOnlyPolicy,
  createPurposeRequiredPolicy,
  exportMasterKeyToBase64
} from '../src';

async function main() {
  console.log('=== ChronoCrypt Example: IoT Sensor Data Encryption ===\n');

  // Step 1: Initialize the system
  console.log('1. Initializing system...');
  const masterKey = generateMasterKey();
  const repository = new InMemoryEncryptedRepository();
  const auditLog = new InMemoryAuditLog();

  console.log(`   Master Key (Base64): ${exportMasterKeyToBase64(masterKey).substring(0, 20)}...`);
  console.log('   Repository: In-Memory');
  console.log('   Audit Log: In-Memory\n');

  // Step 2: Data Source encrypts sensor data
  console.log('2. Data Source: Encrypting sensor readings...');
  const dataSource = createDataSource(repository, masterKey);

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
  console.log(`   Repository size: ${repository.size()} packages\n`);

  // Step 3: Key Holder sets up access control policies
  console.log('3. Key Holder: Configuring access control policies...');
  const policies = [
    createRequesterWhitelistPolicy(['analyst-001', 'analyst-002', 'manager-001']),
    createMaxDurationPolicy(3600000), // Max 1 hour of data per request
    createPastOnlyPolicy(),
    createPurposeRequiredPolicy(15) // Purpose must be at least 15 characters
  ];

  const keyHolder = createKeyHolder(masterKey, auditLog, policies, 'key-holder-main');

  console.log('   Policies configured:');
  console.log('   - Requester Whitelist: analyst-001, analyst-002, manager-001');
  console.log('   - Maximum Duration: 1 hour');
  console.log('   - Past Data Only: Enabled');
  console.log('   - Purpose Required: Minimum 15 characters\n');

  // Step 4: Authorized user requests access
  console.log('4. Access Request: analyst-001 requesting data access...');
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
  console.log(`   Time Range: ${timeRange.startTime} to ${timeRange.endTime}`);
  console.log(`   Purpose: ${accessRequest.purpose}`);

  const authResponse = await keyHolder.authorizeAccess(accessRequest);

  if (!authResponse.granted) {
    console.log(`   ✗ Access Denied: ${authResponse.denialReason}\n`);
    return;
  }

  console.log(`   ✓ Access Granted!`);
  console.log(`   Keys provided: ${authResponse.keys!.size}\n`);

  // Step 5: Data Viewer decrypts the authorized data
  console.log('5. Data Viewer: Decrypting authorized data...');
  const dataViewer = createDataViewer('analyst-001', auditLog);
  dataViewer.loadAuthorizedKeys(authResponse.keys!);

  console.log(`   Loaded ${dataViewer.getAuthorizedTimestamps().length} authorized keys`);

  const decryptedData = await dataViewer.decryptRange(repository, timeRange);

  console.log(`   ✓ Successfully decrypted ${decryptedData.length} packages\n`);

  // Step 6: Process and display the decrypted data
  console.log('6. Processing decrypted sensor data:');
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

  // Step 7: Calculate statistics
  const temperatures = decryptedData.map(item => {
    return JSON.parse(new TextDecoder().decode(item.data)).temperature;
  });

  const avgTemp = temperatures.reduce((a, b) => a + b, 0) / temperatures.length;
  const maxTemp = Math.max(...temperatures);
  const minTemp = Math.min(...temperatures);

  console.log('7. Statistics:');
  console.log(`   Average Temperature: ${avgTemp.toFixed(2)}°C`);
  console.log(`   Maximum Temperature: ${maxTemp}°C`);
  console.log(`   Minimum Temperature: ${minTemp}°C\n`);

  // Step 8: Review audit log
  console.log('8. Audit Log Review:');
  const auditEntries = await auditLog.getAll();
  console.log(`   Total audit entries: ${auditEntries.length}`);

  const stats = await auditLog.getStatistics();
  console.log('   Entries by type:');
  for (const [type, count] of Object.entries(stats.entriesByType)) {
    console.log(`     - ${type}: ${count}`);
  }
  console.log(`   Success rate: ${(stats.successRate * 100).toFixed(1)}%\n`);

  // Step 9: Clean up
  console.log('9. Cleanup: Destroying authorized keys...');
  const destroyedCount = dataViewer.destroyAllKeys();
  console.log(`   ✓ Destroyed ${dataViewer.getKeyStatistics().totalKeys} keys`);
  console.log(`   Remaining keys: ${dataViewer.getKeyStatistics().totalKeys}\n`);

  console.log('=== Example Complete ===');
}

// Run the example
main().catch(console.error);
