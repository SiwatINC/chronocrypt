/**
 * Complete Example: Using Prisma with ChronoCrypt
 *
 * This example shows how to use Prisma (PostgreSQL or SQLite) as the storage backend.
 *
 * Prerequisites:
 * 1. bun add @prisma/client prisma
 * 2. Copy schema.prisma to your project's prisma directory
 * 3. Run: bunx prisma generate && bunx prisma migrate dev
 * 4. Set DATABASE_URL in .env file
 */

import { PrismaClient } from '@prisma/client';
import {
  generateMasterKey,
  createDataSource,
  createKeyHolder,
  createDataViewer,
  createRequesterWhitelistPolicy,
  createMaxDurationPolicy,
  createPastOnlyPolicy,
  exportMasterKeyToBase64
} from '@siwats/chronocrypt';
import { createPrismaRepository } from './prisma-encrypted-repository';
import { createPrismaAuditLog } from './prisma-audit-log';

async function main() {
  console.log('=== ChronoCrypt + Prisma Example ===\n');

  // Initialize Prisma
  console.log('1. Connecting to database...');
  const prisma = new PrismaClient({
    log: ['error', 'warn']
  });

  try {
    await prisma.$connect();
    console.log('   ✓ Database connected\n');
  } catch (error) {
    console.error('   ✗ Failed to connect to database:', error);
    console.log('\nMake sure:');
    console.log('- DATABASE_URL is set in .env');
    console.log('- Database is running');
    console.log('- Migrations have been run: bunx prisma migrate dev\n');
    return;
  }

  // Initialize ChronoCrypt with Prisma storage
  console.log('2. Initializing ChronoCrypt with Prisma storage...');
  const masterKey = generateMasterKey();
  const repository = createPrismaRepository(prisma);
  const auditLog = createPrismaAuditLog(prisma);

  console.log(`   Master Key: ${exportMasterKeyToBase64(masterKey).substring(0, 20)}...`);
  console.log('   Storage: Prisma (PostgreSQL/SQLite)');
  console.log('   Repository: PrismaEncryptedRepository');
  console.log('   Audit Log: PrismaAuditLog\n');

  // Data Source: Encrypt sensor data
  console.log('3. Encrypting IoT sensor data...');
  const dataSource = createDataSource(repository, masterKey);

  const sensorReadings = [
    { deviceId: 'sensor-01', temperature: 22.5, humidity: 45 },
    { deviceId: 'sensor-01', temperature: 23.1, humidity: 47 },
    { deviceId: 'sensor-01', temperature: 21.8, humidity: 44 },
    { deviceId: 'sensor-02', temperature: 24.5, humidity: 50 },
    { deviceId: 'sensor-02', temperature: 23.8, humidity: 48 }
  ];

  const baseTimestamp = Date.now() - 300000; // 5 minutes ago

  for (let i = 0; i < sensorReadings.length; i++) {
    const reading = sensorReadings[i];
    const timestamp = baseTimestamp + i * 60000; // 1 minute intervals
    const data = new TextEncoder().encode(JSON.stringify(reading));

    await dataSource.encryptDataAtTimestamp(data, timestamp, {
      deviceId: reading.deviceId,
      readingNumber: i + 1
    });

    console.log(`   ✓ Encrypted reading ${i + 1} from ${reading.deviceId}`);
  }

  // Verify data in database
  const totalPackages = await repository.size();
  console.log(`\n   Total packages in database: ${totalPackages}\n`);

  // Key Holder: Configure access control
  console.log('4. Configuring access control policies...');
  const policies = [
    createRequesterWhitelistPolicy(['analyst-001', 'analyst-002']),
    createMaxDurationPolicy(3600000), // 1 hour max
    createPastOnlyPolicy()
  ];

  const keyHolder = createKeyHolder(masterKey, auditLog, policies);
  console.log('   ✓ Policies configured\n');

  // Access Request
  console.log('5. Requesting data access...');
  const timeRange = await repository.getTimeRange();

  if (!timeRange) {
    console.log('   No data in repository');
    await prisma.$disconnect();
    return;
  }

  const accessRequest = {
    requesterId: 'analyst-001',
    timeRange: timeRange,
    purpose: 'Analyzing sensor performance metrics'
  };

  const authResponse = await keyHolder.authorizeAccess(accessRequest);

  if (!authResponse.granted) {
    console.log(`   ✗ Access Denied: ${authResponse.denialReason}\n`);
    await prisma.$disconnect();
    return;
  }

  console.log(`   ✓ Access Granted - ${authResponse.keys!.size} keys provided\n`);

  // Data Viewer: Decrypt data
  console.log('6. Decrypting authorized data...');
  const dataViewer = createDataViewer('analyst-001', auditLog);
  dataViewer.loadAuthorizedKeys(authResponse.keys!);

  const decryptedData = await dataViewer.decryptRange(repository, timeRange);
  console.log(`   ✓ Decrypted ${decryptedData.length} packages\n`);

  // Process decrypted data
  console.log('7. Processing sensor data:');
  console.log('   ┌────────────┬──────────┬──────────┬──────────┐');
  console.log('   │ Device     │ Reading  │ Temp °C  │ Humidity │');
  console.log('   ├────────────┼──────────┼──────────┼──────────┤');

  for (const item of decryptedData) {
    const reading = JSON.parse(new TextDecoder().decode(item.data));
    const deviceId = reading.deviceId || 'unknown';
    const readingNum = item.metadata?.readingNumber || '?';

    console.log(
      `   │ ${deviceId.padEnd(10)} │ ${String(readingNum).padEnd(8)} │ ` +
        `${String(reading.temperature).padEnd(8)} │ ${String(reading.humidity).padEnd(8)} │`
    );
  }

  console.log('   └────────────┴──────────┴──────────┴──────────┘\n');

  // Audit Log Review
  console.log('8. Reviewing audit trail...');
  const auditStats = await auditLog.getStatistics();

  console.log(`   Total audit entries: ${auditStats.totalEntries}`);
  console.log(`   Success rate: ${(auditStats.successRate * 100).toFixed(1)}%`);
  console.log('   Entries by type:');
  for (const [type, count] of Object.entries(auditStats.entriesByType)) {
    console.log(`     - ${type}: ${count}`);
  }
  console.log('');

  // Advanced: Time-based queries
  console.log('9. Advanced database queries...');

  // Get data from specific time window
  const recentTime = Date.now() - 120000; // Last 2 minutes
  const recentPackages = await repository.retrieveRange({
    startTime: recentTime,
    endTime: Date.now()
  });
  console.log(`   Recent packages (last 2 min): ${recentPackages.length}`);

  // Get all timestamps
  const allTimestamps = await repository.getAllTimestamps();
  console.log(`   Total unique timestamps: ${allTimestamps.length}`);

  // Get failed operations from audit log
  const failures = await auditLog.getFailedOperations(5);
  console.log(`   Failed operations: ${failures.length}\n`);

  // Cleanup
  console.log('10. Cleanup...');
  dataViewer.destroyAllKeys();
  console.log('   ✓ Destroyed decryption keys');

  // Optionally clear test data (uncomment if needed)
  // await repository.clear();
  // await auditLog.clear();
  // console.log('   ✓ Cleared test data from database');

  await prisma.$disconnect();
  console.log('   ✓ Database connection closed\n');

  console.log('=== Example Complete ===');
}

// Run the example
main().catch(async (error) => {
  console.error('Error:', error);
  process.exit(1);
});
