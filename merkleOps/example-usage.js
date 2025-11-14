// ============= example-usage.js (FIXED) =============
// Example usage and performance testing

const { LogEntry, TopLevelMerkleTree } = require('./merkle-core');
const { MerkleProofGenerator, MerkleProofVerifier } = require('./merkle-proof');
const { MerkleSearch } = require('./merkle-search');

// Performance test function
function performanceTest() {
  console.log('\n=== PERFORMANCE TEST ===\n');

  const logCounts = [100, 1000, 10000];

  for (const count of logCounts) {
    console.log(`\nTesting with ${count.toLocaleString()} logs...`);

    // Create a fresh tree for each test
    const tree = new TopLevelMerkleTree();
    
    // Generate logs
    const start = Date.now();
    
    for (let i = 0; i < count; i++) {
      const logType = ['auth', 'api', 'error', 'system'][i % 4];
      tree.addLog(new LogEntry(
        `log-${i}`,
        1000 + i,
        logType,
        { index: i, data: `sample-data-${i}` }
      ));
    }
    
    const genTime = Date.now() - start;
    console.log(`  Log generation: ${genTime}ms`);

    // Build tree
    const startBuild = Date.now();
    tree.buildTree();
    const buildTime = Date.now() - startBuild;
    console.log(`  Building tree: ${buildTime}ms`);

    // Generate proof - FIXED: Use a logId that actually exists
    const startProof = Date.now();
    const testLogId = 'log-96';
    const testLogType = 'auth'; // log-100 % 4 = 0, so it's 'auth'
    
    // Verify the log exists before generating proof
    const logExists = MerkleSearch.findLogById(tree, testLogId, testLogType);
    
    if (!logExists) {
      console.log(`  ERROR: Log ${testLogId} not found in type ${testLogType}`);
      // Find which type it's actually in
      for (const type of ['auth', 'api', 'error', 'system']) {
        const found = MerkleSearch.findLogById(tree, testLogId, type);
        if (found) {
          console.log(`  Found in type: ${type}`);
          break;
        }
      }
      continue;
    }

    const proof = MerkleProofGenerator.generateFullProof(tree, testLogId, testLogType);
    const proofTime = Date.now() - startProof;
    
    if (!proof) {
      console.log(`  ERROR: Failed to generate proof for ${testLogId}`);
      continue;
    }
    
    console.log(`  Proof generation: ${proofTime}ms`);

    // Verify proof
    const startVerify = Date.now();
    const result = MerkleProofVerifier.verifyFullProof(proof);
    const verifyTime = Date.now() - startVerify;
    console.log(`  Proof verification: ${verifyTime}ms`);
    console.log(`  Proof valid: ${result.valid}`);

    // Memory usage
    const memUsage = process.memoryUsage();
    console.log(`  Memory (heap used): ${(memUsage.heapUsed / 1024 / 1024).toFixed(2)} MB`);
  }
}

// Basic usage example
function basicExample() {
  console.log('\n=== BASIC USAGE EXAMPLE ===\n');

  const tree = new TopLevelMerkleTree();

  // Add logs
  tree.addLog(new LogEntry('auth-1', 1000, 'auth', { action: 'login', user: 'alice' }));
  tree.addLog(new LogEntry('auth-2', 1005, 'auth', { action: 'logout', user: 'alice' }));
  tree.addLog(new LogEntry('api-1', 2000, 'api', { method: 'GET', endpoint: '/users' }));
  tree.addLog(new LogEntry('api-2', 2001, 'api', { method: 'POST', endpoint: '/users' }));

  // Build tree
  tree.buildTree();
  tree.printTree();

  // Search operations
  console.log('=== SEARCH OPERATIONS ===\n');
  
  const log = MerkleSearch.findLogById(tree, 'auth-1');
  console.log('Found log:', log);

  const authLogs = MerkleSearch.getLogsByType(tree, 'auth');
  console.log(`\nAuth logs count: ${authLogs.length}`);

  const latest = MerkleSearch.getLatestLogs(tree, 2);
  console.log('\nLatest 2 logs:', latest.map(l => l.logId));

  // Generate and verify proof
  console.log('\n=== PROOF GENERATION & VERIFICATION ===\n');
  
  const proof = MerkleProofGenerator.generateFullProof(tree, 'auth-1', 'auth');
  
  if (proof) {
    console.log('Proof generated for auth-1');
    console.log('Proof size (sub-tree):', proof.subTreeProof.length, 'hashes');
    console.log('Proof size (top-level):', proof.topLevelProof.length, 'hashes');
    
    const verification = MerkleProofVerifier.verifyFullProof(proof);
    console.log(`Verification result: ${verification.valid}`);
    console.log(`Reason: ${verification.reason}`);
  } else {
    console.log('ERROR: Failed to generate proof');
  }
}

// Range query example
function rangeQueryExample() {
  console.log('\n=== RANGE QUERY EXAMPLE ===\n');

  const tree = new TopLevelMerkleTree();

  // Add logs with different timestamps
  for (let i = 0; i < 20; i++) {
    tree.addLog(new LogEntry(
      `log-${i}`,
      1000 + (i * 100), // timestamps: 1000, 1100, 1200, ...
      'auth',
      { index: i }
    ));
  }

  tree.buildTree();

  // Query logs between timestamps 1200 and 1600
  const logsInRange = MerkleSearch.findLogsByTimeRange(tree, 1200, 1600, 'auth');
  console.log(`Found ${logsInRange.length} logs between t:1200 and t:1600`);
  logsInRange.forEach(log => {
    console.log(`  - ${log.logId}: t:${log.timestamp}`);
  });
}

// Pagination example
function paginationExample() {
  console.log('\n=== PAGINATION EXAMPLE ===\n');

  const tree = new TopLevelMerkleTree();

  // Add 50 logs
  for (let i = 0; i < 50; i++) {
    tree.addLog(new LogEntry(`log-${i}`, 1000 + i, 'auth', { index: i }));
  }

  tree.buildTree();

  // Get page 2 (page size 10)
  const page = MerkleSearch.getLogsPaginated(tree, 1, 10, 'auth');
  console.log(`Page ${page.page + 1} of ${page.totalPages}`);
  console.log(`Showing ${page.logs.length} of ${page.totalLogs} total logs`);
  console.log('\nLogs on this page:');
  page.logs.forEach(log => {
    console.log(`  - ${log.logId}: t:${log.timestamp}`);
  });
}

// Metadata search example
function metadataSearchExample() {
  console.log('\n=== METADATA SEARCH EXAMPLE ===\n');

  const tree = new TopLevelMerkleTree();

  // Add logs with different users
  tree.addLog(new LogEntry('log-1', 1000, 'auth', { user: 'alice', action: 'login' }));
  tree.addLog(new LogEntry('log-2', 1001, 'auth', { user: 'bob', action: 'login' }));
  tree.addLog(new LogEntry('log-3', 1002, 'auth', { user: 'alice', action: 'logout' }));
  tree.addLog(new LogEntry('log-4', 1003, 'api', { user: 'alice', method: 'GET' }));
  tree.addLog(new LogEntry('log-5', 1004, 'auth', { user: 'bob', action: 'logout' }));

  tree.buildTree();

  // Find all logs for user 'alice'
  const aliceLogs = MerkleSearch.findLogsByMetadata(tree, 'user', 'alice');
  console.log(`Found ${aliceLogs.length} logs for user 'alice':`);
  aliceLogs.forEach(log => {
    console.log(`  - ${log.logId} (${log.logType}): ${JSON.stringify(log.metadata)}`);
  });

  // Find all logs for user 'alice' in 'auth' logs only
  const aliceAuthLogs = MerkleSearch.findLogsByMetadata(tree, 'user', 'alice', 'auth');
  console.log(`\nFound ${aliceAuthLogs.length} auth logs for user 'alice':`);
  aliceAuthLogs.forEach(log => {
    console.log(`  - ${log.logId}: ${JSON.stringify(log.metadata)}`);
  });
}

// Count by type example
function countByTypeExample() {
  console.log('\n=== COUNT BY TYPE EXAMPLE ===\n');

  const tree = new TopLevelMerkleTree();

  // Add mixed logs
  for (let i = 0; i < 100; i++) {
    const types = ['auth', 'api', 'error', 'system'];
    const type = types[i % types.length];
    tree.addLog(new LogEntry(`log-${i}`, 1000 + i, type, { index: i }));
  }

  tree.buildTree();

  const counts = MerkleSearch.countByType(tree);
  console.log('Log counts by type:');
  for (const [type, count] of Object.entries(counts)) {
    console.log(`  ${type}: ${count}`);
  }
}

// Run all examples
console.log('\n╔════════════════════════════════════════╗');
console.log('║  Two-Level Merkle Tree - Examples     ║');
console.log('╚════════════════════════════════════════╝');

basicExample();
rangeQueryExample();
paginationExample();
metadataSearchExample();
countByTypeExample();
performanceTest();

console.log('\n✅ All examples completed!\n');