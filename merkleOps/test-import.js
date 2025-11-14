// ============= test-import.js =============
// Test importing logs from your JSON format

const fs = require('fs');
const { MerkleImporter } = require('./MerkleImporter');
const { MerkleFileOps } = require('./MerkleFileOps');

// First, let's create a sample input file in your format


// Create sample input file
//if (!fs.existsSync('./data')) {
  //fs.mkdirSync('./data', { recursive: true });
//}
//fs.writeFileSync('./data/input-logs.json', sampleLogs, 'utf8');
//console.log('✓ Created sample input file: ./data/input-logs.json\n');

// ===========================
// Test 1: Basic Import
// ===========================
const epoch = parseInt(process.argv[2]);
console.log('=== TEST 1: BASIC IMPORT ===\n');

fpath = `./Logs/logs_batch_${epoch}.json`;
merkletreePath = `./merkletree/merklebatch_${epoch}`;

const result = MerkleImporter.importAndAnalyze(`${fpath}`);

console.log('Tree Details:');
result.tree.printTree();

console.log('\n===IMPORT & SAVE (ONE STEP) ===\n');

MerkleImporter.importAndSave(
  fpath,
  merkletreePath
);

console.log('\n=== SAVING CONCAT HASH FILES ===\n');

const { MerklePersistence } = require('./merkle-persistence');
const concatResults = MerklePersistence.saveConcatHashFiles(
  result.tree, 
  epoch,
  './concat_hashes'
);

// ===========================
// Test 2: Search Imported Logs
// ===========================
/*
console.log('\n=== TEST 2: SEARCH IMPORTED LOGS ===\n');

// Find a specific log
console.log('search by ID and type');
MerkleFileOps.searchById(merkletreePath, 'log-5', 'auth');
console.log('search by TimeStamp')
MerkleFileOps.searchByTimeRange(merkletreePath, 1762767503110, 1762767503120);

// ===========================
// Test 3: Generate Proof
// ===========================
console.log('\n=== TEST 3: GENERATE & VERIFY PROOF ===\n');

const prof = MerkleFileOps.generateAndVerifyProof(merkletreePath, 'log-5', 'auth');

if (prof) {
  console.log('✓ Proof generated for log-5');
  console.log('  Log:', prof.proof.logId);
  console.log('  Type:', prof.proof.logType);
  console.log('  Timestamp:', prof.proof.timestamp);
  console.log('  Metadata:', prof.proof.metadata);
  console.log('  Sub-tree proof size:', prof.proof.subTreeProof.length, 'hashes');
  console.log('  Top-level proof size:', prof.proof.topLevelProof.length, 'hashes');
  
  //const verification = MerkleProofVerifier.verifyFullProof(proof);
  console.log('\n✓ Verification:', prof.verification.valid);
  console.log('  Reason:', prof.verification.reason);
} else {
  console.log('✗ Failed to generate proof');
}
*/
// ===========================
// Test 4: Save Imported Tree
// ===========================
/*
console.log('\n=== TEST 4: SAVE IMPORTED TREE ===\n');

const saveResult = MerklePersistence.saveToFile(
  result.tree,
  './data/imported-merkle-tree.json'
);
console.log('✓ Saved imported tree');
console.log('  File:', saveResult.filepath);
console.log('  Size:', MerklePersistence.formatBytes(saveResult.size));
console.log('  Logs:', saveResult.logCount);
*/
// ===========================
// Test 5: Import and Save in One Step
// ===========================


// ===========================
// Test 6: Validate File Format
// ===========================
console.log('=== TEST 6: VALIDATE FILE FORMAT ===');

MerkleImporter.validateFile(fpath);

// ===========================
// Test 7: Create Multiple Input Files and Batch Import
// ===========================
/*console.log('=== TEST 7: BATCH IMPORT ===\n');

// Create additional sample files
const sampleLogs2 = `[
  {"id":9,"timestamp":1762767503130,"Type":"firewall","message":"Batch log 1"},
  {"id":10,"timestamp":1762767503135,"Type":"auth","message":"Batch log 2"}
]`;

const sampleLogs3 = `[
  {"id":11,"timestamp":1762767503140,"Type":"api","message":"Batch log 3"},
  {"id":12,"timestamp":1762767503145,"Type":"firewall","message":"Batch log 4"}
]`;

fs.writeFileSync('./data/input-logs-2.json', sampleLogs2, 'utf8');
fs.writeFileSync('./data/input-logs-3.json', sampleLogs3, 'utf8');

const batchResult = MerkleImporter.importMultipleFiles([
  './data/input-logs.json',
  './data/input-logs-2.json',
  './data/input-logs-3.json'
]);

console.log('Batch tree statistics:');
console.log('  Total logs:', batchResult.tree.getTotalLogCount());
console.log('  Root hash:', batchResult.rootHash);

// ===========================
// Summary
// ===========================
console.log('\n=== SUMMARY ===\n');
console.log('✅ All import tests completed!');
console.log('\nFiles created:');
console.log('  - ./data/input-logs.json          (your format)');
console.log('  - ./data/imported-merkle-tree.json (Merkle format)');
console.log('  - ./data/quick-import.json        (quick import result)');
console.log('\nYou can now:');
console.log('  1. Use MerkleImporter.importFromFile() to load your logs');
console.log('  2. Search, query, and verify proofs');
console.log('  3. Save in Merkle format for faster loading');
console.log();*/