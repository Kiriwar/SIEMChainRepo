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

console.log('\n=== VERIFYING SAVED PROOFS ===\n');

// Load the saved file and check if proofs exist
const { MerklePersistence } = require('./merkle-persistence');

const savedData = JSON.parse(fs.readFileSync(merkletreePath, 'utf8'));

// Check if first log has proofPath
for (const [logType, subTreeData] of Object.entries(savedData.subTrees)) {
  if (subTreeData.logs.length > 0) {
    const firstLog = subTreeData.logs[0];
    if (firstLog.proofPath) {
      console.log(`✓ ${logType}: Proofs saved! (${firstLog.proofPath.length} hashes)`);
    } else {
      console.log(`✗ ${logType}: No proofs saved!`);
    }
  }
  break; // Just check first sub-tree
}

console.log('\n=== SAVING CONCAT HASH FILES ===\n');

const concatResults = MerklePersistence.saveConcatHashFiles(
  result.tree, 
  epoch,
  './concat_hashes'
);