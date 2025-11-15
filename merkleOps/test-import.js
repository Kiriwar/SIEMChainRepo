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