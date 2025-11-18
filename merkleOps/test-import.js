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
//const epoch = 1;
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
<<<<<<< Updated upstream
);
=======
);

const path = require('path');

/**
 * Extract concat hash from: epoch_logtype_epochid.txt
 */
function extractConcatHash(logType, epochId) {
    const filepath = `./concat_hashes/epoch_${logType}_${epochId}.txt`;
    const content = fs.readFileSync(filepath, 'utf8');
    
    const lines = content.split('\n');
    for (const line of lines) {
        if (line.trim().startsWith('hash value:')) {
            return line.substring(line.indexOf(':') + 1).trim();
        }
    }
    
    throw new Error('Hash not found');
}

/**
 * Extract top-level root hash from: merklebatch_epochid
 */
function extractTopLevelRootHash(epochId) {
    const filepath = `./merkletree/merklebatch_${epochId}`;
    const content = fs.readFileSync(filepath, 'utf8');
    
    const json = JSON.parse(content);
    return json.topLevelRootHash;
}

/**
 * Get all log types in an epoch
 */
function getLogTypesInEpoch(epochId) {
    const filepath = `./merkletree/merklebatch_${epochId}`;
    const content = fs.readFileSync(filepath, 'utf8');
    
    const json = JSON.parse(content);
    return Object.keys(json.subTrees);
}

/**
 * Extract all concat hashes for all log types in an epoch
 */
function extractAllConcatHashes(epochId) {
    const logTypes = getLogTypesInEpoch(epochId);
    const hashes = {};
    let h = "";
    for (const logType of logTypes) {
        hashes[logType] = extractConcatHash(logType, epochId);
        h += extractConcatHash(logType, epochId);
        h += " |";
    }

    return h;
}

/**
 * Extract complete epoch data
 */
function extractEpochData(epochId) {
    return {
        epochId: epochId,
        topLevelRootHash: extractTopLevelRootHash(epochId),
        concatHashes: extractAllConcatHashes(epochId)
    };
}

// Test
const topRoot = extractTopLevelRootHash(epoch);
const allHashes = extractAllConcatHashes(epoch);
const fullData = extractEpochData(epoch);

console.log('Top-Level Root:', topRoot);
console.log('Concat Hashes:', allHashes);
console.log('Full Data:', fullData);

// Assuming your setup from before:
const Web3 = require('web3').default; 
const w3 = new Web3('http://127.0.0.1:7545'); 
const contractAddress = '0x0Cd2218A869Ff19eBdf926cCa979801c0e6FA16f'; 
const contractABI = [
	{
		"inputs": [],
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": true,
				"internalType": "uint256",
				"name": "epochId",
				"type": "uint256"
			},
			{
				"indexed": false,
				"internalType": "string",
				"name": "rootHash",
				"type": "string"
			},
			{
				"indexed": false,
				"internalType": "string",
				"name": "batchHash",
				"type": "string"
			},
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			},
			{
				"indexed": false,
				"internalType": "address",
				"name": "submitter",
				"type": "address"
			}
		],
		"name": "EpochFinalized",
		"type": "event"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "epochId",
				"type": "uint256"
			},
			{
				"internalType": "string",
				"name": "root",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "batch",
				"type": "string"
			}
		],
		"name": "finalizeEpoch",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "owner",
		"outputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
];

const contractInstance = new w3.eth.Contract(contractABI, contractAddress);

// --- New Function to Execute the Contract ---

async function runFinalizeEpoch() {
    // 1. Define the Sender Account (must be one of your Ganache accounts)
    //const accounts = await w3.eth.getAccounts();
    const senderAddress = '0x70422d37F1A5D32D72437b3ca911248DB89Bd77e'; // Use the first account in Ganache

    // 2. Define the Function Parameters (based on your ABI)
    //const epochId = 101; 
    //const rootHash = "0xabcdef1234567890abcdef1234567890abcdef1234567890"; // Example string

    console.log(`Sending transaction to finalize Epoch ID ${epoch}...`);

    try {
        // 3. Construct and Send the Transaction
        const receipt = await contractInstance.methods.finalizeEpoch(epoch, topRoot, allHashes)
            .send({
                from: senderAddress,
                gas: 300000 // You may need to adjust this gas limit
            });

        // 4. Log Results
        console.log("✅ Transaction successful!");
        console.log(`Transaction Hash: ${receipt.transactionHash}`);
        console.log(`Block Number: ${receipt.blockNumber}`);
        
        // This confirms your event was created:
        console.log(`Events Logged: ${receipt.events.EpochFinalized ? 'YES' : 'NO'}`);
        
        // Optional: Disconnect from the provider to clear up listeners
        if (w3.currentProvider.disconnect) {
            w3.currentProvider.disconnect();
        }

        return receipt;

    } catch (error) {
        console.error("Transaction failed:", error.message);
    }
}

// Execute the function
runFinalizeEpoch();
>>>>>>> Stashed changes
