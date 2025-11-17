#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { MerkleFileOps } = require('./MerkleFileOps');
const { combineHashes } = require('./merkle-core'); 
const crypto = require('crypto');

// Get command line arguments
const args = process.argv.slice(2);
const mode = args[0]; // "coarse" or "fine"
const logId = args[1];
const logType = args[2];
const epochId = parseInt(args[3]);

const CONCAT_HASH_DIR = './concat_hashes';
const MERKLE_TRE_DIR = './merkletree';

/**
 * Hash function
 */
function hash(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * NEW: Find log metadata by SIEM_LogID
 */
function findLogMetadata(siemLogId) {
  const logDir = './Logs';
  
  if (!fs.existsSync(logDir)) {
    throw new Error(`Logs directory not found: ${logDir}`);
  }
  
  // Search all metadata files
  const files = fs.readdirSync(logDir).filter(f => f.endsWith('_LogMetadata.txt'));
  
  for (const file of files) {
    const filepath = path.join(logDir, file);
    const content = fs.readFileSync(filepath, 'utf8');
    const lines = content.split('\n');
    
    for (const line of lines) {
      if (line.includes('SIEM_LogID:')) {
        const match = line.match(/ID:\s*(\d+).*Type:\s*(\w+).*Epoch:\s*(\d+).*SIEM_LogID:\s*(\d+)/);
        if (match && match[4] === siemLogId.toString()) {
          return {
            logId: `log-${match[1]}`,
            logType: match[2].toLowerCase(),
            epochId: parseInt(match[3]),
            internalId: parseInt(match[1])
          };
        }
      }
    }
  }
  
  throw new Error(`SIEM_LogID ${siemLogId} not found in any metadata file`);
}

/**
 * FUNCTION 1: Coarse-grained verification (concat hash)
 */
function verifyCoarseGrained(rawLog) {
  const result = {
    valid: true,
    method: 'coarse',
    alert: null
  };

  try {
    // Step 1: Extract SIEM_LogID from raw log
    if (!rawLog.id) {
      throw new Error('Raw log must contain "id" field (SIEM_LogID)');
    }
    const siemLogId = rawLog.id;
    
    // Step 2: Find metadata (epoch, type, logId)
    const metadata = findLogMetadata(siemLogId);
    result.logId = metadata.logId;
    result.logType = metadata.logType;
    result.epochId = metadata.epochId;
    
    console.error(`Found metadata: ${JSON.stringify(metadata)}`);
    
    // Step 3: Hash the raw log
    const logId = `log-${siemLogId}`;
    const timestamp = rawLog.timestamp;
    const logType = rawLog.Type.toLowerCase();

    // Put all other fields into metadata (same as MerkleImporter does)
    const m = {};
    for (const [key, value] of Object.entries(rawLog)) {
    if (key=='message') {
        m[key] = value;
    }
    }

    // Create the SAME structure as merkle-core.js LogEntry.computeHash()
    const data = JSON.stringify({
    logId: logId,
    timestamp: timestamp,
    logType: logType,
    metadata: m
    });

    const computedHash = hash(data);
    result.computedHash = computedHash;

console.error(`Computed hash structure: logId=${logId}, timestamp=${timestamp}, logType=${logType}, metadata=${JSON.stringify(m)}`);
console.error(`Computed hash of raw log: ${computedHash}`);
    
    // Step 4: Read concat hash file
    const filename = `epoch_${metadata.logType}_${metadata.epochId}.txt`;
    const filepath = path.join(CONCAT_HASH_DIR, filename);

    if (!fs.existsSync(filepath)) {
      throw new Error(`Concat hash file not found: ${filepath}`);
    }

    const content = fs.readFileSync(filepath, 'utf8');
    const lines = content.split('\n');

    // Step 5: Parse all hash entries
    const entries = [];
    let storedConcatHash = null;

    for (const line of lines) {
      if (line.startsWith('{log id:')) {
        const idMatch = line.match(/log id: ([^,]+),/);
        const hashMatch = line.match(/hash value: ([^}]+)}/);
        if (idMatch && hashMatch) {
          entries.push({
            logId: idMatch[1].trim(),
            hash: hashMatch[1].trim()
          });
        }
      } else if (line.startsWith('hash value:')) {
        storedConcatHash = line.substring('hash value:'.length).trim();
      }
    }

    if (entries.length > 0) {
      result.logIdRange = `${entries[0].logId} to ${entries[entries.length - 1].logId}`;
    }

    // Step 6: Find target entry and replace hash with computed hash
    let targetFound = false;
    let storedHashForTarget = null;
    
    for (let i = 0; i < entries.length; i++) {
      if (entries[i].logId === metadata.logId) {
        storedHashForTarget = entries[i].hash;
        entries[i].hash = computedHash; // REPLACE with computed hash from raw log
        targetFound = true;
        break;
      }
    }

    if (!targetFound) {
      throw new Error(`Log ID ${metadata.logId} not found in concat hash file`);
    }
    
    result.storedHashForLog = storedHashForTarget;
    
    console.error(`Stored hash for ${metadata.logId}: ${storedHashForTarget}`);
    console.error(`Replaced with computed hash: ${computedHash}`);

    // Step 7: Recompute concat hash with new hash
    const concatenated = entries.map(e => e.hash).join('');
    const recomputedConcatHash = hash(concatenated);

    result.expectedConcatHash = storedConcatHash;
    result.actualConcatHash = recomputedConcatHash;

    console.error(`Expected concat hash: ${storedConcatHash}`);
    console.error(`Recomputed concat hash: ${recomputedConcatHash}`);

    // Step 8: Compare
    if (storedConcatHash !== recomputedConcatHash) {
      result.valid = false;
      
      // Create Alert 1
      result.alert = {
        rawL: rawLog,
        severity: 'WARNING',
        alertType: 'CONCAT_HASH_MISMATCH',
        epochId: metadata.epochId,
        logType: metadata.logType,
        logId: metadata.logId,
        siemLogId: siemLogId,
        logIdRange: result.logIdRange,
        message: `Tampering detected: Raw log hash doesn't match. Epoch ${metadata.epochId}, type ${metadata.logType}, range ${result.logIdRange}`,
        expectedConcatHash: storedConcatHash,
        actualConcatHash: recomputedConcatHash,
        storedHashForLog: storedHashForTarget,
        computedHashForLog: computedHash,
        timestamp: Date.now()
      };
    }

  } catch (error) {
    result.valid = false;
    result.error = error.message;
  }

  return result;
}

/**
 * FUNCTION 2: Fine-grained verification (Merkle proof)
 */
function verifyFineGrained(logId, logType, epochId, rawLog) {
  const result = {
    valid: true,
    method: 'fine',
    logId: logId,
    logType: logType,
    epochId: epochId,
    alert: null
  };
  
  try {
    // Step 1: Compute hash from raw log
    const m = {};
    for (const [key, value] of Object.entries(rawLog)) {
      if (key == 'message') {
        m[key] = value;
      }
    }

    const data = JSON.stringify({
      logId: "log-"+rawLog.id,
      timestamp: rawLog.timestamp,
      logType: rawLog.Type,
      metadata: m
    });

    const computedHash = hash(data);
    console.error(`[Fine] Computed hash from raw log: ${computedHash}`);

    // Step 2: Load saved file (JSON only, no tree rebuild)
    const merkleTreePath = path.join(MERKLE_TRE_DIR, `merklebatch_${epochId}`);

    if (!fs.existsSync(merkleTreePath)) {
      result.valid = false;
      result.error = `Merkle tree file not found: ${merkleTreePath}`;
      return result;
    }

    const savedData = JSON.parse(fs.readFileSync(merkleTreePath, 'utf8'));
    
    // Step 3: Find stored log and get FULL proof path
    let storedLog = null;
    
    if (savedData.subTrees && savedData.subTrees[logType]) {
      const subTreeData = savedData.subTrees[logType];
      storedLog = subTreeData.logs.find(log => log.logId === logId);
    }

    if (!storedLog) {
      result.valid = false;
      result.error = `Log ${logId} not found in saved tree`;
      return result;
    }

    if (!storedLog.subTreeProof || !storedLog.topLevelProof) {
      result.valid = false;
      result.error = `No complete proof path saved for log ${logId}`;
      return result;
    }

    console.error(`[Fine] Found stored log`);
    console.error(`[Fine] Sub-tree proof: ${storedLog.subTreeProof.length} steps`);
    console.error(`[Fine] Top-level proof: ${storedLog.topLevelProof.length} steps`);

    // Step 4: Recompute sub-tree root using raw log hash
    let currentHash = computedHash;
    
    console.error(`\n[Fine] === Recomputing Sub-Tree Root ===`);
    console.error(`[Fine] Starting with raw log hash: ${currentHash.substring(0,16)}...`);
    
    for (let i = 0; i < storedLog.subTreeProof.length; i++) {
      const step = storedLog.subTreeProof[i];
      const oldHash = currentHash;
      
      if (step.position === 'left') {
        currentHash = combineHashes(step.hash, currentHash);
      } else {
        currentHash = combineHashes(currentHash, step.hash);
      }
      
      console.error(`[Fine] Step ${i+1}: combine with ${step.hash.substring(0,8)}... (${step.position}) → ${currentHash.substring(0,8)}...`);
    }
    
    const recomputedSubTreeRoot = currentHash;
    console.error(`[Fine] Recomputed sub-tree root: ${recomputedSubTreeRoot}`);
    console.error(`[Fine] Expected sub-tree root:   ${storedLog.subTreeRoot}`);

    // Step 5: Check if sub-tree root matches
    if (recomputedSubTreeRoot !== storedLog.subTreeRoot) {
      result.valid = false;
      result.alert = {
        rawLog: data,
        severity: 'CRITICAL',
        alertType: 'LOG_TAMPERED',
        epochId: epochId,
        logType: logType,
        logId: logId,
        message: `CRITICAL: Raw log hash doesn't match - Log ${logId} was tampered`,
        computedHash: computedHash,
        storedHash: storedLog.hash,
        recomputedSubTreeRoot: recomputedSubTreeRoot,
        expectedSubTreeRoot: storedLog.subTreeRoot,
        timestamp: Date.now()
      };
      return result;
    }

    console.error(`[Fine] ✓ Sub-tree root matches!`);

    // Step 6: Recompute TOP-LEVEL root using sub-tree root
    currentHash = recomputedSubTreeRoot; // Start from sub-tree root
    
    console.error(`\n[Fine] === Recomputing Top-Level Root ===`);
    console.error(`[Fine] Starting with sub-tree root: ${currentHash.substring(0,16)}...`);
    
    for (let i = 0; i < storedLog.topLevelProof.length; i++) {
      const step = storedLog.topLevelProof[i];
      const oldHash = currentHash;
      
      if (step.position === 'left') {
        currentHash = combineHashes(step.hash, currentHash);
      } else {
        currentHash = combineHashes(currentHash, step.hash);
      }
      
      console.error(`[Fine] Step ${i+1}: combine with ${step.hash.substring(0,8)}... (${step.position}) → ${currentHash.substring(0,8)}...`);
    }
    
    const recomputedTopLevelRoot = currentHash;
    console.error(`[Fine] Recomputed top-level root: ${recomputedTopLevelRoot}`);
    console.error(`[Fine] Expected top-level root:   ${storedLog.topLevelRoot}`);
    console.error(`[Fine] Saved file root:           ${savedData.topLevelRootHash}`);

    // Step 7: Check if top-level root matches
    if (recomputedTopLevelRoot !== storedLog.topLevelRoot) {
      result.valid = false;
      result.alert = {
        rawLog: data,
        severity: 'CRITICAL',
        alertType: 'MERKLE_TREE_TAMPERED',
        epochId: epochId,
        logType: logType,
        logId: logId,
        message: `CRITICAL: Top-level Merkle root mismatch - Tree was tampered`,
        recomputedRoot: recomputedTopLevelRoot,
        expectedRoot: storedLog.topLevelRoot,
        timestamp: Date.now()
      };
      return result;
    }

    console.error(`[Fine] ✓ Top-level root matches! Verification complete.`);
    
    result.valid = true;
    result.recomputedRoot = recomputedTopLevelRoot;
    result.expectedRoot = storedLog.topLevelRoot;

  } catch (error) {
    result.valid = false;
    result.error = error.message;
    console.error('[Fine] Error:', error);
  }

  return result;
}

// Main execution
if (mode === 'coarse') {
  // Read raw log from stdin
  let rawLogJson = '';
  
  process.stdin.on('data', (chunk) => {
    rawLogJson += chunk;
  });
  
  process.stdin.on('end', () => {
    try {
      const rawLog = JSON.parse(rawLogJson.trim());
      const result = verifyCoarseGrained(rawLog);
      console.log(JSON.stringify(result));
    } catch (error) {
      console.log(JSON.stringify({
        valid: false,
        error: `Failed to parse raw log: ${error.message}`
      }));
    }
  });
  
} else if (mode === 'fine') {
  const logId = args[1];
  const logType = args[2];
  const epochId = parseInt(args[3]);
  let rawLogJson = '';
  
  process.stdin.on('data', (chunk) => {
    rawLogJson += chunk;
  });
  
  process.stdin.on('end', () => {
    try {
      const rawLog = JSON.parse(rawLogJson.trim());
      const result = verifyFineGrained(logId, logType, epochId, rawLog);
      console.log(JSON.stringify(result));
    } catch (error) {
      console.log(JSON.stringify({
        valid: false,
        error: `Failed to parse raw log: ${error.message}`
      }));
    }
  });

} else {
  console.log(JSON.stringify({
    valid: false,
    error: `Invalid mode: ${mode}. Use 'coarse' or 'fine'`
  }));
}