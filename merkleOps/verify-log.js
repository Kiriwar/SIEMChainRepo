#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { MerkleFileOps } = require('./MerkleFileOps');
const crypto = require('crypto');

// Get command line arguments
const args = process.argv.slice(2);
const mode = args[0]; // "coarse" or "fine"
const logId = args[1];
const logType = args[2];
const epochId = parseInt(args[3]);

const CONCAT_HASH_DIR = './concat_hashes';
const MERKLE_TREE_DIR = './merkletree';

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
function verifyFineGrained(logId, logType, epochId) {
  const result = {
    valid: true,
    method: 'fine',
    logId: logId,
    logType: logType,
    epochId: epochId,
    alert: null
  };

  try {
    const merkleTreePath = path.join(MERKLE_TRE_DIR, `merklebatch_${epochId}`);

    if (!fs.existsSync(merkleTreePath)) {
      result.valid = false;
      result.error = `Merkle tree file not found: ${merkleTreePath}`;
      return result;
    }

    // Use existing MerkleFileOps
    const proof = MerkleFileOps.generateAndVerifyProof(merkleTreePath, logId, logType);

    if (!proof) {
      result.valid = false;
      result.error = 'Failed to generate proof - log may not exist';
      return result;
    }

    result.merkleProof = {
      leafHash: proof.proof.leafHash,
      subTreeRoot: proof.proof.subTreeRoot,
      topLevelRoot: proof.proof.topLevelRoot
    };

    // Check verification
    if (!proof.verification.valid) {
      result.valid = false;
      
      // Create Alert 2
      result.alert = {
        severity: 'CRITICAL',
        alertType: 'LOG_TAMPERED',
        epochId: epochId,
        logType: logType,
        logId: logId,
        message: `CRITICAL: Log ${logId} in epoch ${epochId} (type ${logType}) has been tampered`,
        expectedHash: proof.proof.leafHash,
        timestamp: Date.now()
      };
    }

  } catch (error) {
    result.valid = false;
    result.error = error.message;
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
  const result = verifyFineGrained(logId, logType, epochId);
  console.log(JSON.stringify(result));
} else {
  console.log(JSON.stringify({
    valid: false,
    error: `Invalid mode: ${mode}. Use 'coarse' or 'fine'`
  }));
}