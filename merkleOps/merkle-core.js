// ============= FILE 1: merkle-core.js =============
// Core Merkle Tree data structures and building logic

const crypto = require('crypto');

// Utility function to create SHA-256 hash
function hash(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// Utility function to combine two hashes
function combineHashes(left, right) {
  return hash(left + right);
}

// Log Entry class - represents a single log with metadata
class LogEntry {
  constructor(logId, timestamp, logType, metadata = {}) {
    this.logId = logId;
    this.timestamp = timestamp;
    this.logType = logType;
    this.metadata = metadata;
    this.hash = this.computeHash();
  }

  computeHash() {
    const data = JSON.stringify({
      logId: this.logId,
      timestamp: this.timestamp,
      logType: this.logType,
      metadata: this.metadata
    });
    return hash(data);
  }
}

// Merkle Tree Node
class MerkleNode {
  constructor(hash, left = null, right = null, data = null) {
    this.hash = hash;
    this.left = left;
    this.right = right;
    this.data = data; // Only leaf nodes store actual data
  }

  isLeaf() {
    return this.left === null && this.right === null;
  }
}

// Sub Merkle Tree - represents one log type
class SubMerkleTree {
  constructor(logType) {
    this.logType = logType;
    this.logs = [];
    this.root = null;
  }

  verifyLogWithProof(log, rootHash) {
    let currentHash = log.hash;
    
    if (!log.proofPath) {
      return false; // No proof path saved
    }
    
    for (const step of log.proofPath) {
      if (step.position === 'left') {
        currentHash = combineHashes(step.hash, currentHash);
      } else {
        currentHash = combineHashes(currentHash, step.hash);
      }
    }
    
    return currentHash === rootHash;
  }

  // Generate concatenated hash file data
  generateConcatHashData(epochId) {
    const hashEntries = this.logs.map(log => ({
      logId: log.logId,
      hashValue: log.hash
    }));
    
    // Concatenate all hashes
    const concatenatedHashes = this.logs.map(log => log.hash).join('');
    const concatHash = hash(concatenatedHashes);
    
    return {
      entries: hashEntries,
      epochId: epochId,
      logType: this.logType,
      hashValue: concatHash
    };
  }

  // Add a log entry (will need to rebuild tree)
  addLog(logEntry) {
    if (logEntry.logType !== this.logType) {
      throw new Error(`Log type mismatch: expected ${this.logType}, got ${logEntry.logType}`);
    }
    this.logs.push(logEntry);
  }

  // Add multiple logs at once (more efficient)
  addLogs(logEntries) {
    for (const entry of logEntries) {
      this.addLog(entry);
    }
  }

  // Sort logs by timestamp (or logId, or other metadata)
  sortLogs(sortBy = 'timestamp') {
    this.logs.sort((a, b) => {
      if (sortBy === 'timestamp') {
        return a.timestamp - b.timestamp;
      } else if (sortBy === 'logId') {
        return a.logId.localeCompare(b.logId);
      }
      return 0;
    });
  }

  // Build the Merkle tree from logs
  buildTree() {
    if (this.logs.length === 0) {
      this.root = null;
      return;
    }

    // Sort logs before building tree
    this.sortLogs();

    // Create leaf nodes
    let nodes = this.logs.map(log => new MerkleNode(log.hash, null, null, log));

    // Build tree bottom-up
    while (nodes.length > 1) {
      const newLevel = [];
      
      for (let i = 0; i < nodes.length; i += 2) {
        const left = nodes[i];
        const right = i + 1 < nodes.length ? nodes[i + 1] : left; // Duplicate if odd
        
        const parentHash = combineHashes(left.hash, right.hash);
        const parentNode = new MerkleNode(parentHash, left, right);
        
        newLevel.push(parentNode);
      }
      
      nodes = newLevel;
    }

    this.root = nodes[0];
  }

  // Get the root hash of this sub-tree
  getRootHash() {
    return this.root ? this.root.hash : null;
  }

  // Get logs count
  getLogCount() {
    return this.logs.length;
  }

  // Find a log by logId
  findLog(logId) {
    return this.logs.find(log => log.logId === logId);
  }

  // Get logs in a timestamp range
  getLogsByTimeRange(startTime, endTime) {
    return this.logs.filter(log => 
      log.timestamp >= startTime && log.timestamp <= endTime
    );
  }
}

// Top-Level Merkle Tree - combines all sub-tree roots
class TopLevelMerkleTree {
  constructor() {
    this.subTrees = new Map(); // logType -> SubMerkleTree
    this.root = null;
  }

  computeRootFromProofs() {
  const subTreeRoots = [];
  
  // Get each sub-tree root from any log's proof
  for (const [logType, subTree] of this.subTrees.entries()) {
    if (subTree.logs.length > 0) {
      const firstLog = subTree.logs[0];
      if (firstLog.proofPath) {
        // Compute sub-tree root from first log's proof
        let hash = firstLog.hash;
        for (const step of firstLog.proofPath) {
          if (step.position === 'left') {
            hash = combineHashes(step.hash, hash);
          } else {
            hash = combineHashes(hash, step.hash);
          }
          }
          subTreeRoots.push(hash);
        }
      }
    }
    
    // Compute top-level root from sub-tree roots
    // (similar logic here)
    return this.computeRootFromHashes(subTreeRoots);
  }

  computeRootFromHashes(hashes) {
    if (hashes.length === 0) return null;
    if (hashes.length === 1) return hashes[0];
    
    let currentLevel = [...hashes];
    
    // Build tree bottom-up (same as buildTree, but only hashes)
    while (currentLevel.length > 1) {
      const nextLevel = [];
      
      for (let i = 0; i < currentLevel.length; i += 2) {
        const left = currentLevel[i];
        const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : left;
        
        const parentHash = combineHashes(left, right);
        nextLevel.push(parentHash);
      }
      
      currentLevel = nextLevel;
    }
    
    return currentLevel[0];
  }

  // Add a sub-tree for a specific log type
  addSubTree(logType) {
    if (!this.subTrees.has(logType)) {
      this.subTrees.set(logType, new SubMerkleTree(logType));
    }
    return this.subTrees.get(logType);
  }

  // Get a sub-tree by log type
  getSubTree(logType) {
    return this.subTrees.get(logType);
  }

  // Add a log entry (automatically routes to correct sub-tree)
  addLog(logEntry) {
    let subTree = this.subTrees.get(logEntry.logType);
    if (!subTree) {
      subTree = this.addSubTree(logEntry.logType);
    }
    subTree.addLog(logEntry);
  }

  // Add multiple logs at once (more efficient)
  addLogs(logEntries) {
    for (const entry of logEntries) {
      this.addLog(entry);
    }
  }

  // Build the entire two-level tree
  buildTree() {
    // First, build all sub-trees
    for (const subTree of this.subTrees.values()) {
      subTree.buildTree();
    }

    // Then build the top-level tree from sub-tree roots
    const subTreeRoots = Array.from(this.subTrees.values())
      .filter(subTree => subTree.root !== null)
      .map(subTree => new MerkleNode(subTree.getRootHash(), null, null, { logType: subTree.logType }));

    if (subTreeRoots.length === 0) {
      this.root = null;
      return;
    }

    let nodes = subTreeRoots;

    while (nodes.length > 1) {
      const newLevel = [];
      
      for (let i = 0; i < nodes.length; i += 2) {
        const left = nodes[i];
        const right = i + 1 < nodes.length ? nodes[i + 1] : left;
        
        const parentHash = combineHashes(left.hash, right.hash);
        const parentNode = new MerkleNode(parentHash, left, right);
        
        newLevel.push(parentNode);
      }
      
      nodes = newLevel;
    }

    this.root = nodes[0];
  }

  // Get the top-level root hash
  getRootHash() {
    return this.root ? this.root.hash : null;
  }

  // Get total log count across all sub-trees
  getTotalLogCount() {
    let total = 0;
    for (const subTree of this.subTrees.values()) {
      total += subTree.getLogCount();
    }
    return total;
  }

  // Get statistics
  getStatistics() {
    const stats = {
      totalLogs: this.getTotalLogCount(),
      subTreeCount: this.subTrees.size,
      rootHash: this.getRootHash(),
      subTrees: {}
    };

    for (const [logType, subTree] of this.subTrees.entries()) {
      stats.subTrees[logType] = {
        logCount: subTree.getLogCount(),
        rootHash: subTree.getRootHash()
      };
    }

    return stats;
  }

  // Pretty print the tree structure
  printTree() {
    console.log('\n=== TWO-LEVEL MERKLE TREE ===\n');
    console.log(`Top-Level Root: ${this.getRootHash()}`);
    console.log(`Total Logs: ${this.getTotalLogCount()}\n`);
    
    for (const [logType, subTree] of this.subTrees.entries()) {
      console.log(`\n--- Sub-Tree: ${logType} ---`);
      console.log(`Root: ${subTree.getRootHash()}`);
      console.log(`Log Count: ${subTree.logs.length}`);
      if (subTree.logs.length <= 10) {
        console.log('Logs:');
        subTree.logs.forEach(log => {
          console.log(`  - [${log.logId}] t:${log.timestamp} | ${JSON.stringify(log.metadata)}`);
        });
      } else {
        console.log('Logs: (showing first 5 and last 5)');
        for (let i = 0; i < 5; i++) {
          const log = subTree.logs[i];
          console.log(`  - [${log.logId}] t:${log.timestamp} | ${JSON.stringify(log.metadata)}`);
        }
        console.log('  ...');
        for (let i = subTree.logs.length - 5; i < subTree.logs.length; i++) {
          const log = subTree.logs[i];
          console.log(`  - [${log.logId}] t:${log.timestamp} | ${JSON.stringify(log.metadata)}`);
        }
      }
    }
    console.log('\n=============================\n');
  }
}

module.exports = {
  LogEntry,
  MerkleNode,
  SubMerkleTree,
  TopLevelMerkleTree,
  hash,
  combineHashes
};
