// ============= merkle-file-ops.js =============
// Search and verify operations on saved Merkle tree files

const { MerklePersistence } = require('./merkle-persistence');
const { MerkleSearch } = require('./merkle-search');
const { MerkleProofGenerator, MerkleProofVerifier } = require('./merkle-proof');

class MerkleFileOps {
  
  /**
   * Search for a log by ID in a saved Merkle tree file
   */
  static searchById(filepath, logId, logType = null) {
    console.log(`\n=== SEARCHING IN FILE: ${filepath} ===\n`);
    
    // Load tree from file
    const tree = MerklePersistence.loadFromFile(filepath);
    
    // Search
    const log = MerkleSearch.findLogById(tree, logId, logType);
    
    if (log) {
      console.log('✓ Log found:');
      console.log('  LogId:', log.logId);
      console.log('  Timestamp:', log.timestamp);
      console.log('  Type:', log.logType);
      console.log('  Metadata:', JSON.stringify(log.metadata, null, 2));
      console.log('  Hash:', log.hash);
    } else {
      console.log('✗ Log not found');
    }
    
    return log;
  }

  /**
   * Search logs by time range in a saved file
   */
  static searchByTimeRange(filepath, startTime, endTime, logType = null) {
    console.log(`\n=== SEARCHING TIME RANGE IN FILE: ${filepath} ===\n`);
    console.log(`Time range: ${startTime} - ${endTime}`);
    if (logType) {
      console.log(`Log type: ${logType}`);
    }
    console.log();
    
    // Load tree from file
    const tree = MerklePersistence.loadFromFile(filepath);
    
    // Search
    const logs = MerkleSearch.findLogsByTimeRange(tree, startTime, endTime, logType);
    
    console.log(`✓ Found ${logs.length} logs:\n`);
    logs.forEach(log => {
      console.log(`  - ${log.logId} (${log.logType}): t=${log.timestamp}`);
      console.log(`    ${JSON.stringify(log.metadata)}`);
    });
    
    return logs;
  }

  /**
   * Search logs by metadata field in a saved file
   */
  static searchByMetadata(filepath, fieldName, fieldValue, logType = null) {
    console.log(`\n=== SEARCHING BY METADATA IN FILE: ${filepath} ===\n`);
    console.log(`Field: ${fieldName} = ${fieldValue}`);
    if (logType) {
      console.log(`Log type: ${logType}`);
    }
    console.log();
    
    // Load tree from file
    const tree = MerklePersistence.loadFromFile(filepath);
    
    // Search
    const logs = MerkleSearch.findLogsByMetadata(tree, fieldName, fieldValue, logType);
    
    console.log(`✓ Found ${logs.length} logs:\n`);
    logs.forEach(log => {
      console.log(`  - ${log.logId} (${log.logType})`);
      console.log(`    ${JSON.stringify(log.metadata)}`);
    });
    
    return logs;
  }

  /**
   * Get logs by type from a saved file
   */
  static getLogsByType(filepath, logType) {
    console.log(`\n=== GETTING LOGS BY TYPE FROM FILE: ${filepath} ===\n`);
    console.log(`Type: ${logType}\n`);
    
    // Load tree from file
    const tree = MerklePersistence.loadFromFile(filepath);
    
    // Get logs
    const logs = MerkleSearch.getLogsByType(tree, logType);
    
    console.log(`✓ Found ${logs.length} ${logType} logs:\n`);
    logs.forEach(log => {
      console.log(`  - ${log.logId}: t=${log.timestamp}`);
    });
    
    return logs;
  }

  /**
   * Get latest N logs from a saved file
   */
  static getLatestLogs(filepath, count, logType = null) {
    console.log(`\n=== GETTING LATEST LOGS FROM FILE: ${filepath} ===\n`);
    console.log(`Count: ${count}`);
    if (logType) {
      console.log(`Type: ${logType}`);
    }
    console.log();
    
    // Load tree from file
    const tree = MerklePersistence.loadFromFile(filepath);
    
    // Get latest logs
    const logs = MerkleSearch.getLatestLogs(tree, count, logType);
    
    console.log(`✓ Latest ${logs.length} logs:\n`);
    logs.forEach(log => {
      console.log(`  - ${log.logId} (${log.logType}): t=${log.timestamp}`);
      console.log(`    ${JSON.stringify(log.metadata)}`);
    });
    
    return logs;
  }

  /**
   * Generate proof for a log in a saved file
   */
  static generateProof(filepath, logId, logType) {
    console.log(`\n=== GENERATING PROOF FROM FILE: ${filepath} ===\n`);
    console.log(`LogId: ${logId}`);
    console.log(`Type: ${logType}\n`);
    
    // Load tree from file
    const tree = MerklePersistence.loadFromFile(filepath);
    
    // Generate proof
    const proof = MerkleProofGenerator.generateFullProof(tree, logId, logType);
    
    if (proof) {
      console.log('✓ Proof generated successfully\n');
      console.log('Proof details:');
      console.log('  LogId:', proof.logId);
      console.log('  Type:', proof.logType);
      console.log('  Timestamp:', proof.timestamp);
      console.log('  Leaf hash:', proof.leafHash);
      console.log('  Sub-tree root:', proof.subTreeRoot);
      console.log('  Sub-tree proof size:', proof.subTreeProof.length, 'hashes');
      console.log('  Top-level root:', proof.topLevelRoot);
      console.log('  Top-level proof size:', proof.topLevelProof.length, 'hashes');
      console.log('  Total proof size:', proof.subTreeProof.length + proof.topLevelProof.length, 'hashes');
    } else {
      console.log('✗ Failed to generate proof');
    }
    
    return proof;
  }

  /**
   * Verify a proof against a saved file's root
   */
  static verifyProof(filepath, proof) {
    console.log(`\n=== VERIFYING PROOF AGAINST FILE: ${filepath} ===\n`);
    
    // Load tree from file
    const tree = MerklePersistence.loadFromFile(filepath);
    
    // Get expected root hash
    const expectedRoot = tree.getRootHash();
    console.log('Expected root hash:', expectedRoot);
    console.log('Proof root hash:', proof.topLevelRoot);
    console.log();
    
    // Verify proof
    const result = MerkleProofVerifier.verifyAgainstRoot(proof, expectedRoot);
    
    if (result.valid) {
      console.log('✅ PROOF VALID');
      console.log('  Reason:', result.reason);
    } else {
      console.log('❌ PROOF INVALID');
      console.log('  Reason:', result.reason);
    }
    
    return result;
  }

  /**
   * Generate and verify proof in one operation
   */
  static generateAndVerifyProof(filepath, logId, logType) {
    console.log(`\n=== GENERATE & VERIFY PROOF FROM FILE: ${filepath} ===\n`);
    
    // Load tree from file
    const tree = MerklePersistence.loadFromFile(filepath);
    
    // Find the log first
    const log = MerkleSearch.findLogById(tree, logId, logType);
    if (!log) {
      console.log(`✗ Log ${logId} not found in type ${logType}`);
      return null;
    }
    
    console.log('✓ Log found:', log.logId);
    console.log('  Type:', log.logType);
    console.log('  Timestamp:', log.timestamp);
    console.log('  Metadata:', JSON.stringify(log.metadata));
    console.log();
    
    // Generate proof
    console.log('Generating proof...');
    const proof = MerkleProofGenerator.generateFullProof(tree, logId, logType);
    
    if (!proof) {
      console.log('✗ Failed to generate proof');
      return null;
    }
    
    console.log('✓ Proof generated');
    console.log('  Sub-tree proof size:', proof.subTreeProof.length, 'hashes');
    console.log('  Top-level proof size:', proof.topLevelProof.length, 'hashes');
    console.log();
    
    // Verify proof
    console.log('Verifying proof...');
    const verification = MerkleProofVerifier.verifyFullProof(proof);
    
    if (verification.valid) {
      console.log('✅ PROOF VALID');
      console.log('  Reason:', verification.reason);
    } else {
      console.log('❌ PROOF INVALID');
      console.log('  Reason:', verification.reason);
    }
    
    return {
      log,
      proof,
      verification
    };
  }

  /**
   * Get statistics from a saved file without loading full tree
   */
  static getFileStatistics(filepath) {
    console.log(`\n=== FILE STATISTICS: ${filepath} ===\n`);
    
    // Get file info (quick, doesn't load full tree)
    const fileInfo = MerklePersistence.getFileInfo(filepath);
    
    console.log('File Information:');
    console.log('  Path:', fileInfo.filepath);
    console.log('  Size:', fileInfo.sizeFormatted);
    console.log('  Version:', fileInfo.version);
    console.log('  Created:', fileInfo.timestamp);
    console.log('  Modified:', fileInfo.modified);
    console.log();
    
    console.log('Tree Information:');
    console.log('  Total logs:', fileInfo.logCount);
    console.log('  Sub-trees:', fileInfo.subTreeCount);
    console.log('  Root hash:', fileInfo.rootHash);
    console.log();
    
    // Load tree for detailed stats
    const tree = MerklePersistence.loadFromFile(filepath);
    const stats = tree.getStatistics();
    
    console.log('Logs by Type:');
    for (const [logType, info] of Object.entries(stats.subTrees)) {
      console.log(`  - ${logType}: ${info.logCount} logs (root: ${info.rootHash.substring(0, 16)}...)`);
    }
    console.log();
    
    return {
      fileInfo,
      treeStats: stats
    };
  }

  /**
   * Compare two saved Merkle tree files
   */
  static compareFiles(filepath1, filepath2) {
    console.log(`\n=== COMPARING FILES ===\n`);
    console.log(`File 1: ${filepath1}`);
    console.log(`File 2: ${filepath2}\n`);
    
    const tree1 = MerklePersistence.loadFromFile(filepath1);
    const tree2 = MerklePersistence.loadFromFile(filepath2);
    
    const root1 = tree1.getRootHash();
    const root2 = tree2.getRootHash();
    const count1 = tree1.getTotalLogCount();
    const count2 = tree2.getTotalLogCount();
    
    console.log('File 1:');
    console.log('  Logs:', count1);
    console.log('  Root:', root1);
    console.log();
    
    console.log('File 2:');
    console.log('  Logs:', count2);
    console.log('  Root:', root2);
    console.log();
    
    if (root1 === root2) {
      console.log('✅ ROOT HASHES MATCH - Files are identical');
    } else {
      console.log('❌ ROOT HASHES DIFFER - Files are different');
      
      if (count1 !== count2) {
        console.log(`  Log count differs: ${count1} vs ${count2}`);
      }
    }
    
    return {
      identical: root1 === root2,
      root1,
      root2,
      count1,
      count2
    };
  }

  /**
   * Get paginated logs from a saved file
   */
  static getPaginatedLogs(filepath, page, pageSize, logType = null) {
    console.log(`\n=== PAGINATED LOGS FROM FILE: ${filepath} ===\n`);
    console.log(`Page: ${page + 1}`);
    console.log(`Page size: ${pageSize}`);
    if (logType) {
      console.log(`Type: ${logType}`);
    }
    console.log();
    
    // Load tree from file
    const tree = MerklePersistence.loadFromFile(filepath);
    
    // Get paginated results
    const result = MerkleSearch.getLogsPaginated(tree, page, pageSize, logType);
    
    console.log(`Page ${result.page + 1} of ${result.totalPages}`);
    console.log(`Showing ${result.logs.length} of ${result.totalLogs} total logs\n`);
    
    result.logs.forEach((log, index) => {
      console.log(`${(page * pageSize) + index + 1}. ${log.logId} (${log.logType}): t=${log.timestamp}`);
      console.log(`   ${JSON.stringify(log.metadata)}`);
    });
    
    return result;
  }

  /**
   * Export search results to a new file
   */
  static exportSearchResults(sourceFilepath, targetFilepath, searchCriteria) {
    console.log(`\n=== EXPORTING SEARCH RESULTS ===\n`);
    console.log(`Source: ${sourceFilepath}`);
    console.log(`Target: ${targetFilepath}`);
    console.log(`Criteria:`, JSON.stringify(searchCriteria, null, 2));
    console.log();
    
    // Load tree from file
    const tree = MerklePersistence.loadFromFile(sourceFilepath);
    
    // Search based on criteria
    let logs = [];
    if (searchCriteria.logType) {
      logs = MerkleSearch.getLogsByType(tree, searchCriteria.logType);
    } else if (searchCriteria.timeRange) {
      logs = MerkleSearch.findLogsByTimeRange(
        tree,
        searchCriteria.timeRange.start,
        searchCriteria.timeRange.end,
        searchCriteria.logType
      );
    } else if (searchCriteria.metadata) {
      logs = MerkleSearch.findLogsByMetadata(
        tree,
        searchCriteria.metadata.field,
        searchCriteria.metadata.value,
        searchCriteria.logType
      );
    }
    
    console.log(`✓ Found ${logs.length} logs matching criteria`);
    
    // Create a new tree with just these logs
    const { TopLevelMerkleTree } = require('./merkle-core');
    const newTree = new TopLevelMerkleTree();
    
    for (const log of logs) {
      newTree.addLog(log);
    }
    
    newTree.buildTree();
    
    // Save to new file
    const saveResult = MerklePersistence.saveToFile(newTree, targetFilepath);
    
    console.log(`✓ Exported to: ${saveResult.filepath}`);
    console.log(`  Size: ${MerklePersistence.formatBytes(saveResult.size)}`);
    console.log(`  Logs: ${saveResult.logCount}`);
    console.log(`  Root hash: ${newTree.getRootHash()}`);
    
    return {
      logs,
      tree: newTree,
      saveResult
    };
  }
}

module.exports = {
  MerkleFileOps
};