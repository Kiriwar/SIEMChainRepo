// ============= FILE 5: merkle-persistence.js =============
// File storage and loading functionality

const fs = require('fs');
const path = require('path');
const { LogEntry, TopLevelMerkleTree } = require('./merkle-core');
const { MerkleProofGenerator } = require('./merkle-proof');

class MerklePersistence {
  
  // Save concatenated hash file for each sub-tree
static saveConcatHashFiles(topLevelTree, epochId, outputDir = './concat_hashes') {
  const { hash } = require('./merkle-core');
  
  // Create directory if not exists
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }
  
  const results = [];
  
  for (const [logType, subTree] of topLevelTree.subTrees.entries()) {
    const data = subTree.generateConcatHashData(epochId);
    
    // Format: epoch_logtype_epochid
    const filename = `epoch_${logType}_${epochId}.txt`;
    const filepath = path.join(outputDir, filename);
    
    // Create file content
    let content = '';
    data.entries.forEach(entry => {
      content += `{log id: ${entry.logId}, hash value: ${entry.hashValue}}\n`;
    });
    content += `\nepoch id: ${data.epochId}\n`;
    content += `log type: ${data.logType}\n`;
    content += `hash value: ${data.hashValue}\n`;
    
    fs.writeFileSync(filepath, content, 'utf8');
    
    results.push({
      logType,
      filepath,
      epochId,
      concatHash: data.hashValue,
      logCount: data.entries.length
    });
  }
  
  return results;
}

  // Save entire tree to a single JSON file
  static saveToFile(topLevelTree, filepath) {
    const data = this.serialize(topLevelTree);
    
    // Ensure directory exists
    const dir = path.dirname(filepath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    fs.writeFileSync(filepath, JSON.stringify(data, null, 2), 'utf8');
    
    return {
      filepath,
      size: fs.statSync(filepath).size,
      logCount: topLevelTree.getTotalLogCount(),
      subTreeCount: topLevelTree.subTrees.size
    };
  }

  // Save tree to file asynchronously
  static async saveToFileAsync(topLevelTree, filepath) {
    const data = this.serialize(topLevelTree);
    
    const dir = path.dirname(filepath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    return new Promise((resolve, reject) => {
      fs.writeFile(filepath, JSON.stringify(data, null, 2), 'utf8', (err) => {
        if (err) reject(err);
        else resolve({
          filepath,
          size: fs.statSync(filepath).size,
          logCount: topLevelTree.getTotalLogCount(),
          subTreeCount: topLevelTree.subTrees.size
        });
      });
    });
  }

  // Load tree from file
  static loadFromFile(filepath) {
    if (!fs.existsSync(filepath)) {
      throw new Error(`File not found: ${filepath}`);
    }
    
    const data = JSON.parse(fs.readFileSync(filepath, 'utf8'));
    return this.deserialize(data);
  }

  // Load tree from file asynchronously
  static async loadFromFileAsync(filepath) {
    return new Promise((resolve, reject) => {
      fs.readFile(filepath, 'utf8', (err, data) => {
        if (err) reject(err);
        else {
          try {
            const tree = this.deserialize(JSON.parse(data));
            resolve(tree);
          } catch (error) {
            reject(error);
          }
        }
      });
    });
  }

  // Serialize tree to JSON-compatible object
  static serialize(topLevelTree) {
  const subTreesData = {};
  
  for (const [logType, subTree] of topLevelTree.subTrees.entries()) {
    subTreesData[logType] = {  // ← MISSING! You need to assign to subTreesData
      logType: subTree.logType,
      rootHash: subTree.getRootHash(),  // ← MISSING!
      logs: subTree.logs.map(log => {  // ← MISSING 'logs:' assignment
        // Generate proof path for THIS log (inside the map)
        const fullProof = MerkleProofGenerator.generateFullProof(topLevelTree, log.logId, log.logType);
        
        return {
          logId: log.logId,
          timestamp: log.timestamp,
          logType: log.logType,
          metadata: log.metadata,
          hash: log.hash,
          subTreeProof: fullProof.subTreeProof,      // Proof to sub-tree root
          subTreeRoot: fullProof.subTreeRoot,        // Sub-tree root hash
          topLevelProof: fullProof.topLevelProof,    // Proof from sub-tree root to top-level root
          topLevelRoot: fullProof.topLevelRoot
        };
      })
    };
  }
  
  return {
    version: '1.0',
    timestamp: new Date().toISOString(),
    topLevelRootHash: topLevelTree.getRootHash(),
    subTrees: subTreesData,
    statistics: topLevelTree.getStatistics()
  };
}

  // Deserialize JSON data back to tree
  static deserialize(data) {
    const tree = new TopLevelMerkleTree();
    
    // Restore logs to sub-trees
    for (const [logType, subTreeData] of Object.entries(data.subTrees)) {
      for (const logData of subTreeData.logs) {
        const log = new LogEntry(
          logData.logId,
          logData.timestamp,
          logData.logType,
          logData.metadata
        );
        tree.addLog(log);
      }
    }
    
    // Rebuild the tree structure
    tree.buildTree();
    
    // Verify integrity
    if (tree.getRootHash() !== data.topLevelRootHash) {
      console.warn('Warning: Root hash mismatch after deserialization');
      console.warn(`Expected: ${data.topLevelRootHash}`);
      console.warn(`Got: ${tree.getRootHash()}`);
    }
    
    return tree;
  }

  // Save only logs (more compact, no tree structure)
  static saveLogsOnly(topLevelTree, filepath) {
    const allLogs = [];
    
    for (const subTree of topLevelTree.subTrees.values()) {
      for (const log of subTree.logs) {
        allLogs.push({
          logId: log.logId,
          timestamp: log.timestamp,
          logType: log.logType,
          metadata: log.metadata
        });
      }
    }

    const data = {
      version: '1.0',
      timestamp: new Date().toISOString(),
      logCount: allLogs.length,
      logs: allLogs
    };

    const dir = path.dirname(filepath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(filepath, JSON.stringify(data, null, 2), 'utf8');
    
    return {
      filepath,
      size: fs.statSync(filepath).size,
      logCount: allLogs.length
    };
  }

  // Load logs and rebuild tree
  static loadLogsAndRebuild(filepath) {
    const data = JSON.parse(fs.readFileSync(filepath, 'utf8'));
    const tree = new TopLevelMerkleTree();
    
    for (const logData of data.logs) {
      const log = new LogEntry(
        logData.logId,
        logData.timestamp,
        logData.logType,
        logData.metadata
      );
      tree.addLog(log);
    }
    
    tree.buildTree();
    return tree;
  }

  // Save to multiple files (one per log type)
  static saveToMultipleFiles(topLevelTree, directoryPath) {
    if (!fs.existsSync(directoryPath)) {
      fs.mkdirSync(directoryPath, { recursive: true });
    }

    const results = [];
    
    // Save metadata file
    const metadata = {
      version: '1.0',
      timestamp: new Date().toISOString(),
      topLevelRootHash: topLevelTree.getRootHash(),
      statistics: topLevelTree.getStatistics(),
      files: []
    };

    // Save each sub-tree to separate file
    for (const [logType, subTree] of topLevelTree.subTrees.entries()) {
      const filename = `${logType}.json`;
      const filepath = path.join(directoryPath, filename);
      
      const subTreeData = {
        logType: subTree.logType,
        rootHash: subTree.getRootHash(),
        logCount: subTree.logs.length,
        logs: subTree.logs.map(log => ({
          logId: log.logId,
          timestamp: log.timestamp,
          logType: log.logType,
          metadata: log.metadata
        }))
      };

      fs.writeFileSync(filepath, JSON.stringify(subTreeData, null, 2), 'utf8');
      
      const fileInfo = {
        filename,
        filepath,
        logType,
        size: fs.statSync(filepath).size,
        logCount: subTree.logs.length
      };
      
      results.push(fileInfo);
      metadata.files.push({ filename, logType, logCount: subTree.logs.length });
    }

    // Save metadata file
    const metadataPath = path.join(directoryPath, 'metadata.json');
    fs.writeFileSync(metadataPath, JSON.stringify(metadata, null, 2), 'utf8');
    
    return {
      directory: directoryPath,
      metadataFile: metadataPath,
      files: results,
      totalSize: results.reduce((sum, f) => sum + f.size, 0)
    };
  }

  // Load from multiple files
  static loadFromMultipleFiles(directoryPath) {
    const metadataPath = path.join(directoryPath, 'metadata.json');
    
    if (!fs.existsSync(metadataPath)) {
      throw new Error(`Metadata file not found: ${metadataPath}`);
    }

    const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
    const tree = new TopLevelMerkleTree();

    // Load each sub-tree file
    for (const fileInfo of metadata.files) {
      const filepath = path.join(directoryPath, fileInfo.filename);
      const subTreeData = JSON.parse(fs.readFileSync(filepath, 'utf8'));
      
      for (const logData of subTreeData.logs) {
        const log = new LogEntry(
          logData.logId,
          logData.timestamp,
          logData.logType,
          logData.metadata
        );
        tree.addLog(log);
      }
    }

    // Rebuild tree
    tree.buildTree();

    // Verify integrity
    if (tree.getRootHash() !== metadata.topLevelRootHash) {
      console.warn('Warning: Root hash mismatch after loading');
    }

    return tree;
  }

  // Export to CSV format
  static exportToCSV(topLevelTree, filepath) {
    const allLogs = [];
    
    for (const subTree of topLevelTree.subTrees.values()) {
      allLogs.push(...subTree.logs);
    }

    // Sort by timestamp
    allLogs.sort((a, b) => a.timestamp - b.timestamp);

    // Create CSV content
    const headers = ['logId', 'timestamp', 'logType', 'metadata', 'hash'];
    const rows = allLogs.map(log => [
      log.logId,
      log.timestamp,
      log.logType,
      JSON.stringify(log.metadata),
      log.hash
    ]);

    const csv = [
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
    ].join('\n');

    const dir = path.dirname(filepath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(filepath, csv, 'utf8');

    return {
      filepath,
      size: fs.statSync(filepath).size,
      logCount: allLogs.length
    };
  }

  // Get file info without loading
  static getFileInfo(filepath) {
    if (!fs.existsSync(filepath)) {
      throw new Error(`File not found: ${filepath}`);
    }

    const stats = fs.statSync(filepath);
    const data = JSON.parse(fs.readFileSync(filepath, 'utf8'));

    return {
      filepath,
      size: stats.size,
      sizeFormatted: this.formatBytes(stats.size),
      version: data.version,
      timestamp: data.timestamp,
      logCount: data.statistics?.totalLogs || data.logCount,
      subTreeCount: data.statistics?.subTreeCount,
      rootHash: data.topLevelRootHash,
      modified: stats.mtime
    };
  }

  // Format bytes to human-readable
  static formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  }
}

module.exports = {
  MerklePersistence
};