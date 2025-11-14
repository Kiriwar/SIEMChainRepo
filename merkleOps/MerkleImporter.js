// ============= merkle-import.js =============
// Import logs from external JSON files

const fs = require('fs');
const { LogEntry, TopLevelMerkleTree } = require('./merkle-core');

class MerkleImporter {
  
  /**
   * Import logs from JSON file with format:
   * [
   *   {"id":1,"timestamp":1762767502999,"Type":"firewall","message":"Single log 1"},
   *   {"id":2,"timestamp":1762767503110,"Type":"auth","message":"Single log 2"},
   *   ...
   * ]
   * HashValue: <optional hash at the end>
   */
  static importFromFile(filepath) {
    if (!fs.existsSync(filepath)) {
      throw new Error(`File not found: ${filepath}`);
    }

    const content = fs.readFileSync(filepath, 'utf8');
    return this.importFromString(content);
  }

  /**
   * Import logs from JSON string
   */
  static importFromString(jsonString) {
    // Remove the "HashValue: xxx" line if it exists
    const lines = jsonString.split('\n');
    const jsonLines = lines.filter(line => !line.trim().startsWith('HashValue:'));
    const cleanJson = jsonLines.join('\n');

    // Parse JSON array
    let logsData;
    try {
      logsData = JSON.parse(cleanJson);
    } catch (error) {
      throw new Error(`Failed to parse JSON: ${error.message}`);
    }

    if (!Array.isArray(logsData)) {
      throw new Error('JSON must be an array of log objects');
    }

    const tree = new TopLevelMerkleTree();
    let importedCount = 0;
    let skippedCount = 0;

    for (const logData of logsData) {
      try {
        // Validate required fields
        if (!logData.id && logData.id !== 0) {
          console.warn(`Skipping log without 'id' field:`, logData);
          skippedCount++;
          continue;
        }

        if (!logData.timestamp) {
          console.warn(`Skipping log ${logData.id} without 'timestamp' field`);
          skippedCount++;
          continue;
        }

        if (!logData.Type) {
          console.warn(`Skipping log ${logData.id} without 'Type' field`);
          skippedCount++;
          continue;
        }

        // Create LogEntry
        // Use 'id' as logId, 'Type' as logType
        // Store all other fields (like 'message') in metadata
        const logId = `log-${logData.id}`;
        const timestamp = logData.timestamp;
        const logType = logData.Type.toLowerCase(); // Normalize to lowercase
        
        // Put all extra fields into metadata
        const metadata = {};
        for (const [key, value] of Object.entries(logData)) {
          if (key !== 'id' && key !== 'timestamp' && key !== 'Type') {
            metadata[key] = value;
          }
        }

        const logEntry = new LogEntry(logId, timestamp, logType, metadata);
        tree.addLog(logEntry);
        importedCount++;

      } catch (error) {
        console.warn(`Error importing log ${logData.id}:`, error.message);
        skippedCount++;
      }
    }

    // Build the tree
    tree.buildTree();

    return {
      tree,
      importedCount,
      skippedCount,
      totalLogs: logsData.length,
      rootHash: tree.getRootHash()
    };
  }

  /**
   * Import logs and return statistics
   */
  static importAndAnalyze(filepath) {
    console.log(`\n=== IMPORTING LOGS FROM: ${filepath} ===\n`);

    const result = this.importFromFile(filepath);

    console.log('Import Summary:');
    console.log(`  ✓ Total logs in file: ${result.totalLogs}`);
    console.log(`  ✓ Successfully imported: ${result.importedCount}`);
    if (result.skippedCount > 0) {
      console.log(`  ⚠ Skipped (errors): ${result.skippedCount}`);
    }
    console.log(`\n  Root Hash: ${result.rootHash}\n`);

    // Show statistics by type
    const stats = result.tree.getStatistics();
    console.log('Logs by Type:');
    for (const [logType, info] of Object.entries(stats.subTrees)) {
      console.log(`  - ${logType}: ${info.logCount} logs`);
    }
    console.log();

    return result;
  }

  /**
   * Import and save to Merkle format
   */
  static importAndSave(inputFilepath, outputFilepath) {
    const { MerklePersistence } = require('./merkle-persistence');
    
    console.log(`\nImporting from: ${inputFilepath}`);
    const result = this.importFromFile(inputFilepath);
    
    console.log(`Imported ${result.importedCount} logs`);
    console.log(`Root hash: ${result.rootHash}`);
    
    console.log(`\nSaving to: ${outputFilepath}`);
    const saveResult = MerklePersistence.saveToFile(result.tree, outputFilepath);
    
    console.log(`✓ Saved successfully`);
    console.log(`  File size: ${MerklePersistence.formatBytes(saveResult.size)}`);
    console.log(`  Logs: ${saveResult.logCount}\n`);
    
    return result;
  }

  /**
   * Batch import from multiple files
   */
  static importMultipleFiles(filepaths) {
    const tree = new TopLevelMerkleTree();
    let totalImported = 0;
    let totalSkipped = 0;

    console.log(`\n=== BATCH IMPORT FROM ${filepaths.length} FILES ===\n`);

    for (const filepath of filepaths) {
      console.log(`Importing: ${filepath}`);
      try {
        const result = this.importFromFile(filepath);
        
        // Add all logs from this file to the main tree
        for (const subTree of result.tree.subTrees.values()) {
          for (const log of subTree.logs) {
            tree.addLog(log);
          }
        }

        totalImported += result.importedCount;
        totalSkipped += result.skippedCount;
        console.log(`  ✓ Imported ${result.importedCount} logs`);
      } catch (error) {
        console.log(`  ✗ Error: ${error.message}`);
      }
    }

    // Build the combined tree
    tree.buildTree();

    console.log('\nBatch Import Summary:');
    console.log(`  Total imported: ${totalImported}`);
    console.log(`  Total skipped: ${totalSkipped}`);
    console.log(`  Root hash: ${tree.getRootHash()}\n`);

    return {
      tree,
      totalImported,
      totalSkipped,
      rootHash: tree.getRootHash()
    };
  }

  /**
   * Validate log file format without importing
   */
  static validateFile(filepath) {
    console.log(`\n=== VALIDATING: ${filepath} ===\n`);

    if (!fs.existsSync(filepath)) {
      console.log('✗ File not found');
      return false;
    }

    try {
      const content = fs.readFileSync(filepath, 'utf8');
      const lines = content.split('\n');
      const jsonLines = lines.filter(line => !line.trim().startsWith('HashValue:'));
      const cleanJson = jsonLines.join('\n');

      const logsData = JSON.parse(cleanJson);

      if (!Array.isArray(logsData)) {
        console.log('✗ JSON must be an array');
        return false;
      }

      console.log(`✓ Valid JSON array with ${logsData.length} entries`);

      // Check required fields
      let validCount = 0;
      let invalidCount = 0;

      for (const log of logsData) {
        const hasId = log.id !== undefined;
        const hasTimestamp = log.timestamp !== undefined;
        const hasType = log.Type !== undefined;

        if (hasId && hasTimestamp && hasType) {
          validCount++;
        } else {
          invalidCount++;
          console.log(`  ⚠ Invalid log (missing fields):`, log);
        }
      }

      console.log(`\n✓ Valid logs: ${validCount}`);
      if (invalidCount > 0) {
        console.log(`⚠ Invalid logs: ${invalidCount}`);
      }
      console.log();

      return invalidCount === 0;

    } catch (error) {
      console.log(`✗ Error: ${error.message}\n`);
      return false;
    }
  }
}

module.exports = {
  MerkleImporter
};