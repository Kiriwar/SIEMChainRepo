// ============= FILE 3: merkle-search.js =============
// Search and query operations

class MerkleSearch {
  
  // Search for a specific log by ID
  static findLogById(topLevelTree, logId, logType = null) {
    if (logType) {
      const subTree = topLevelTree.getSubTree(logType);
      return subTree ? subTree.findLog(logId) : null;
    }

    // Search all sub-trees
    for (const subTree of topLevelTree.subTrees.values()) {
      const log = subTree.findLog(logId);
      if (log) return log;
    }

    return null;
  }

  // Search logs by time range
  static findLogsByTimeRange(topLevelTree, startTime, endTime, logType = null) {
    const results = [];

    if (logType) {
      const subTree = topLevelTree.getSubTree(logType);
      if (subTree) {
        results.push(...subTree.getLogsByTimeRange(startTime, endTime));
      }
    } else {
      // Search all sub-trees
      for (const subTree of topLevelTree.subTrees.values()) {
        results.push(...subTree.getLogsByTimeRange(startTime, endTime));
      }
    }

    return results.sort((a, b) => a.timestamp - b.timestamp);
  }

  // Search logs by metadata field
  static findLogsByMetadata(topLevelTree, fieldName, fieldValue, logType = null) {
    const results = [];

    const searchInSubTree = (subTree) => {
      return subTree.logs.filter(log => 
        log.metadata[fieldName] === fieldValue
      );
    };

    if (logType) {
      const subTree = topLevelTree.getSubTree(logType);
      if (subTree) {
        results.push(...searchInSubTree(subTree));
      }
    } else {
      for (const subTree of topLevelTree.subTrees.values()) {
        results.push(...searchInSubTree(subTree));
      }
    }

    return results;
  }

  // Get all logs of a specific type
  static getLogsByType(topLevelTree, logType) {
    const subTree = topLevelTree.getSubTree(logType);
    return subTree ? [...subTree.logs] : [];
  }

  // Get the latest N logs
  static getLatestLogs(topLevelTree, count, logType = null) {
    let allLogs = [];

    if (logType) {
      const subTree = topLevelTree.getSubTree(logType);
      if (subTree) {
        allLogs = [...subTree.logs];
      }
    } else {
      for (const subTree of topLevelTree.subTrees.values()) {
        allLogs.push(...subTree.logs);
      }
    }

    return allLogs
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, count);
  }

  // Count logs by type
  static countByType(topLevelTree) {
    const counts = {};
    
    for (const [logType, subTree] of topLevelTree.subTrees.entries()) {
      counts[logType] = subTree.getLogCount();
    }

    return counts;
  }

  // Get logs with pagination
  static getLogsPaginated(topLevelTree, page, pageSize, logType = null) {
    let allLogs = [];

    if (logType) {
      const subTree = topLevelTree.getSubTree(logType);
      if (subTree) {
        allLogs = [...subTree.logs];
      }
    } else {
      for (const subTree of topLevelTree.subTrees.values()) {
        allLogs.push(...subTree.logs);
      }
      allLogs.sort((a, b) => a.timestamp - b.timestamp);
    }

    const startIdx = page * pageSize;
    const endIdx = startIdx + pageSize;

    return {
      logs: allLogs.slice(startIdx, endIdx),
      page,
      pageSize,
      totalLogs: allLogs.length,
      totalPages: Math.ceil(allLogs.length / pageSize)
    };
  }
}

module.exports = {
  MerkleSearch
};
