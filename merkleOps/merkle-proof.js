// ============= FILE 2: merkle-proof.js =============
// Proof generation and verification logic

const { combineHashes } = require('./merkle-core');

class MerkleProofGenerator {
  
  // Generate a Merkle proof for a specific log entry in a sub-tree
  static generateSubTreeProof(subTree, logId) {
    if (!subTree.root) return null;

    const proof = [];
    const targetLog = subTree.findLog(logId);
    if (!targetLog) return null;

    this._generateProofRecursive(subTree.root, targetLog.hash, proof);
    return proof;
  }

  static _generateProofRecursive(node, targetHash, proof) {
    if (!node || node.isLeaf()) {
      return node && node.hash === targetHash;
    }

    // Check left subtree
    if (this._generateProofRecursive(node.left, targetHash, proof)) {
      if (node.right) {
        proof.push({ hash: node.right.hash, position: 'right' });
      }
      return true;
    }

    // Check right subtree
    if (this._generateProofRecursive(node.right, targetHash, proof)) {
      if (node.left) {
        proof.push({ hash: node.left.hash, position: 'left' });
      }
      return true;
    }

    return false;
  }

  // Generate top-level proof (from sub-tree root to top-level root)
  static generateTopLevelProof(topLevelTree, logType) {
    if (!topLevelTree.root) return null;

    const subTree = topLevelTree.getSubTree(logType);
    if (!subTree) return null;

    const proof = [];
    const targetSubTreeRoot = subTree.getRootHash();
    
    this._generateProofRecursive(topLevelTree.root, targetSubTreeRoot, proof);
    return proof;
  }

  // Generate a full proof (sub-tree proof + top-level proof)
  static generateFullProof(topLevelTree, logId, logType) {
    const subTree = topLevelTree.getSubTree(logType);
    if (!subTree) return null;

    const targetLog = subTree.findLog(logId);
    if (!targetLog) return null;

    const subTreeProof = this.generateSubTreeProof(subTree, logId);
    if (!subTreeProof) return null;

    const topLevelProof = this.generateTopLevelProof(topLevelTree, logType);

    return {
      logId,
      logType,
      leafHash: targetLog.hash,
      subTreeProof,
      subTreeRoot: subTree.getRootHash(),
      topLevelProof,
      topLevelRoot: topLevelTree.getRootHash(),
      timestamp: targetLog.timestamp,
      metadata: targetLog.metadata
    };
  }
}

class MerkleProofVerifier {
  
  // Verify a single-level proof (generic)
  static verifyProof(leafHash, proof, rootHash) {
    let currentHash = leafHash;

    for (const step of proof) {
      if (step.position === 'left') {
        currentHash = combineHashes(step.hash, currentHash);
      } else {
        currentHash = combineHashes(currentHash, step.hash);
      }
    }

    return currentHash === rootHash;
  }

  // Verify a full two-level proof
  static verifyFullProof(proof) {
    // First verify the sub-tree proof
    const subTreeValid = this.verifyProof(
      proof.leafHash,
      proof.subTreeProof,
      proof.subTreeRoot
    );

    if (!subTreeValid) {
      return { valid: false, reason: 'Sub-tree proof invalid' };
    }

    // Then verify the top-level proof
    const topLevelValid = this.verifyProof(
      proof.subTreeRoot,
      proof.topLevelProof,
      proof.topLevelRoot
    );

    if (!topLevelValid) {
      return { valid: false, reason: 'Top-level proof invalid' };
    }

    return { valid: true, reason: 'Proof is valid' };
  }

  // Verify against a known root hash
  static verifyAgainstRoot(proof, expectedRootHash) {
    if (proof.topLevelRoot !== expectedRootHash) {
      return { valid: false, reason: 'Root hash mismatch' };
    }

    return this.verifyFullProof(proof);
  }
}

module.exports = {
  MerkleProofGenerator,
  MerkleProofVerifier
};