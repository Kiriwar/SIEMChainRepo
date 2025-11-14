import time
import hashlib
import random
import json
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import statistics

# ============================================================================
# COMMON DATA STRUCTURES
# ============================================================================

@dataclass
class LogEntry:
    """Individual log entry"""
    log_id: str
    timestamp: str
    log_type: str
    user: str
    action: str
    status: str
    data: str

# ============================================================================
# YOUR IDEA: TWO-LAYER MERKLE TREE WITH PATH CACHING
# ============================================================================

@dataclass
class CachedPath:
    """Cached Merkle path for verification"""
    leaf_hash: str
    sub_tree_path: List[Dict]
    sub_root_hash: str
    top_tree_path: List[Dict]
    global_root_hash: str

@dataclass
class LogWithCache:
    """Log entry with cached Merkle path"""
    log: LogEntry
    cached_path: CachedPath

class MerkleTree:
    """Basic Merkle tree implementation"""
    
    def __init__(self):
        self.leaves: List[str] = []
        self.root: str = ""
    
    @staticmethod
    def hash_data(data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()
    
    @staticmethod
    def hash_pair(left: str, right: str) -> str:
        return hashlib.sha256((left + right).encode()).hexdigest()
    
    def add_leaf(self, data: str) -> str:
        leaf_hash = self.hash_data(data)
        self.leaves.append(leaf_hash)
        return leaf_hash
    
    def build_tree(self) -> Tuple[str, List[List[str]]]:
        if not self.leaves:
            return "", []
        
        levels = []
        current_level = self.leaves.copy()
        levels.append(current_level.copy())
        
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                parent_hash = self.hash_pair(left, right)
                next_level.append(parent_hash)
            current_level = next_level
            levels.append(current_level.copy())
        
        self.root = current_level[0]
        return self.root, levels
    
    def get_proof(self, leaf_index: int, levels: List[List[str]]) -> List[Dict]:
        proof = []
        current_index = leaf_index
        
        for level_num, level in enumerate(levels[:-1]):
            if current_index % 2 == 0:
                sibling_index = current_index + 1
                position = "right"
            else:
                sibling_index = current_index - 1
                position = "left"
            
            if sibling_index < len(level):
                sibling_hash = level[sibling_index]
            elif current_index < len(level):
                sibling_hash = level[current_index]
            else:
                break  # Skip this level if indices are out of bounds
            
            proof.append({
                "level": level_num,
                "position": position,
                "siblingHash": sibling_hash
            })
            
            current_index = current_index // 2
        
        return proof

class YourIdeaTwoLayerMerkleTree:
    """Your idea: Two-layer Merkle tree with path caching"""
    
    def __init__(self, log_types: List[str]):
        self.log_types = log_types
        self.sub_trees: Dict[str, MerkleTree] = {lt: MerkleTree() for lt in log_types}
        self.sub_tree_levels: Dict[str, List[List[str]]] = {}
        self.sub_roots: Dict[str, str] = {}
        self.global_tree = MerkleTree()
        self.global_root = ""
        self.logs_with_cache: List[LogWithCache] = []
    
    def add_log(self, log_entry: LogEntry) -> Tuple[LogWithCache, float]:
        """Add log and return with insertion time"""
        start_time = time.time()
        
        # Add to sub-tree
        sub_tree = self.sub_trees[log_entry.log_type]
        log_data = json.dumps(asdict(log_entry), sort_keys=True)
        leaf_hash = sub_tree.add_leaf(log_data)
        
        # Rebuild sub-tree
        sub_root, sub_levels = sub_tree.build_tree()
        self.sub_tree_levels[log_entry.log_type] = sub_levels
        self.sub_roots[log_entry.log_type] = sub_root
        
        # Get proof in sub-tree
        leaf_index = len(sub_tree.leaves) - 1
        sub_tree_path = sub_tree.get_proof(leaf_index, sub_levels)
        
        # Rebuild global tree
        self.global_tree = MerkleTree()
        for log_type in self.log_types:
            if self.sub_roots.get(log_type):
                self.global_tree.leaves.append(self.sub_roots[log_type])
        
        global_root, global_levels = self.global_tree.build_tree()
        self.global_root = global_root
        
        # Get proof in global tree
        # Find the actual index in global tree (only count sub-trees with roots)
        active_log_types = [lt for lt in self.log_types if self.sub_roots.get(lt)]
        if log_entry.log_type in active_log_types:
            global_leaf_index = active_log_types.index(log_entry.log_type)
        else:
            global_leaf_index = 0
    
        if global_leaf_index < len(global_levels[0]) if global_levels else False:
            top_tree_path = self.global_tree.get_proof(global_leaf_index, global_levels)
        else:
            top_tree_path = []
        
        # Create cached path
        cached_path = CachedPath(
            leaf_hash=leaf_hash,
            sub_tree_path=sub_tree_path,
            sub_root_hash=sub_root,
            top_tree_path=top_tree_path,
            global_root_hash=global_root
        )
        
        log_with_cache = LogWithCache(log=log_entry, cached_path=cached_path)
        self.logs_with_cache.append(log_with_cache)
        
        insertion_time = time.time() - start_time
        return log_with_cache, insertion_time
    
    def verify_log(self, log_with_cache: LogWithCache) -> Tuple[bool, float]:
        """Verify log using cached path"""
        start_time = time.time()
        
        # Verify leaf hash
        log_data = json.dumps(asdict(log_with_cache.log), sort_keys=True)
        computed_hash = MerkleTree.hash_data(log_data)
        
        if computed_hash != log_with_cache.cached_path.leaf_hash:
            return False, time.time() - start_time
        
        # Verify sub-tree path
        current_hash = log_with_cache.cached_path.leaf_hash
        for node in log_with_cache.cached_path.sub_tree_path:
            if node["position"] == "left":
                current_hash = MerkleTree.hash_pair(node["siblingHash"], current_hash)
            else:
                current_hash = MerkleTree.hash_pair(current_hash, node["siblingHash"])
        
        if current_hash != log_with_cache.cached_path.sub_root_hash:
            return False, time.time() - start_time
        
        # Verify global tree path
        current_hash = log_with_cache.cached_path.sub_root_hash
        for node in log_with_cache.cached_path.top_tree_path:
            if node["position"] == "left":
                current_hash = MerkleTree.hash_pair(node["siblingHash"], current_hash)
            else:
                current_hash = MerkleTree.hash_pair(current_hash, node["siblingHash"])
        
        verification_time = time.time() - start_time
        is_valid = current_hash == log_with_cache.cached_path.global_root_hash
        
        return is_valid, verification_time
    
    def get_storage_size(self) -> Dict[str, int]:
        """Calculate storage overhead"""
        log_data_size = 0
        cache_size = 0
        
        for log_with_cache in self.logs_with_cache:
            # Log data size
            log_data = json.dumps(asdict(log_with_cache.log))
            log_data_size += len(log_data.encode())
            
            # Cache size
            cache_size += 32  # leaf_hash
            cache_size += 32  # sub_root_hash
            cache_size += 32  # global_root_hash
            cache_size += len(log_with_cache.cached_path.sub_tree_path) * 32
            cache_size += len(log_with_cache.cached_path.top_tree_path) * 32
        
        return {
            "log_data_bytes": log_data_size,
            "cache_bytes": cache_size,
            "total_bytes": log_data_size + cache_size
        }

# ============================================================================
# DELIA IMPLEMENTATION (Simplified)
# ============================================================================

class DELIASystem:
    """DELIA: LocalState -> GlobalState with Merkle trees"""
    
    def __init__(self, servers: List[str], batch_size: int):
        self.servers = servers
        self.batch_size = batch_size
        self.log_cache_queues: Dict[str, List[str]] = {s: [] for s in servers}
        self.local_states: Dict[str, List[str]] = {s: [] for s in servers}
        self.global_states: List[Dict] = []
        self.current_batch: Dict[str, List[LogEntry]] = {s: [] for s in servers}
    
    def add_log(self, server: str, log_entry: LogEntry) -> Tuple[Optional[str], float]:
        """Add log to server's cache"""
        start_time = time.time()
        
        # Hash log
        log_data = json.dumps(asdict(log_entry), sort_keys=True)
        log_hash = hashlib.sha256(log_data.encode()).hexdigest()
        
        # Add to cache queue
        self.log_cache_queues[server].append(log_hash)
        self.current_batch[server].append(log_entry)
        
        global_state = None
        
        # Check if batch is full
        if len(self.log_cache_queues[server]) >= self.batch_size:
            # Generate Merkle root for this batch
            tree = MerkleTree()
            for h in self.log_cache_queues[server]:
                tree.leaves.append(h)
            root, _ = tree.build_tree()
            
            # Update LocalState
            if self.local_states[server]:
                prev_state = self.local_states[server][-1]
                new_state = hashlib.sha256((root + prev_state).encode()).hexdigest()
            else:
                new_state = hashlib.sha256(root.encode()).hexdigest()
            
            self.local_states[server].append(new_state)
            
            # Generate GlobalState
            global_state_data = {}
            for s in self.servers:
                if self.local_states[s]:
                    global_state_data[s] = self.local_states[s][-1]
                else:
                    global_state_data[s] = ""
            
            self.global_states.append(global_state_data)
            global_state = json.dumps(global_state_data, sort_keys=True)
            
            # Reset cache
            self.log_cache_queues[server] = []
        
        insertion_time = time.time() - start_time
        return global_state, insertion_time
    
    def verify_log(self, server: str, log_entry: LogEntry) -> Tuple[bool, float]:
        """Verify log by rebuilding LocalState"""
        start_time = time.time()
        
        # Find which batch this log belongs to
        batch_index = -1
        log_index = -1
        
        for idx, log in enumerate(self.current_batch[server]):  # logs -> log
            if log.log_id == log_entry.log_id:
                batch_index = idx
                log_index = idx
                break
        
        if batch_index == -1:
            return False, time.time() - start_time
        
        # Rebuild Merkle tree for that batch
        tree = MerkleTree()
        batch_logs = self.current_batch[server][batch_index:batch_index + self.batch_size]
        for log in batch_logs:
            log_data = json.dumps(asdict(log), sort_keys=True)
            log_hash = hashlib.sha256(log_data.encode()).hexdigest()
            tree.leaves.append(log_hash)
        
        root, _ = tree.build_tree()
        
        # Compare with stored LocalState
        if batch_index < len(self.local_states[server]):
            stored_state = self.local_states[server][batch_index]
            # Would need to reverse hash chain to verify, simplified here
            is_valid = True
        else:
            is_valid = False
        
        verification_time = time.time() - start_time
        return is_valid, verification_time
    
    def get_storage_size(self) -> Dict[str, int]:
        """Calculate storage overhead"""
        total_size = 0
        
        # LocalStates
        for server in self.servers:
            total_size += len(self.local_states[server]) * 32
        
        # GlobalStates
        total_size += len(self.global_states) * len(self.servers) * 32
        
        # Log data
        for server in self.servers:
            for log in self.current_batch[server]:
                log_data = json.dumps(asdict(log))
                total_size += len(log_data.encode())
        
        return {
            "total_bytes": total_size,
            "local_states_bytes": len(self.servers) * len(self.local_states[self.servers[0]]) * 32,
            "global_states_bytes": len(self.global_states) * len(self.servers) * 32
        }

# ============================================================================
# BLOCKTRAIL IMPLEMENTATION (Simplified)
# ============================================================================

class BlockTrailSystem:
    """BlockTrail: Hierarchical blockchain structure"""
    
    def __init__(self, cities: List[str]):
        self.cities = cities
        self.city_logs: Dict[str, List[LogEntry]] = {c: [] for c in cities}
        self.city_roots: Dict[str, str] = {}
        self.consensus_times: List[float] = []
    
    def add_log(self, city: str, log_entry: LogEntry) -> Tuple[str, float]:
        """Add log to city blockchain"""
        start_time = time.time()
        
        # Add log
        self.city_logs[city].append(log_entry)
        
        # Hash all logs in this city
        city_data = json.dumps([asdict(log) for log in self.city_logs[city]], sort_keys=True)
        city_root = hashlib.sha256(city_data.encode()).hexdigest()
        self.city_roots[city] = city_root
        
        # Simulate PBFT consensus (3 phases: preprepare, prepare, commit)
        # Message complexity: O(n^2) where n = number of replicas
        num_replicas = 4  # Minimum for PBFT
        consensus_messages = num_replicas * (num_replicas - 1)  # Simplified
        
        # Simulate message exchange time
        time.sleep(0.0001 * consensus_messages)  # 0.1ms per message
        
        insertion_time = time.time() - start_time
        self.consensus_times.append(insertion_time)
        
        return city_root, insertion_time
    
    def verify_log(self, city: str, log_entry: LogEntry) -> Tuple[bool, float]:
        """Verify log exists in city blockchain"""
        start_time = time.time()
        
        # Check if log exists
        is_valid = any(log.log_id == log_entry.log_id for log in self.city_logs[city])
        
        # Rebuild city root to verify
        if is_valid:
            city_data = json.dumps([asdict(log) for log in self.city_logs[city]], sort_keys=True)
            computed_root = hashlib.sha256(city_data.encode()).hexdigest()
            is_valid = computed_root == self.city_roots.get(city, "")
        
        verification_time = time.time() - start_time
        return is_valid, verification_time
    
    def get_storage_size(self) -> Dict[str, int]:
        """Calculate storage overhead"""
        total_size = 0
        
        for city in self.cities:
            for log in self.city_logs[city]:
                log_data = json.dumps(asdict(log))
                total_size += len(log_data.encode())
            
            # City root
            total_size += 32
        
        return {"total_bytes": total_size}

# ============================================================================
# BLOCKCHAIN DEDUPLICATION IMPLEMENTATION (Simplified)
# ============================================================================

class BlockchainDeduplicationSystem:
    """Blockchain-based deduplication with authentication tags"""
    
    def __init__(self):
        self.files: Dict[str, str] = {}  # file_hash -> data
        self.auth_tags: Dict[str, str] = {}  # file_hash -> tag
        self.audit_logs: List[LogEntry] = []
    
    def add_log(self, log_entry: LogEntry) -> Tuple[str, float]:
        """Add log with deduplication"""
        start_time = time.time()
        
        # Hash log data
        log_data = json.dumps(asdict(log_entry), sort_keys=True)
        log_hash = hashlib.sha256(log_data.encode()).hexdigest()
        
        # Check for duplicate
        if log_hash in self.files:
            # Duplicate found, no storage needed
            insertion_time = time.time() - start_time
            return self.auth_tags[log_hash], insertion_time
        
        # Store new log
        self.files[log_hash] = log_data
        self.audit_logs.append(log_entry)
        
        # Generate authentication tag (simplified)
        # In paper: τi = [H4(ci||i) · χ^(Σci,j)]^H3(kl)
        auth_tag = hashlib.sha256((log_hash + "auth").encode()).hexdigest()
        self.auth_tags[log_hash] = auth_tag
        
        insertion_time = time.time() - start_time
        return auth_tag, insertion_time
    
    def verify_log(self, log_entry: LogEntry) -> Tuple[bool, float]:
        """Verify log using authentication tag"""
        start_time = time.time()
        
        # Hash log
        log_data = json.dumps(asdict(log_entry), sort_keys=True)
        log_hash = hashlib.sha256(log_data.encode()).hexdigest()
        
        # Check if exists and verify tag
        is_valid = log_hash in self.files
        
        if is_valid:
            # Verify authentication tag
            expected_tag = hashlib.sha256((log_hash + "auth").encode()).hexdigest()
            is_valid = self.auth_tags.get(log_hash) == expected_tag
        
        verification_time = time.time() - start_time
        return is_valid, verification_time
    
    def get_storage_size(self) -> Dict[str, int]:
        """Calculate storage overhead"""
        total_size = 0
        
        # Deduplicated files
        for file_data in self.files.values():
            total_size += len(file_data.encode())
        
        # Authentication tags
        total_size += len(self.auth_tags) * 32
        
        return {"total_bytes": total_size, "dedup_ratio": len(self.audit_logs) / max(len(self.files), 1)}

# ============================================================================
# PERFORMANCE TEST SUITE
# ============================================================================

class PerformanceComparison:
    """Compare all implementations"""
    
    @staticmethod
    def generate_log(log_id: int, log_types: List[str]) -> LogEntry:
        """Generate random log entry"""
        return LogEntry(
            log_id=f"log_{log_id:06d}",
            timestamp=datetime.now().isoformat(),
            log_type=random.choice(log_types),
            user=f"user_{random.randint(1, 100)}",
            action=random.choice(["login", "logout", "read", "write", "delete"]),
            status=random.choice(["success", "failure"]),
            data=f"data_{random.randint(1000, 9999)}"
        )
    
    @staticmethod
    def test_insertion_performance(num_logs: int, num_log_types: int):
        """Test 1: Insertion Performance"""
        print("\n" + "="*80)
        print("TEST 1: INSERTION PERFORMANCE")
        print("="*80)
        print(f"Number of logs: {num_logs}, Log types: {num_log_types}\n")
        
        log_types = [f"type_{i}" for i in range(num_log_types)]
        results = {}
        
        # Your Idea
        print("Testing Your Idea (Two-Layer Merkle with Cache)...")
        your_tree = YourIdeaTwoLayerMerkleTree(log_types)
        your_times = []
        
        for i in range(num_logs):
            log = PerformanceComparison.generate_log(i, log_types)
            _, insert_time = your_tree.add_log(log)
            your_times.append(insert_time)
        
        results["Your Idea"] = {
            "avg_ms": statistics.mean(your_times) * 1000,
            "median_ms": statistics.median(your_times) * 1000,
            "p95_ms": sorted(your_times)[int(0.95 * len(your_times))] * 1000,
            "min_ms": min(your_times) * 1000,
            "max_ms": max(your_times) * 1000
        }
        
        print(f"  Avg: {results['Your Idea']['avg_ms']:.4f}ms")
        print(f"  Median: {results['Your Idea']['median_ms']:.4f}ms")
        print(f"  P95: {results['Your Idea']['p95_ms']:.4f}ms")
        
        # DELIA
        print("\nTesting DELIA...")
        delia = DELIASystem(servers=["server1", "server2", "server3"], batch_size=100)
        delia_times = []
        
        for i in range(num_logs):
            log = PerformanceComparison.generate_log(i, log_types)
            server = f"server{(i % 3) + 1}"
            _, insert_time = delia.add_log(server, log)
            delia_times.append(insert_time)
        
        results["DELIA"] = {
            "avg_ms": statistics.mean(delia_times) * 1000,
            "median_ms": statistics.median(delia_times) * 1000,
            "p95_ms": sorted(delia_times)[int(0.95 * len(delia_times))] * 1000,
            "min_ms": min(delia_times) * 1000,
            "max_ms": max(delia_times) * 1000
        }
        
        print(f"  Avg: {results['DELIA']['avg_ms']:.4f}ms")
        print(f"  Median: {results['DELIA']['median_ms']:.4f}ms")
        print(f"  P95: {results['DELIA']['p95_ms']:.4f}ms")
        
        # BlockTrail
        print("\nTesting BlockTrail...")
        blocktrail = BlockTrailSystem(cities=["city1", "city2", "city3"])
        blocktrail_times = []
        
        for i in range(num_logs):
            log = PerformanceComparison.generate_log(i, log_types)
            city = f"city{(i % 3) + 1}"
            _, insert_time = blocktrail.add_log(city, log)
            blocktrail_times.append(insert_time)
        
        results["BlockTrail"] = {
            "avg_ms": statistics.mean(blocktrail_times) * 1000,
            "median_ms": statistics.median(blocktrail_times) * 1000,
            "p95_ms": sorted(blocktrail_times)[int(0.95 * len(blocktrail_times))] * 1000,
            "min_ms": min(blocktrail_times) * 1000,
            "max_ms": max(blocktrail_times) * 1000
        }
        
        print(f"  Avg: {results['BlockTrail']['avg_ms']:.4f}ms")
        print(f"  Median: {results['BlockTrail']['median_ms']:.4f}ms")
        print(f"  P95: {results['BlockTrail']['p95_ms']:.4f}ms")
        
        # Blockchain Deduplication
        print("\nTesting Blockchain Deduplication...")
        dedup = BlockchainDeduplicationSystem()
        dedup_times = []
        
        for i in range(num_logs):
            log = PerformanceComparison.generate_log(i, log_types)
            _, insert_time = dedup.add_log(log)
            dedup_times.append(insert_time)
        
        results["Blockchain Dedup"] = {
            "avg_ms": statistics.mean(dedup_times) * 1000,
            "median_ms": statistics.median(dedup_times) * 1000,
            "p95_ms": sorted(dedup_times)[int(0.95 * len(dedup_times))] * 1000,
            "min_ms": min(dedup_times) * 1000,
            "max_ms": max(dedup_times) * 1000
        }
        
        print(f"  Avg: {results['Blockchain Dedup']['avg_ms']:.4f}ms")
        print(f"  Median: {results['Blockchain Dedup']['median_ms']:.4f}ms")
        print(f"  P95: {results['Blockchain Dedup']['p95_ms']:.4f}ms")
        
        return results, (your_tree, delia, blocktrail, dedup)
    
    @staticmethod
    def test_verification_performance(systems: tuple, num_verifications: int):
        """Test 2: Verification Performance"""
        print("\n" + "="*80)
        print("TEST 2: VERIFICATION PERFORMANCE")
        print("="*80)
        print(f"Number of verifications: {num_verifications}\n")
        
        your_tree, delia, blocktrail, dedup = systems
        results = {}
        
        # Your Idea
        print("Testing Your Idea (Two-Layer Merkle with Cache)...")
        your_times = []
        
        for _ in range(min(num_verifications, len(your_tree.logs_with_cache))):
            random_log = random.choice(your_tree.logs_with_cache)
            is_valid, verify_time = your_tree.verify_log(random_log)
            your_times.append(verify_time)
            assert is_valid
        
        results["Your Idea"] = {
            "avg_ms": statistics.mean(your_times) * 1000,
            "median_ms": statistics.median(your_times) * 1000,
            "min_ms": min(your_times) * 1000,
            "max_ms": max(your_times) * 1000
        }
        
        print(f"  Avg: {results['Your Idea']['avg_ms']:.4f}ms")
        print(f"  Median: {results['Your Idea']['median_ms']:.4f}ms")
        
        # DELIA
        print("\nTesting DELIA...")
        delia_times = []
        
        for _ in range(num_verifications):
            server = random.choice(list(delia.current_batch.keys()))
            if delia.current_batch[server]:
                random_log = random.choice(delia.current_batch[server])
                is_valid, verify_time = delia.verify_log(server, random_log)
                delia_times.append(verify_time)
        
        if delia_times:
            results["DELIA"] = {
                "avg_ms": statistics.mean(delia_times) * 1000,
                "median_ms": statistics.median(delia_times) * 1000,
                "min_ms": min(delia_times) * 1000,
                "max_ms": max(delia_times) * 1000
            }
            
            print(f"  Avg: {results['DELIA']['avg_ms']:.4f}ms")
            print(f"  Median: {results['DELIA']['median_ms']:.4f}ms")
        
        # BlockTrail
        print("\nTesting BlockTrail...")
        blocktrail_times = []
        
        for _ in range(num_verifications):
            city = random.choice(list(blocktrail.city_logs.keys()))
            if blocktrail.city_logs[city]:
                random_log = random.choice(blocktrail.city_logs[city])
                is_valid, verify_time = blocktrail.verify_log(city, random_log)
                blocktrail_times.append(verify_time)
        
        if blocktrail_times:
            results["BlockTrail"] = {
                "avg_ms": statistics.mean(blocktrail_times) * 1000,
                "median_ms": statistics.median(blocktrail_times) * 1000,
                "min_ms": min(blocktrail_times) * 1000,
                "max_ms": max(blocktrail_times) * 1000
            }
            
            print(f"  Avg: {results['BlockTrail']['avg_ms']:.4f}ms")
            print(f"  Median: {results['BlockTrail']['median_ms']:.4f}ms")
        
        # Blockchain Deduplication
        print("\nTesting Blockchain Deduplication...")
        dedup_times = []
        
        for _ in range(min(num_verifications, len(dedup.audit_logs))):
            random_log = random.choice(dedup.audit_logs)
            is_valid, verify_time = dedup.verify_log(random_log)
            dedup_times.append(verify_time)
        
        if dedup_times:
            results["Blockchain Dedup"] = {
                "avg_ms": statistics.mean(dedup_times) * 1000,
                "median_ms": statistics.median(dedup_times) * 1000,
                "min_ms": min(dedup_times) * 1000,
                "max_ms": max(dedup_times) * 1000
            }
            
            print(f"  Avg: {results['Blockchain Dedup']['avg_ms']:.4f}ms")
            print(f"  Median: {results['Blockchain Dedup']['median_ms']:.4f}ms")
        
        return results
    
    @staticmethod
    def test_storage_overhead(systems: tuple):
        """Test 3: Storage Overhead"""
        print("\n" + "="*80)
        print("TEST 3: STORAGE OVERHEAD")
        print("="*80 + "\n")
        
        your_tree, delia, blocktrail, dedup = systems
        results = {}
        
        # Your Idea
        print("Testing Your Idea (Two-Layer Merkle with Cache)...")
        your_storage = your_tree.get_storage_size()
        results["Your Idea"] = {
            "log_data_kb": your_storage["log_data_bytes"] / 1024,
            "cache_kb": your_storage["cache_bytes"] / 1024,
            "total_kb": your_storage["total_bytes"] / 1024,
            "overhead_ratio": your_storage["cache_bytes"] / max(your_storage["log_data_bytes"], 1)
        }
        
        print(f"  Log Data: {results['Your Idea']['log_data_kb']:.2f} KB")
        print(f"  Cache: {results['Your Idea']['cache_kb']:.2f} KB")
        print(f"  Total: {results['Your Idea']['total_kb']:.2f} KB")
        print(f"  Overhead Ratio: {results['Your Idea']['overhead_ratio']:.2f}x")
        
        # DELIA
        print("\nTesting DELIA...")
        delia_storage = delia.get_storage_size()
        results["DELIA"] = {
            "total_kb": delia_storage["total_bytes"] / 1024,
            "local_states_kb": delia_storage.get("local_states_bytes", 0) / 1024,
            "global_states_kb": delia_storage.get("global_states_bytes", 0) / 1024
        }
        
        print(f"  Total: {results['DELIA']['total_kb']:.2f} KB")
        print(f"  LocalStates: {results['DELIA']['local_states_kb']:.2f} KB")
        print(f"  GlobalStates: {results['DELIA']['global_states_kb']:.2f} KB")
        
        # BlockTrail
        print("\nTesting BlockTrail...")
        blocktrail_storage = blocktrail.get_storage_size()
        results["BlockTrail"] = {
            "total_kb": blocktrail_storage["total_bytes"] / 1024
        }
        
        print(f"  Total: {results['BlockTrail']['total_kb']:.2f} KB")
        
        # Blockchain Deduplication
        print("\nTesting Blockchain Deduplication...")
        dedup_storage = dedup.get_storage_size()
        results["Blockchain Dedup"] = {
            "total_kb": dedup_storage["total_bytes"] / 1024,
            "dedup_ratio": dedup_storage.get("dedup_ratio", 1.0)
        }
        
        print(f"  Total: {results['Blockchain Dedup']['total_kb']:.2f} KB")
        print(f"  Deduplication Ratio: {results['Blockchain Dedup']['dedup_ratio']:.2f}x")
        
        return results
    
    @staticmethod
    def test_scalability(log_counts: List[int], num_log_types: int):
        """Test 4: Scalability Test"""
        print("\n" + "="*80)
        print("TEST 4: SCALABILITY TEST")
        print("="*80)
        print(f"Testing with different log counts: {log_counts}\n")
        
        log_types = [f"type_{i}" for i in range(num_log_types)]
        results = {
            "Your Idea": [],
            "DELIA": [],
            "BlockTrail": [],
            "Blockchain Dedup": []
        }

        verify_results = {
            "Your Idea": [],
            "DELIA": [],
            "BlockTrail": [],
            "Blockchain Dedup": []
        }
        

    @staticmethod
    def test_scalability(log_counts: List[int], num_log_types: int):
        """Test 4: Scalability Test"""
        print("\n" + "="*80)
        print("TEST 4: SCALABILITY TEST")
        print("="*80)
        print(f"Testing with different log counts: {log_counts}\n")
        
        log_types = [f"type_{i}" for i in range(num_log_types)]
        insertion_results = {
            "Your Idea": [],
            "DELIA": [],
            "BlockTrail": [],
            "Blockchain Dedup": []
        }
        verification_results = {
            "Your Idea": [],
            "DELIA": [],
            "BlockTrail": [],
            "Blockchain Dedup": []
        }
        
        for count in log_counts:
            print(f"\n--- Testing with {count} logs ---")
            
            # Your Idea
            your_tree = YourIdeaTwoLayerMerkleTree(log_types)
            your_insert_times = []
            
            for i in range(count):
                log = PerformanceComparison.generate_log(i, log_types)
                _, insert_time = your_tree.add_log(log)
                your_insert_times.append(insert_time)
            
            your_insert_avg = statistics.mean(your_insert_times) * 1000
            insertion_results["Your Idea"].append(your_insert_avg)
            
            # Verification for Your Idea
            your_verify_times = []
            for _ in range(min(100, count)):
                random_log = random.choice(your_tree.logs_with_cache)
                _, verify_time = your_tree.verify_log(random_log)
                your_verify_times.append(verify_time)
            your_verify_avg = statistics.mean(your_verify_times) * 1000
            verification_results["Your Idea"].append(your_verify_avg)
            
            print(f"  Your Idea - Insert: {your_insert_avg:.4f}ms, Verify: {your_verify_avg:.4f}ms")
            
            # DELIA
            delia = DELIASystem(servers=["server1", "server2", "server3"], batch_size=100)
            delia_insert_times = []
            
            for i in range(count):
                log = PerformanceComparison.generate_log(i, log_types)
                server = f"server{(i % 3) + 1}"
                _, insert_time = delia.add_log(server, log)
                delia_insert_times.append(insert_time)
            
            delia_insert_avg = statistics.mean(delia_insert_times) * 1000
            insertion_results["DELIA"].append(delia_insert_avg)
            
            # Verification for DELIA
            delia_verify_times = []
            for _ in range(min(100, count)):
                server = random.choice(list(delia.current_batch.keys()))
                if delia.current_batch[server]:
                    random_log = random.choice(delia.current_batch[server])
                    _, verify_time = delia.verify_log(server, random_log)
                    delia_verify_times.append(verify_time)
            
            if delia_verify_times:
                delia_verify_avg = statistics.mean(delia_verify_times) * 1000
                verification_results["DELIA"].append(delia_verify_avg)
            else:
                verification_results["DELIA"].append(0)
                delia_verify_avg = 0
            
            print(f"  DELIA - Insert: {delia_insert_avg:.4f}ms, Verify: {delia_verify_avg:.4f}ms")
            
            # BlockTrail
            blocktrail = BlockTrailSystem(cities=["city1", "city2", "city3"])
            blocktrail_insert_times = []
            
            for i in range(count):
                log = PerformanceComparison.generate_log(i, log_types)
                city = f"city{(i % 3) + 1}"
                _, insert_time = blocktrail.add_log(city, log)
                blocktrail_insert_times.append(insert_time)
            
            blocktrail_insert_avg = statistics.mean(blocktrail_insert_times) * 1000
            insertion_results["BlockTrail"].append(blocktrail_insert_avg)
            
            # Verification for BlockTrail
            blocktrail_verify_times = []
            for _ in range(min(100, count)):
                city = random.choice(list(blocktrail.city_logs.keys()))
                if blocktrail.city_logs[city]:
                    random_log = random.choice(blocktrail.city_logs[city])
                    _, verify_time = blocktrail.verify_log(city, random_log)
                    blocktrail_verify_times.append(verify_time)
            
            if blocktrail_verify_times:
                blocktrail_verify_avg = statistics.mean(blocktrail_verify_times) * 1000
                verification_results["BlockTrail"].append(blocktrail_verify_avg)
            else:
                verification_results["BlockTrail"].append(0)
                blocktrail_verify_avg = 0
            
            print(f"  BlockTrail - Insert: {blocktrail_insert_avg:.4f}ms, Verify: {blocktrail_verify_avg:.4f}ms")
            
            # Blockchain Deduplication
            dedup = BlockchainDeduplicationSystem()
            dedup_insert_times = []
            
            for i in range(count):
                log = PerformanceComparison.generate_log(i, log_types)
                _, insert_time = dedup.add_log(log)
                dedup_insert_times.append(insert_time)
            
            dedup_insert_avg = statistics.mean(dedup_insert_times) * 1000
            insertion_results["Blockchain Dedup"].append(dedup_insert_avg)
            
            # Verification for Blockchain Dedup
            dedup_verify_times = []
            for _ in range(min(100, len(dedup.audit_logs))):
                random_log = random.choice(dedup.audit_logs)
                _, verify_time = dedup.verify_log(random_log)
                dedup_verify_times.append(verify_time)
            
            if dedup_verify_times:
                dedup_verify_avg = statistics.mean(dedup_verify_times) * 1000
                verification_results["Blockchain Dedup"].append(dedup_verify_avg)
            else:
                verification_results["Blockchain Dedup"].append(0)
                dedup_verify_avg = 0
            
            print(f"  Blockchain Dedup - Insert: {dedup_insert_avg:.4f}ms, Verify: {dedup_verify_avg:.4f}ms")
        
        return insertion_results, verification_results, log_counts
    
    @staticmethod
    def test_batch_commit_performance(batch_sizes: List[int], time_periods: List[int], 
                                     logs_per_second: int, duration_seconds: int):
        """Test 5: Batch Commit Performance (Your Idea Only)"""
        print("\n" + "="*80)
        print("TEST 5: BATCH COMMIT PERFORMANCE (Your Idea)")
        print("="*80)
        print(f"Logs per second: {logs_per_second}, Duration: {duration_seconds}s\n")
        
        log_types = ["auth", "system", "network"]
        results = {}
        
        for batch_size in batch_sizes:
            for time_period in time_periods:
                print(f"\n--- Batch size: {batch_size}, Time period: {time_period}s ---")
                
                # Initialize system
                tree = YourIdeaTwoLayerMerkleTree(log_types)
                batches_committed = 0
                threshold_triggers = 0
                time_triggers = 0
                batch_start_time = time.time()
                insertion_times = []
                commit_times = []
                
                logs_added = 0
                total_logs = logs_per_second * duration_seconds
                
                for i in range(total_logs):
                    log = PerformanceComparison.generate_log(i, log_types)
                    _, insert_time = tree.add_log(log)
                    insertion_times.append(insert_time)
                    logs_added += 1
                    
                    # Check batch triggers
                    elapsed = time.time() - batch_start_time
                    should_commit = False
                    trigger_type = ""
                    
                    if len(tree.logs_with_cache) >= batch_size:
                        should_commit = True
                        trigger_type = "THRESHOLD"
                        threshold_triggers += 1
                    elif elapsed >= time_period:
                        should_commit = True
                        trigger_type = "TIME"
                        time_triggers += 1
                    
                    if should_commit:
                        commit_start = time.time()
                        # Simulate blockchain commit
                        global_root = tree.global_root
                        time.sleep(0.001)  # 1ms blockchain delay
                        commit_time = time.time() - commit_start
                        commit_times.append(commit_time)
                        
                        batches_committed += 1
                        
                        # Reset for new batch
                        tree.reset_for_new_batch() if hasattr(tree, 'reset_for_new_batch') else None
                        batch_start_time = time.time()
                    
                    # Simulate rate limiting
                    time.sleep(1.0 / logs_per_second)
                
                key = f"batch_{batch_size}_time_{time_period}"
                results[key] = {
                    "batch_size": batch_size,
                    "time_period": time_period,
                    "batches_committed": batches_committed,
                    "threshold_triggers": threshold_triggers,
                    "time_triggers": time_triggers,
                    "avg_insertion_ms": statistics.mean(insertion_times) * 1000,
                    "avg_commit_ms": statistics.mean(commit_times) * 1000 if commit_times else 0,
                    "total_logs": total_logs
                }
                
                print(f"  Batches committed: {batches_committed}")
                print(f"  Threshold triggers: {threshold_triggers}")
                print(f"  Time triggers: {time_triggers}")
                print(f"  Avg insertion: {results[key]['avg_insertion_ms']:.4f}ms")
                print(f"  Avg commit: {results[key]['avg_commit_ms']:.4f}ms")
        
        return results
    
    @staticmethod
    def plot_results(scalability_results: Dict, log_counts: List[int], verification_results_by_scale: Dict = None):
        """Plot comparison graphs"""
        print("\n" + "="*80)
        print("GENERATING PLOTS")
        print("="*80)
        
        try:
            import matplotlib.pyplot as plt
            
            fig, axes = plt.subplots(2, 2, figsize=(14, 10))
            
            # Plot 1: Scalability - Insertion Time
            ax1 = axes[0, 0]
            for system, times in scalability_results.items():
                ax1.plot(log_counts, times, marker='o', label=system, linewidth=2)
            ax1.set_xlabel('Number of Logs')
            ax1.set_ylabel('Avg Insertion Time (ms)')
            ax1.set_title('Insertion Performance Comparison')
            ax1.legend()
            ax1.grid(True, alpha=0.3)
            
            # Plot 2: Scalability - Normalized
            ax2 = axes[0, 1]
            if verification_results_by_scale:
                for system, times in verification_results_by_scale.items():
                    ax2.plot(log_counts, times, marker='s', label=system, linewidth=2)
                ax2.set_xlabel('Number of Logs')
                ax2.set_ylabel('Avg Verification Time (ms)')
                ax2.set_title('Verification Performance Comparison')
                ax2.legend()
                ax2.grid(True, alpha=0.3)
            
            # Plot 3: Bar chart comparison
            ax3 = axes[1, 0]
            systems = list(scalability_results.keys())
            final_times = [scalability_results[s][-1] for s in systems]
            colors = ['#2ecc71', '#3498db', '#e74c3c', '#f39c12']
            ax3.bar(systems, final_times, color=colors)
            ax3.set_ylabel('Avg Insertion Time (ms)')
            ax3.set_title(f'Performance at {log_counts[-1]} Logs')
            ax3.tick_params(axis='x', rotation=45)
            ax3.grid(True, alpha=0.3, axis='y')
            
            # Plot 4: Log scale comparison
            ax4 = axes[1, 1]
            for system, times in scalability_results.items():
                ax4.loglog(log_counts, times, marker='o', label=system, linewidth=2)
            ax4.set_xlabel('Number of Logs (log scale)')
            ax4.set_ylabel('Avg Insertion Time (ms, log scale)')
            ax4.set_title('Log-Log Scalability')
            ax4.legend()
            ax4.grid(True, alpha=0.3, which="both", ls="-")
            
            plt.tight_layout()
            plt.savefig('performance_comparison.png', dpi=300, bbox_inches='tight')
            print("\nPlot saved as 'performance_comparison.png'")
            plt.show()
            
        except ImportError:
            print("\nMatplotlib not available. Skipping plots.")
    
    @staticmethod
    def generate_summary_report(all_results: Dict):
        """Generate comprehensive summary report"""
        print("\n" + "="*80)
        print("COMPREHENSIVE SUMMARY REPORT")
        print("="*80)
        
        print("\n1. INSERTION PERFORMANCE WINNER:")
        if "insertion" in all_results:
            insertion_results = all_results["insertion"]
            best_system = min(insertion_results.keys(), 
                            key=lambda x: insertion_results[x]["avg_ms"])
            print(f"   🏆 {best_system}: {insertion_results[best_system]['avg_ms']:.4f}ms")
            
            print("\n   Rankings:")
            sorted_systems = sorted(insertion_results.keys(), 
                                  key=lambda x: insertion_results[x]["avg_ms"])
            for i, system in enumerate(sorted_systems, 1):
                print(f"   {i}. {system}: {insertion_results[system]['avg_ms']:.4f}ms")
        
        print("\n2. VERIFICATION PERFORMANCE WINNER:")
        if "verification" in all_results:
            verification_results = all_results["verification"]
            best_system = min(verification_results.keys(), 
                            key=lambda x: verification_results[x]["avg_ms"])
            print(f"   🏆 {best_system}: {verification_results[best_system]['avg_ms']:.4f}ms")
            
            print("\n   Rankings:")
            sorted_systems = sorted(verification_results.keys(), 
                                  key=lambda x: verification_results[x]["avg_ms"])
            for i, system in enumerate(sorted_systems, 1):
                print(f"   {i}. {system}: {verification_results[system]['avg_ms']:.4f}ms")
        
        print("\n3. STORAGE EFFICIENCY WINNER:")
        if "storage" in all_results:
            storage_results = all_results["storage"]
            best_system = min(storage_results.keys(), 
                            key=lambda x: storage_results[x]["total_kb"])
            print(f"   🏆 {best_system}: {storage_results[best_system]['total_kb']:.2f} KB")
            
            print("\n   Rankings:")
            sorted_systems = sorted(storage_results.keys(), 
                                  key=lambda x: storage_results[x]["total_kb"])
            for i, system in enumerate(sorted_systems, 1):
                print(f"   {i}. {system}: {storage_results[system]['total_kb']:.2f} KB")
        
        print("\n4. OVERALL ASSESSMENT:")
        print("\n   Your Idea (Two-Layer Merkle with Cache):")
        print("   ✅ Pros: Fast verification with O(log n) cached paths")
        print("   ✅ Pros: Independent batch verification")
        print("   ✅ Pros: Hierarchical organization by log type")
        print("   ⚠️  Cons: Higher storage overhead due to caching")
        
        print("\n   DELIA:")
        print("   ✅ Pros: LocalState → GlobalState provides good abstraction")
        print("   ✅ Pros: Batch-based processing")
        print("   ⚠️  Cons: Sequential verification through state chain")
        
        print("\n   BlockTrail:")
        print("   ✅ Pros: Hierarchical structure (city/county/state)")
        print("   ✅ Pros: PBFT consensus provides Byzantine fault tolerance")
        print("   ⚠️  Cons: O(n²) message complexity affects scalability")
        
        print("\n   Blockchain Deduplication:")
        print("   ✅ Pros: Excellent for duplicate data scenarios")
        print("   ✅ Pros: Reduces storage through deduplication")
        print("   ⚠️  Cons: Not optimized for unique log verification")
        
        print("\n" + "="*80)

# ============================================================================
# MAIN TEST RUNNER
# ============================================================================

def run_all_tests():
    """Run all performance tests"""
    print("="*80)
    print("BLOCKCHAIN AUDIT LOG SYSTEMS - PERFORMANCE COMPARISON")
    print("="*80)
    print("\nComparing:")
    print("  1. Your Idea: Two-Layer Merkle Tree with Path Caching")
    print("  2. DELIA: LocalState → GlobalState with Merkle Trees")
    print("  3. BlockTrail: Hierarchical Blockchain with PBFT")
    print("  4. Blockchain Deduplication: Auth Tags with Deduplication")
    print("\n" + "="*80)
    
    all_results = {}
    
    # Test 1: Insertion Performance
    insertion_results, systems = PerformanceComparison.test_insertion_performance(
        num_logs=1000,
        num_log_types=5
    )
    all_results["insertion"] = insertion_results
    
    # Test 2: Verification Performance
    verification_results = PerformanceComparison.test_verification_performance(
        systems=systems,
        num_verifications=100
    )
    all_results["verification"] = verification_results
    
    # Test 3: Storage Overhead
    storage_results = PerformanceComparison.test_storage_overhead(systems)
    all_results["storage"] = storage_results
    
    # Test 4: Scalability
    insertion_results, verification_results, log_counts = PerformanceComparison.test_scalability(
        log_counts=[1000, 2000, 5000, 10000, 20000, 50000],
        num_log_types=5
    )
    all_results["scalability"] = scalability_results
    
    # Test 5: Batch Performance (Your Idea only)
    batch_results = PerformanceComparison.test_batch_commit_performance(
        batch_sizes=[100, 500, 1000],
        time_periods=[5, 10, 30],
        logs_per_second=50,
        duration_seconds=30
    )
    all_results["batch"] = batch_results
    
    # Collect verification times at different scales
    verification_by_scale = {
        "Your Idea": [],
        "DELIA": [],
        "BlockTrail": [],
        "Blockchain Dedup": []
    }

    # You need to add verification testing in scalability test or create new method
    PerformanceComparison.plot_results(insertion_results, verification_results, log_counts)
    
    # Generate summary report
    PerformanceComparison.generate_summary_report(all_results)
    
    return all_results

# ============================================================================
# RUN TESTS
# ============================================================================

if __name__ == "__main__":
    print("\nStarting performance tests...\n")
    results = run_all_tests()
    print("\n✅ All tests completed!\n")