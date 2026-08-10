#!/usr/bin/env python3
"""
Improved Bi-GCN Training with Official Contest Data Integration and Augmented Data Support
Maintains 30 features while improving detection accuracy
Now with resume training capability
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torch_geometric.nn import GATConv, SAGEConv, global_mean_pool, global_max_pool
from torch_geometric.data import Data, DataLoader, Batch
from torch.optim.lr_scheduler import OneCycleLR
import numpy as np
import pickle
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix, roc_auc_score
from sklearn.preprocessing import StandardScaler
import argparse
from tqdm import tqdm
import os
import re
from collections import defaultdict, deque, Counter
import networkx as nx
from multiprocessing import Pool, cpu_count
import time
from functools import partial
import random
from scipy.sparse import csr_matrix, lil_matrix
from scipy.sparse.csgraph import shortest_path, connected_components
import warnings
warnings.filterwarnings('ignore')

# Set random seeds for reproducibility
def set_seed(seed=42):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)

class WeightedFocalLoss(nn.Module):
    """Weighted Focal loss for extreme class imbalance (1:8 trojan:clean gates)"""
    def __init__(self, alpha=0.125, gamma=2.0, pos_weight=5.0):
        super(WeightedFocalLoss, self).__init__()
        self.alpha = alpha  # Weight for negative class
        self.gamma = gamma
        self.pos_weight = pos_weight  # Additional weight for positive class
        
    def forward(self, logits, targets):
        ce_loss = F.cross_entropy(logits, targets, reduction='none')
        pt = torch.exp(-ce_loss)
        focal_loss = (1 - pt) ** self.gamma * ce_loss
        
        # Apply alpha weighting
        alpha_t = torch.where(targets == 1, 1 - self.alpha, self.alpha)
        focal_loss = alpha_t * focal_loss
        
        # Apply additional positive class weight
        pos_weight_t = torch.where(targets == 1, self.pos_weight, 1.0)
        focal_loss = pos_weight_t * focal_loss
        
        return focal_loss.mean()

class ImprovedBiGCN(nn.Module):
    """Enhanced Bi-directional GCN optimized for Trojan detection"""
    def __init__(self, input_dim=30, hidden_dim=96, output_dim=2, dropout_rate=0.3, num_layers=4):
        super(ImprovedBiGCN, self).__init__()
        
        # Enhanced input projection
        self.input_proj = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout_rate)
        )
        
        # Multi-layer GCN with attention
        self.num_layers = num_layers
        self.fw_layers = nn.ModuleList()  # Forward layers
        self.bw_layers = nn.ModuleList()  # Backward layers
        self.layer_norms = nn.ModuleList()
        self.attention_weights = nn.ModuleList()
        
        for i in range(num_layers):
            if i % 2 == 0:
                # Even layers: SAGE forward, GAT backward
                self.fw_layers.append(SAGEConv(hidden_dim, hidden_dim))
                self.bw_layers.append(GATConv(hidden_dim, hidden_dim, heads=4, concat=False, dropout=dropout_rate))
            else:
                # Odd layers: GAT forward, SAGE backward
                self.fw_layers.append(GATConv(hidden_dim, hidden_dim, heads=4, concat=False, dropout=dropout_rate))
                self.bw_layers.append(SAGEConv(hidden_dim, hidden_dim))
            
            self.layer_norms.append(nn.LayerNorm(hidden_dim * 2))
            self.attention_weights.append(nn.Linear(hidden_dim * 2, 1))
        
        # Gate-level attention mechanism
        self.gate_attention = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            nn.Linear(hidden_dim, 1),
            nn.Sigmoid()
        )
        
        # Classifier with residual connections
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.LayerNorm(hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            nn.Linear(hidden_dim // 2, output_dim)
        )
        
        self.dropout = nn.Dropout(dropout_rate)
        
    def forward(self, x, edge_index_fw, edge_index_bw, batch=None):
        # Initial projection
        x = self.input_proj(x)
        x_init = x
        
        # Multi-layer GCN processing
        layer_outputs = []
        for i in range(self.num_layers):
            # Forward and backward propagation
            h_fw = F.relu(self.fw_layers[i](x, edge_index_fw))
            h_bw = F.relu(self.bw_layers[i](x, edge_index_bw))
            
            # Concatenate and normalize
            h_combined = torch.cat([h_fw, h_bw], dim=1)
            h_combined = self.layer_norms[i](h_combined)
            h_combined = self.dropout(h_combined)
            
            # Attention weighting
            att_weight = self.attention_weights[i](h_combined)
            layer_outputs.append(h_combined * torch.sigmoid(att_weight))
            
            # Update x with residual
            x = x + 0.1 * h_fw
        
        # Combine all layers with weighted sum
        final_features = sum(layer_outputs) / len(layer_outputs)
        
        # Gate-level attention
        gate_scores = self.gate_attention(final_features)
        final_features = final_features * gate_scores
        
        # Classification
        out = self.classifier(final_features)
        
        return out, final_features

class FastNetlistParser:
    """Optimized parser with enhanced DFF handling"""
    
    def __init__(self):
        self.gate_types = {
            'and': 0, 'or': 1, 'not': 2, 'inv': 2,
            'nand': 3, 'nor': 4, 'xor': 5, 'xnor': 6,
            'buf': 7, 'buff': 7, 'dff': 8
        }
    
    def parse_netlist_fast(self, filepath):
        """Parse netlist with improved DFF detection"""
        with open(filepath, 'r') as f:
            content = f.read()
        
        gates = []
        
        # Parse standard gates
        gate_pattern = re.compile(r'(\w+)\s+(\w+)\s*\((.*?)\);')
        
        for match in gate_pattern.finditer(content):
            gate_type = match.group(1).lower()
            if gate_type in self.gate_types and gate_type != 'dff':
                gate_name = match.group(2)
                connections = [c.strip() for c in match.group(3).split(',')]
                gates.append({
                    'name': gate_name,
                    'type': self.gate_types[gate_type],
                    'inputs': connections[1:],
                    'output': connections[0],
                    'is_dff': False
                })
        
        # Parse DFF gates - handle your specific format
        # dff g2088 (.RN(intstart_reg), .SN(1'b1), .CK(clk_i), .D(_1551_), .Q(writeram_node));
        dff_pattern = re.compile(r'dff\s+(\w+)\s*\((.*?)\);', re.DOTALL | re.IGNORECASE)
        
        for match in dff_pattern.finditer(content):
            gate_name = match.group(1)
            connections_str = match.group(2)
            
            # Parse named connections
            conn_dict = {}
            conn_pattern = re.compile(r'\.(\w+)\s*\(([^)]+)\)')
            for conn_match in conn_pattern.finditer(connections_str):
                pin_name = conn_match.group(1)
                pin_value = conn_match.group(2).strip()
                conn_dict[pin_name] = pin_value
            
            # Extract DFF connections
            dff_gate = {
                'name': gate_name,
                'type': self.gate_types['dff'],
                'is_dff': True,
                'inputs': [],
                'output': conn_dict.get('Q', conn_dict.get('q', '')),
                'clock': conn_dict.get('CK', conn_dict.get('clk', '')),
                'data': conn_dict.get('D', conn_dict.get('d', '')),
                'reset': conn_dict.get('RN', conn_dict.get('rst_n', '')),
                'set': conn_dict.get('SN', '1\'b1'),
                'reset_type': 'async_low' if 'RN' in conn_dict else 'sync'
            }
            
            # Set inputs for DFF
            dff_inputs = []
            if dff_gate['clock']:
                dff_inputs.append(dff_gate['clock'])
            if dff_gate['data']:
                dff_inputs.append(dff_gate['data'])
            if dff_gate['reset'] and dff_gate['reset'] != '1\'b1':
                dff_inputs.append(dff_gate['reset'])
            if dff_gate['set'] and dff_gate['set'] != '1\'b1':
                dff_inputs.append(dff_gate['set'])
            
            dff_gate['inputs'] = dff_inputs
            gates.append(dff_gate)
        
        return gates
    
    def build_graph_fast(self, gates):
        """Build graph with optimized edge creation"""
        num_gates = len(gates)
        edge_list_fw = []
        edge_list_bw = []
        
        # Build wire-to-gate mapping
        output_map = {}
        input_map = defaultdict(list)
        
        for i, gate in enumerate(gates):
            output_map[gate['output']] = i
            for inp in gate['inputs']:
                input_map[inp].append(i)
        
        # Create edges efficiently
        for wire, consumers in input_map.items():
            if wire in output_map:
                producer = output_map[wire]
                for consumer in consumers:
                    edge_list_fw.append([producer, consumer])
                    edge_list_bw.append([consumer, producer])
        
        return edge_list_fw, edge_list_bw, num_gates
    
    def compute_graph_metrics_optimized(self, gates, edge_list_fw, num_gates):
        """Optimized graph metrics computation"""
        if not edge_list_fw:
            return None
            
        rows = [e[0] for e in edge_list_fw]
        cols = [e[1] for e in edge_list_fw]
        data = [1] * len(edge_list_fw)
        adj_matrix = csr_matrix((data, (rows, cols)), shape=(num_gates, num_gates))
        
        # Compute basic metrics
        in_degree = np.array(adj_matrix.sum(axis=0)).flatten()
        out_degree = np.array(adj_matrix.sum(axis=1)).flatten()
        
        # Identify special nodes
        primary_inputs = np.where(in_degree == 0)[0]
        primary_outputs = np.where(out_degree == 0)[0]
        dff_indices = [i for i, g in enumerate(gates) if g['is_dff']]
        
        # PageRank
        pagerank = np.ones(num_gates) / num_gates
        damping = 0.85
        for _ in range(20):
            sink_pr = damping * pagerank[out_degree == 0].sum() / num_gates
            pagerank = (1 - damping) / num_gates + sink_pr + damping * adj_matrix.T.dot(pagerank / (out_degree + 1e-10))
        
        # Clustering coefficient
        adj_undirected = (adj_matrix + adj_matrix.T).astype(bool).astype(float)
        triangles = np.zeros(num_gates)
        for i in range(num_gates):
            if out_degree[i] + in_degree[i] > 1:
                row = adj_undirected.getrow(i)
                neighbors = row.indices
                if len(neighbors) > 1:
                    subgraph = adj_undirected[neighbors][:, neighbors]
                    triangles[i] = subgraph.sum() / 2
        
        max_triangles = (in_degree + out_degree) * (in_degree + out_degree - 1) / 2
        clustering = np.divide(triangles, max_triangles, out=np.zeros_like(triangles), where=max_triangles > 0)
        
        # Betweenness centrality approximation
        sample_size = min(50, max(5, num_gates // 10))
        if sample_size > 5 and num_gates > 10:
            sampled_nodes = np.random.choice(num_gates, sample_size, replace=False)
            betweenness = self.approximate_betweenness(adj_matrix, sampled_nodes)
        else:
            betweenness = np.zeros(num_gates)
        
        # Distance calculations
        max_sources = min(20, len(primary_inputs)) if len(primary_inputs) > 0 else 0
        dist_from_inputs = np.full(num_gates, np.inf)
        dist_to_outputs = np.full(num_gates, np.inf)
        dist_from_dffs = np.full(num_gates, np.inf)
        
        if max_sources > 0:
            d = shortest_path(adj_matrix, directed=True, indices=primary_inputs[:max_sources])
            dist_from_inputs = np.min(d, axis=0)
            dist_from_inputs = np.minimum(dist_from_inputs, 50)
            
        if len(primary_outputs) > 0:
            d = shortest_path(adj_matrix.T, directed=True, indices=primary_outputs[:min(20, len(primary_outputs))])
            dist_to_outputs = np.min(d, axis=0)
            dist_to_outputs = np.minimum(dist_to_outputs, 50)
            
        if len(dff_indices) > 0:
            d = shortest_path(adj_matrix, directed=True, indices=dff_indices[:min(40, len(dff_indices))])
            dist_from_dffs = np.min(d, axis=0)
            for dff_idx in dff_indices:
                dist_from_dffs[dff_idx] = np.inf
            dist_from_dffs = np.minimum(dist_from_dffs, 50)
        
        return {
            'in_degree': in_degree,
            'out_degree': out_degree,
            'pagerank': pagerank,
            'clustering': clustering,
            'betweenness': betweenness,
            'dist_from_inputs': dist_from_inputs,
            'dist_to_outputs': dist_to_outputs,
            'dist_from_dffs': dist_from_dffs,
            'adj_matrix': adj_matrix,
            'primary_inputs': primary_inputs,
            'primary_outputs': primary_outputs,
            'dff_indices': dff_indices
        }
    
    def approximate_betweenness(self, adj_matrix, sample_nodes):
        """Fast approximation of betweenness centrality"""
        n = adj_matrix.shape[0]
        betweenness = np.zeros(n)
        
        for s in sample_nodes:
            dist, predecessors = self.bfs_shortest_path(adj_matrix, s)
            
            delta = np.zeros(n)
            sigma = np.zeros(n)
            sigma[s] = 1
            
            for v in np.argsort(dist):
                if dist[v] < np.inf:
                    for u in predecessors[v]:
                        if dist[u] == dist[v] - 1:
                            sigma[v] += sigma[u]
            
            for v in np.argsort(-dist):
                if v != s and dist[v] < np.inf:
                    for u in predecessors[v]:
                        if dist[u] == dist[v] - 1:
                            delta[u] += (sigma[u] / (sigma[v] + 1e-10)) * (1 + delta[v])
                    betweenness[v] += delta[v]
        
        betweenness = betweenness * n / len(sample_nodes)
        return betweenness / ((n - 1) * (n - 2) + 1e-10)
    
    def bfs_shortest_path(self, adj_matrix, source):
        """BFS for single source shortest paths"""
        n = adj_matrix.shape[0]
        dist = np.full(n, np.inf)
        dist[source] = 0
        predecessors = defaultdict(list)
        
        queue = deque([source])
        while queue:
            u = queue.popleft()
            neighbors = adj_matrix.getrow(u).indices
            
            for v in neighbors:
                if dist[v] == np.inf:
                    dist[v] = dist[u] + 1
                    queue.append(v)
                
                if dist[v] == dist[u] + 1:
                    predecessors[v].append(u)
        
        return dist, predecessors
    
    def extract_features_enhanced(self, gates, edge_list_fw, num_gates):
        """Enhanced 30 features optimized for Trojan detection"""
        features = np.zeros((num_gates, 30))
        
        # Gate type features (one-hot) - 9 features
        for i, gate in enumerate(gates):
            features[i, gate['type']] = 1
            features[i, 9] = len(gate['inputs'])  # Fan-in
            
            # DFF-specific features (features 10-14)
            if gate['is_dff']:
                features[i, 10] = 1  # Is DFF
                features[i, 11] = 1 if gate.get('reset_type') == 'async_low' else 0
                features[i, 12] = 1 if gate.get('set', '1\'b1') != '1\'b1' else 0
                features[i, 13] = 1 if 'clk' in gate.get('clock', '').lower() else 0
                features[i, 14] = 1 if gate.get('reset', '') not in ['', '1\'b1'] else 0
        
        # Compute graph metrics
        if edge_list_fw:
            metrics = self.compute_graph_metrics_optimized(gates, edge_list_fw, num_gates)
            
            if metrics:
                # Basic graph features
                features[:, 15] = metrics['out_degree']  # Fan-out
                features[:, 16] = metrics['in_degree'] / (num_gates + 1)
                features[:, 17] = metrics['out_degree'] / (num_gates + 1)
                features[:, 18] = metrics['pagerank'] * 1000
                features[:, 19] = metrics['clustering']
                features[:, 20] = metrics['betweenness'] * 100
                
                # Distance features (normalized)
                features[:, 21] = 1.0 / (metrics['dist_from_inputs'] + 1)
                features[:, 22] = 1.0 / (metrics['dist_to_outputs'] + 1)
                features[:, 23] = 1.0 / (metrics['dist_from_dffs'] + 1)
                
                # Replace inf values with 0
                features[np.isinf(features)] = 0
                features[np.isnan(features)] = 0
                
                # Enhanced neighborhood analysis for Trojan detection
                adj_matrix = metrics['adj_matrix']
                gate_types = np.array([g['type'] for g in gates])
                is_dff = np.array([g['is_dff'] for g in gates])
                
                # Detect suspicious patterns
                for i in range(num_gates):
                    # Get all neighbors
                    out_neighbors = adj_matrix.getrow(i).indices
                    in_neighbors = adj_matrix.getcol(i).tocsr().indices
                    all_neighbors = np.unique(np.concatenate([out_neighbors, in_neighbors]))
                    
                    if len(all_neighbors) > 0:
                        # Feature 24: XOR/XNOR ratio (critical for crypto Trojans)
                        xor_count = np.sum(np.isin(gate_types[all_neighbors], [5, 6]))
                        features[i, 24] = xor_count / len(all_neighbors)
                        
                        # Feature 25: Multiple DFF connections (not just ratio)
                        # This is what you asked about - gates connected to multiple DFFs
                        dff_neighbors = np.sum(is_dff[all_neighbors])
                        features[i, 25] = 1 if dff_neighbors >= 2 else 0  # Binary feature
                        
                        # Feature 26: High-degree nodes in neighborhood
                        neighbor_degrees = metrics['in_degree'][all_neighbors] + metrics['out_degree'][all_neighbors]
                        high_degree_threshold = np.percentile(metrics['in_degree'] + metrics['out_degree'], 90)
                        high_degree_count = np.sum(neighbor_degrees > high_degree_threshold)
                        features[i, 26] = high_degree_count / len(all_neighbors)
                        
                        # Feature 27: Reconvergent fanout indicator
                        if len(out_neighbors) > 1:
                            # Check if outputs reconverge
                            reconverges = False
                            for j in range(len(out_neighbors)-1):
                                for k in range(j+1, len(out_neighbors)):
                                    # Check 2-hop neighbors
                                    desc_j = adj_matrix.getrow(out_neighbors[j]).indices
                                    desc_k = adj_matrix.getrow(out_neighbors[k]).indices
                                    if len(np.intersect1d(desc_j, desc_k)) > 0:
                                        reconverges = True
                                        break
                                if reconverges:
                                    break
                            features[i, 27] = 1 if reconverges else 0
                        else:
                            features[i, 27] = 0
                    
                    # Feature 28: Unusual fanout pattern (potential covert channel)
                    features[i, 28] = 1 if metrics['out_degree'][i] > 5 else 0
                    
                    # Feature 29: Part of potential feedback loop
                    # Simple check: can we reach this node from its descendants?
                    if len(out_neighbors) > 0:
                        # Check if any path exists from descendants back to this node
                        feedback = 0
                        for neighbor in out_neighbors[:5]:  # Check first 5 to limit computation
                            try:
                                path_exists = shortest_path(adj_matrix, directed=True, indices=[neighbor], return_predecessors=False)
                                if path_exists[0, i] < np.inf:
                                    feedback = 1
                                    break
                            except:
                                pass
                        features[i, 29] = feedback
                    else:
                        features[i, 29] = 0
        
        return features


def load_official_trojan_labels(result_file, gates, circuit_name):
    """Load labels from official result files"""
    labels = np.zeros(len(gates), dtype=int)
    
    if not os.path.exists(result_file):
        print(f"Warning: Result file not found for {circuit_name}")
        return labels
    
    with open(result_file, 'r') as f:
        lines = f.readlines()
    
    # Check if it's a Trojan circuit
    if lines[0].strip() != 'TROJANED':
        return labels  # All zeros for non-Trojan circuit
    
    # Create gate name to index mapping
    gate_name_to_idx = {gate['name']: i for i, gate in enumerate(gates)}
    
    # Parse Trojan gates
    in_trojan_section = False
    trojan_count = 0
    
    for line in lines:
        line = line.strip()
        if line == 'TROJAN_GATES':
            in_trojan_section = True
        elif line == 'END_TROJAN_GATES':
            break
        elif in_trojan_section and line:
            if line in gate_name_to_idx:
                labels[gate_name_to_idx[line]] = 1
                trojan_count += 1
    
    if trojan_count > 0:
        print(f"  Loaded {trojan_count} Trojan gates for {circuit_name}")
    
    return labels


def process_official_circuit(args):
    """Process official contest circuits (both trojan and trojan_free)"""
    design_file, result_file, circuit_name, is_trojan_circuit = args
    parser = FastNetlistParser()
    
    try:
        # Parse netlist
        gates = parser.parse_netlist_fast(design_file)
        edge_list_fw, edge_list_bw, num_gates = parser.build_graph_fast(gates)
        features = parser.extract_features_enhanced(gates, edge_list_fw, num_gates)
        
        # Convert to PyTorch tensors
        edge_index_fw = torch.LongTensor(edge_list_fw).t().contiguous()
        edge_index_bw = torch.LongTensor(edge_list_bw).t().contiguous()
        
        # Load labels
        if result_file and os.path.exists(result_file):
            labels = load_official_trojan_labels(result_file, gates, circuit_name)
        else:
            labels = np.zeros(num_gates, dtype=int)  # All clean for trojan_free
        
        # Count DFFs
        dff_count = sum(1 for g in gates if g['is_dff'])
        
        return {
            'features': features,
            'edge_index_fw': edge_index_fw,
            'edge_index_bw': edge_index_bw,
            'labels': labels,
            'circuit_name': f"official_{circuit_name}",
            'num_gates': num_gates,
            'num_dffs': dff_count,
            'is_trojan_circuit': is_trojan_circuit,
            'source': 'official'
        }
    except Exception as e:
        print(f"Error processing official circuit {circuit_name}: {e}")
        import traceback
        traceback.print_exc()
        return None


def process_augmented_circuit(args):
    """Process augmented data circuit"""
    design_file, result_file, circuit_name, is_trojan_circuit = args
    parser = FastNetlistParser()
    
    try:
        # Parse netlist
        gates = parser.parse_netlist_fast(design_file)
        edge_list_fw, edge_list_bw, num_gates = parser.build_graph_fast(gates)
        features = parser.extract_features_enhanced(gates, edge_list_fw, num_gates)
        
        # Convert to PyTorch tensors
        edge_index_fw = torch.LongTensor(edge_list_fw).t().contiguous()
        edge_index_bw = torch.LongTensor(edge_list_bw).t().contiguous()
        
        # Load labels
        if result_file and os.path.exists(result_file):
            labels = load_official_trojan_labels(result_file, gates, circuit_name)
        else:
            labels = np.zeros(num_gates, dtype=int)  # All clean for trojan_free
        
        # Count DFFs
        dff_count = sum(1 for g in gates if g['is_dff'])
        
        return {
            'features': features,
            'edge_index_fw': edge_index_fw,
            'edge_index_bw': edge_index_bw,
            'labels': labels,
            'circuit_name': circuit_name,
            'num_gates': num_gates,
            'num_dffs': dff_count,
            'is_trojan_circuit': is_trojan_circuit,
            'source': 'augmented'
        }
    except Exception as e:
        print(f"Error processing augmented circuit {circuit_name}: {e}")
        import traceback
        traceback.print_exc()
        return None


def process_circuit_parallel(args):
    """Process a single circuit (for parallel processing)"""
    filepath, is_trojan, circuit_name, base_dir = args
    parser = FastNetlistParser()
    
    try:
        # Parse netlist
        gates = parser.parse_netlist_fast(filepath)
        edge_list_fw, edge_list_bw, num_gates = parser.build_graph_fast(gates)
        features = parser.extract_features_enhanced(gates, edge_list_fw, num_gates)
        
        # Convert to PyTorch tensors
        edge_index_fw = torch.LongTensor(edge_list_fw).t().contiguous()
        edge_index_bw = torch.LongTensor(edge_list_bw).t().contiguous()
        
        # Load labels
        if is_trojan:
            ref_path = os.path.join(os.path.dirname(filepath), 'reference.txt')
            labels = load_reference_labels(ref_path, gates)
            
            if labels.sum() == 0:
                print(f"Warning: No Trojan labels found for {circuit_name}")
        else:
            labels = np.zeros(num_gates, dtype=int)
        
        # Count DFFs
        dff_count = sum(1 for g in gates if g['is_dff'])
        
        return {
            'features': features,
            'edge_index_fw': edge_index_fw,
            'edge_index_bw': edge_index_bw,
            'labels': labels,
            'circuit_name': circuit_name,
            'num_gates': num_gates,
            'num_dffs': dff_count,
            'is_trojan_circuit': is_trojan,
            'source': 'training'
        }
    except Exception as e:
        print(f"Error processing {circuit_name}: {e}")
        import traceback
        traceback.print_exc()
        return None


def load_reference_labels(reference_path, gates):
    """Load actual Trojan labels from reference.txt"""
    labels = np.zeros(len(gates), dtype=int)
    
    if os.path.exists(reference_path):
        with open(reference_path, 'r') as f:
            content = f.read().strip()
        
        # Create gate name to index mapping
        gate_name_to_idx = {gate['name']: i for i, gate in enumerate(gates)}
        
        # Parse reference file
        lines = content.split('\n')
        in_trojan_section = False
        trojan_gate_names = set()
        
        for line in lines:
            line = line.strip()
            if line == 'TROJAN_GATES':
                in_trojan_section = True
                continue
            elif line == 'END_TROJAN_GATES':
                in_trojan_section = False
                break
            elif in_trojan_section and line and line != 'TROJANED':
                trojan_gate_names.add(line)
        
        # Mark trojan gates
        trojan_count = 0
        for gate_name in trojan_gate_names:
            if gate_name in gate_name_to_idx:
                labels[gate_name_to_idx[gate_name]] = 1
                trojan_count += 1
        
        if trojan_count > 0:
            print(f"  Found {trojan_count} Trojan gates out of {len(trojan_gate_names)} listed")
        
    return labels


class OptimizedDataLoader:
    """Data loader with official data integration"""
    
    def __init__(self, cache_dir='./cache'):
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)
        self.scaler = StandardScaler()
    
    def load_all_data_with_official(self, trojan_dir, trojan_free_dir, official_dir, num_workers=None):
        """Load training data and official contest data (both trojan and trojan_free)"""
        if num_workers is None:
            num_workers = min(cpu_count() - 1, 8)
        
        # Check cache
        cache_file = os.path.join(self.cache_dir, 'processed_all_with_official.pkl')
        if os.path.exists(cache_file):
            print("Loading from cache...")
            with open(cache_file, 'rb') as f:
                data_list = pickle.load(f)
                # Load scaler
                scaler_file = os.path.join(self.cache_dir, 'feature_scaler_all_official.pkl')
                if os.path.exists(scaler_file):
                    with open(scaler_file, 'rb') as f:
                        self.scaler = pickle.load(f)
                return data_list
        
        # Prepare file lists
        tasks = []
        official_tasks = []
        
        # Official contest data - Trojaned circuits
        if official_dir and os.path.exists(official_dir):
            trojan_dir_official = os.path.join(official_dir, 'trojan')
            if os.path.exists(trojan_dir_official):
                for i in range(20):  # designs 0-19
                    design_file = os.path.join(trojan_dir_official, f'design{i}.v')
                    result_file = os.path.join(trojan_dir_official, f'result{i}.txt')
                    if os.path.exists(design_file):
                        official_tasks.append((design_file, result_file, f'trojan_design{i}', True))
            
            # Official contest data - Clean circuits
            trojan_free_official = os.path.join(official_dir, 'trojan_free')
            if os.path.exists(trojan_free_official):
                for i in range(20, 30):  # designs 20-29
                    design_file = os.path.join(trojan_free_official, f'design{i}.v')
                    if os.path.exists(design_file):
                        official_tasks.append((design_file, None, f'clean_design{i}', False))
        
        # Training data - Trojan-inserted circuits
        for subdir in os.listdir(trojan_dir):
            subdir_path = os.path.join(trojan_dir, subdir)
            if os.path.isdir(subdir_path):
                for file in os.listdir(subdir_path):
                    if file.endswith('.v') and file != 'reference.txt':
                        filepath = os.path.join(subdir_path, file)
                        tasks.append((filepath, True, subdir, trojan_dir))
        
        # Training data - Trojan-free circuits
        for file in os.listdir(trojan_free_dir):
            if file.endswith('_converted.v'):
                filepath = os.path.join(trojan_free_dir, file)
                circuit_name = file.replace('_converted.v', '')
                tasks.append((filepath, False, circuit_name, trojan_free_dir))
        
        print(f"Processing {len(tasks)} training circuits and {len(official_tasks)} official circuits...")
        
        # Process in parallel
        data_list = []
        
        # Process training data
        with Pool(num_workers) as pool:
            results = list(tqdm(
                pool.imap(process_circuit_parallel, tasks),
                total=len(tasks),
                desc="Loading training circuits"
            ))
        data_list.extend([r for r in results if r is not None])
        
        # Process official data
        if official_tasks:
            with Pool(num_workers) as pool:
                results = list(tqdm(
                    pool.imap(process_official_circuit, official_tasks),
                    total=len(official_tasks),
                    desc="Loading official circuits"
                ))
            data_list.extend([r for r in results if r is not None])
        
        # Normalize features
        all_features = np.vstack([d['features'] for d in data_list])
        self.scaler.fit(all_features)
        
        for d in data_list:
            d['features'] = self.scaler.transform(d['features'])
        
        # Save to cache
        with open(cache_file, 'wb') as f:
            pickle.dump(data_list, f)
        
        # Save scaler
        with open(os.path.join(self.cache_dir, 'feature_scaler_all_official.pkl'), 'wb') as f:
            pickle.dump(self.scaler, f)
        
        return data_list
    
    def load_augmented_data(self, augmented_dir, num_workers=None):
        """Load augmented data with flexible file matching
        - Files matching exactly design{N}.v where N≤20 -> TEST set
        - All other design*.v files -> TRAIN/VAL split
        """
        if num_workers is None:
            num_workers = min(cpu_count() - 1, 8)
        
        trojan_dir = os.path.join(augmented_dir, 'trojan')
        trojan_free_dir = os.path.join(augmented_dir, 'trojan_free')
        
        test_tasks = []
        train_tasks = []
        
        # Process trojan circuits
        if os.path.exists(trojan_dir):
            design_files = [f for f in os.listdir(trojan_dir) if f.startswith('design') and f.endswith('.v')]
            result_files = [f for f in os.listdir(trojan_dir) if f.startswith('result') and f.endswith('.txt')]
            
            # Create a mapping from design files to result files
            result_map = {}
            for result_file in result_files:
                # Extract the base name from result file
                base_name = result_file[6:-4]  # Remove 'result' prefix and '.txt' suffix
                result_map[base_name] = result_file
            
            for design_file in design_files:
                filepath = os.path.join(trojan_dir, design_file)
                
                # Check if this is an original test file (design0.v to design20.v)
                exact_match = re.match(r'^design(\d+)\.v$', design_file)
                if exact_match and int(exact_match.group(1)) <= 20:
                    # This is a test file
                    design_num = int(exact_match.group(1))
                    result_file = os.path.join(trojan_dir, f'result{design_num}.txt')
                    test_tasks.append((filepath, result_file, f'test_trojan_design{design_num}', True))
                else:
                    # This is a training file - need to find corresponding result file
                    # Remove 'design' prefix and '.v' suffix to get base name
                    base_name = design_file[6:-2]  # Remove 'design' and '.v'
                    
                    # Look for matching result file
                    result_file = None
                    if base_name in result_map:
                        result_file = os.path.join(trojan_dir, result_map[base_name])
                    else:
                        # Try alternative patterns
                        # For files like design_barrel_shifter_64bit_tj5_aug_15.v
                        # The result might be result_barrel_shifter_64bit_tj5_aug_15.txt
                        potential_result = f'result{base_name}.txt'
                        if potential_result in result_files:
                            result_file = os.path.join(trojan_dir, potential_result)
                    
                    if result_file and os.path.exists(result_file):
                        train_tasks.append((filepath, result_file, design_file.replace('.v', ''), True))
                    else:
                        print(f"Warning: No result file found for {design_file}")
                        # Still add it but without labels
                        train_tasks.append((filepath, None, design_file.replace('.v', ''), True))
        
        # Process trojan-free circuits
        if os.path.exists(trojan_free_dir):
            design_files = [f for f in os.listdir(trojan_free_dir) if f.startswith('design') and f.endswith('.v')]
            
            for design_file in design_files:
                filepath = os.path.join(trojan_free_dir, design_file)
                
                # Check if this is an original test file
                exact_match = re.match(r'^design(\d+)\.v$', design_file)
                if exact_match and int(exact_match.group(1)) <= 20:
                    # This is a test file
                    design_num = int(exact_match.group(1))
                    test_tasks.append((filepath, None, f'test_clean_design{design_num}', False))
                else:
                    # This is a training file
                    train_tasks.append((filepath, None, design_file.replace('.v', ''), False))
        
        # Split training data 80:20 for train:val
        random.shuffle(train_tasks)
        split_idx = int(0.8 * len(train_tasks))
        final_train_tasks = train_tasks[:split_idx]
        val_tasks = train_tasks[split_idx:]
        
        print(f"\nAugmented data split:")
        print(f"  Test (original files only): {len(test_tasks)}")
        print(f"  Train (augmented files): {len(final_train_tasks)}")
        print(f"  Val (augmented files): {len(val_tasks)}")
        
        # Count by type
        test_trojan = sum(1 for _, _, _, is_trojan in test_tasks if is_trojan)
        test_clean = len(test_tasks) - test_trojan
        train_trojan = sum(1 for _, _, _, is_trojan in final_train_tasks if is_trojan)
        train_clean = len(final_train_tasks) - train_trojan
        val_trojan = sum(1 for _, _, _, is_trojan in val_tasks if is_trojan)
        val_clean = len(val_tasks) - val_trojan
        
        print(f"\nDetailed breakdown:")
        print(f"  Test: {test_trojan} trojan, {test_clean} clean")
        print(f"  Train: {train_trojan} trojan, {train_clean} clean")
        print(f"  Val: {val_trojan} trojan, {val_clean} clean")
        
        # Show some example files being processed
        print(f"\nExample files being processed:")
        if final_train_tasks:
            for i in range(min(3, len(final_train_tasks))):
                design_path, result_path, name, is_trojan = final_train_tasks[i]
                print(f"  Train: {os.path.basename(design_path)} -> {os.path.basename(result_path) if result_path else 'NO_RESULT'}")
        
        # Process all data
        all_data = []
        
        # Process with parallel pool
        with Pool(num_workers) as pool:
            # Process test data
            if test_tasks:
                results = list(tqdm(
                    pool.imap(process_augmented_circuit, test_tasks),
                    total=len(test_tasks),
                    desc="Loading test data (original files)"
                ))
                for r in results:
                    if r:
                        r['split'] = 'test'
                        r['is_augmented'] = False
                        all_data.append(r)
            
            # Process training data
            if final_train_tasks:
                results = list(tqdm(
                    pool.imap(process_augmented_circuit, final_train_tasks),
                    total=len(final_train_tasks),
                    desc="Loading training data (augmented)"
                ))
                for r in results:
                    if r:
                        r['split'] = 'train'
                        r['is_augmented'] = True
                        all_data.append(r)
            
            # Process validation data
            if val_tasks:
                results = list(tqdm(
                    pool.imap(process_augmented_circuit, val_tasks),
                    total=len(val_tasks),
                    desc="Loading validation data (augmented)"
                ))
                for r in results:
                    if r:
                        r['split'] = 'val'
                        r['is_augmented'] = True
                        all_data.append(r)
        
        return all_data

class EfficientBatchCreator:
    """Efficient batch creation with gate-level balancing"""
    
    @staticmethod
    def create_balanced_batches(data_list, batch_size=64, shuffle=True, balance_gates=True):
        """Create batches with better gate-level balance"""
        if shuffle:
            data_list = data_list.copy()
            random.shuffle(data_list)
        
        batches = []
        
        if balance_gates:
            # Prioritize circuits with Trojan gates for better balance
            trojan_circuits = [d for d in data_list if d['is_trojan_circuit']]
            clean_circuits = [d for d in data_list if not d['is_trojan_circuit']]
            
            # Use 2:1 ratio (trojan:clean) to account for gate imbalance
            max_trojan = len(trojan_circuits)
            max_clean = len(clean_circuits)
            
            # Create mixed batches
            batch_data = []
            for i in range(max(max_trojan, max_clean)):
                if i < max_trojan:
                    batch_data.append(trojan_circuits[i])
                if i % 2 == 0 and i // 2 < max_clean:
                    batch_data.append(clean_circuits[i // 2])
            
            data_list = batch_data
        
        # Create batches
        for i in range(0, len(data_list), batch_size // 16):
            batch_circuits = data_list[i:i + batch_size // 16]
            
            if not batch_circuits:
                continue
            
            # Pre-allocate arrays
            total_nodes = sum(d['num_gates'] for d in batch_circuits)
            batch_features = np.zeros((total_nodes, batch_circuits[0]['features'].shape[1]))
            batch_labels = []
            edge_lists_fw = []
            edge_lists_bw = []
            
            node_offset = 0
            for data in batch_circuits:
                n_nodes = data['num_gates']
                
                # Copy features
                batch_features[node_offset:node_offset + n_nodes] = data['features']
                batch_labels.extend(data['labels'])
                
                # Add edges with offset
                if data['edge_index_fw'].shape[1] > 0:
                    edge_fw = data['edge_index_fw'] + node_offset
                    edge_bw = data['edge_index_bw'] + node_offset
                    edge_lists_fw.append(edge_fw)
                    edge_lists_bw.append(edge_bw)
                
                node_offset += n_nodes
            
            # Create batch tensor
            batch = {
                'x': torch.FloatTensor(batch_features),
                'y': torch.LongTensor(batch_labels),
                'edge_index_fw': torch.cat(edge_lists_fw, dim=1) if edge_lists_fw else torch.LongTensor(2, 0),
                'edge_index_bw': torch.cat(edge_lists_bw, dim=1) if edge_lists_bw else torch.LongTensor(2, 0)
            }
            batches.append(batch)
        
        return batches


class EfficientTrojanDetector:
    """Detector optimized for high F1 score with 1:8 class imbalance"""
    
    def __init__(self, input_dim=30, hidden_dim=96, learning_rate=0.001, weight_decay=5e-5, 
                 total_epochs=60, train_data_size=None, batch_size=64):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model = ImprovedBiGCN(input_dim=input_dim, hidden_dim=hidden_dim).to(self.device)
        
        # Initialize optimizer with lower base learning rate
        self.optimizer = optim.AdamW(self.model.parameters(), lr=0.0001, weight_decay=weight_decay)
        
        # Calculate total steps for OneCycleLR
        if train_data_size is not None:
            steps_per_epoch = max(1, train_data_size // (batch_size // 16))  # Adjusted for your batch creation
            self.total_steps = steps_per_epoch * total_epochs
            
            # Initialize OneCycleLR
            self.scheduler = OneCycleLR(
                self.optimizer,
                max_lr=learning_rate,  # Peak learning rate
                total_steps=self.total_steps,
                epochs=total_epochs,
                steps_per_epoch=steps_per_epoch,
                pct_start=0.3,  # 30% of training for warmup
                anneal_strategy='cos',
                cycle_momentum=True,
                base_momentum=0.85,
                max_momentum=0.95,
                div_factor=25,  # Initial lr = max_lr/25
                final_div_factor=1000,  # Final lr = max_lr/1000
                three_phase=False,
                last_epoch=-1,
                verbose=False
            )
            self.use_onecycle = True
            self.steps_per_epoch = steps_per_epoch
        else:
            # Fallback to CosineAnnealingWarmRestarts if train_data_size not provided
            self.scheduler = optim.lr_scheduler.CosineAnnealingWarmRestarts(
                self.optimizer, T_0=20, T_mult=2
            )
            self.use_onecycle = False
        
        # Use weighted focal loss for 1:8 imbalance
        self.criterion = WeightedFocalLoss(alpha=0.111, gamma=2.0, pos_weight=8.0)
        
        # Track best thresholds
        self.best_threshold = 0.5
        
        # Track current step for OneCycleLR
        self.current_step = 0
    
    def train_epoch_balanced(self, train_data, batch_size=64):
        """Training with better gate-level balance and OneCycleLR"""
        self.model.train()
        
        # Create balanced batches
        train_batches = EfficientBatchCreator.create_balanced_batches(
            train_data, batch_size, shuffle=True, balance_gates=True
        )
        
        total_loss = 0
        all_preds = []
        all_labels = []
        
        # Track false positive rate for adaptive training
        batch_fp_rates = []
        
        for batch_idx, batch in enumerate(tqdm(train_batches, desc="Training")):
            # Move to device
            batch = {k: v.to(self.device, non_blocking=True) for k, v in batch.items()}
            
            self.optimizer.zero_grad(set_to_none=True)
            
            # Forward pass
            out, _ = self.model(batch['x'], batch['edge_index_fw'], batch['edge_index_bw'])
            
            # Calculate loss
            loss = self.criterion(out, batch['y'])
            
            # Add L1 regularization on positive predictions to reduce false positives
            positive_scores = F.softmax(out, dim=1)[:, 1]
            l1_penalty = 0.001 * torch.mean(torch.abs(positive_scores))
            loss = loss + l1_penalty
            
            # Backward pass
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
            self.optimizer.step()
            
            # Update learning rate with OneCycleLR (step after each batch)
            if self.use_onecycle:
                self.scheduler.step()
                self.current_step += 1
            
            total_loss += loss.item()
            
            # Predictions and metrics
            with torch.no_grad():
                probs = F.softmax(out, dim=1)
                preds = (probs[:, 1] > self.best_threshold).long()
                
                all_preds.extend(preds.cpu().numpy())
                all_labels.extend(batch['y'].cpu().numpy())
                
                # Calculate batch false positive rate
                batch_preds = preds.cpu().numpy()
                batch_labels = batch['y'].cpu().numpy()
                batch_tn = np.sum((batch_preds == 0) & (batch_labels == 0))
                batch_fp = np.sum((batch_preds == 1) & (batch_labels == 0))
                if batch_tn + batch_fp > 0:
                    batch_fp_rate = batch_fp / (batch_tn + batch_fp)
                    batch_fp_rates.append(batch_fp_rate)
        
        # Update learning rate for non-OneCycle schedulers
        if not self.use_onecycle:
            self.scheduler.step()
        
        # Calculate epoch metrics
        precision, recall, f1, _ = precision_recall_fscore_support(
            all_labels, all_preds, average='binary', pos_label=1, zero_division=0
        )
        
        # Calculate average false positive rate
        avg_fp_rate = np.mean(batch_fp_rates) if batch_fp_rates else 0.0
        
        # Log current learning rate
        current_lr = self.optimizer.param_groups[0]['lr']
        if self.use_onecycle:
            progress = self.current_step / self.total_steps if self.total_steps > 0 else 0
            print(f"  OneCycle Progress: {progress:.1%}, LR: {current_lr:.6f}, Avg FP Rate: {avg_fp_rate:.3f}")
        
        return total_loss / len(train_batches), precision, recall, f1
    
    # Keep the rest of the methods the same...
    def find_optimal_threshold(self, val_data):
        """Find threshold that maximizes F1 score"""
        self.model.eval()
        
        # Create validation batches
        val_batches = EfficientBatchCreator.create_balanced_batches(
            val_data, batch_size=128, shuffle=False, balance_gates=False
        )
        
        all_probs = []
        all_labels = []
        
        with torch.no_grad():
            for batch in val_batches:
                batch = {k: v.to(self.device) for k, v in batch.items()}
                out, _ = self.model(batch['x'], batch['edge_index_fw'], batch['edge_index_bw'])
                probs = F.softmax(out, dim=1)
                
                all_probs.extend(probs[:, 1].cpu().numpy())
                all_labels.extend(batch['y'].cpu().numpy())
        
        all_probs = np.array(all_probs)
        all_labels = np.array(all_labels)
        
        # Find best threshold for F1
        best_f1 = 0
        best_threshold = 0.5
        best_metrics = {}
        
        for threshold in np.arange(0.05, 0.95, 0.05):
            preds = (all_probs > threshold).astype(int)
            precision, recall, f1, _ = precision_recall_fscore_support(
                all_labels, preds, average='binary', pos_label=1, zero_division=0
            )
            
            if f1 > best_f1:
                best_f1 = f1
                best_threshold = threshold
                best_metrics = {'precision': precision, 'recall': recall, 'f1': f1}
        
        print(f"  Best threshold: {best_threshold:.3f} -> P: {best_metrics['precision']:.3f}, R: {best_metrics['recall']:.3f}, F1: {best_metrics['f1']:.3f}")
        
        return best_threshold, best_f1
    
    def evaluate(self, val_data, batch_size=128):
        """Evaluate model performance"""
        self.model.eval()
        
        # Create validation batches
        val_batches = EfficientBatchCreator.create_balanced_batches(
            val_data, batch_size, shuffle=False, balance_gates=False
        )
        
        all_preds = []
        all_labels = []
        all_probs = []
        
        with torch.no_grad():
            for batch in val_batches:
                batch = {k: v.to(self.device) for k, v in batch.items()}
                out, _ = self.model(batch['x'], batch['edge_index_fw'], batch['edge_index_bw'])
                probs = F.softmax(out, dim=1)
                preds = (probs[:, 1] > self.best_threshold).long()
                
                all_preds.extend(preds.cpu().numpy())
                all_labels.extend(batch['y'].cpu().numpy())
                all_probs.extend(probs[:, 1].cpu().numpy())
        
        all_preds = np.array(all_preds)
        all_labels = np.array(all_labels)
        all_probs = np.array(all_probs)
        
        # Calculate metrics
        precision, recall, f1, _ = precision_recall_fscore_support(
            all_labels, all_preds, average='binary', pos_label=1, zero_division=0
        )
        
        # Confusion matrix
        cm = confusion_matrix(all_labels, all_preds)
        if cm.shape == (2, 2):
            tn, fp, fn, tp = cm.ravel()
            tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
            tnr = tn / (tn + fp) if (tn + fp) > 0 else 0
        else:
            tpr = tnr = 0
            tp = fp = fn = tn = 0
        
        # AUC
        try:
            auc = roc_auc_score(all_labels, all_probs)
        except:
            auc = 0.5
        
        return {
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'tpr': tpr,
            'tnr': tnr,
            'auc': auc,
            'tp': tp,
            'fp': fp,
            'fn': fn,
            'tn': tn
        }
    
    def evaluate_with_graph_metrics(self, val_data, batch_size=128):
        """Evaluate model performance including graph-level metrics"""
        self.model.eval()
        
        # Create validation batches
        val_batches = EfficientBatchCreator.create_balanced_batches(
            val_data, batch_size, shuffle=False, balance_gates=False
        )
        
        all_preds = []
        all_labels = []
        all_probs = []
        
        # Store predictions per circuit for graph-level metrics
        circuit_boundaries = []  # Track where each circuit starts/ends
        
        current_pos = 0
        for circuit in val_data:
            circuit_boundaries.append((current_pos, current_pos + circuit['num_gates']))
            current_pos += circuit['num_gates']
        
        with torch.no_grad():
            for batch in val_batches:
                batch = {k: v.to(self.device) for k, v in batch.items()}
                out, _ = self.model(batch['x'], batch['edge_index_fw'], batch['edge_index_bw'])
                probs = F.softmax(out, dim=1)
                preds = (probs[:, 1] > self.best_threshold).long()
                
                all_preds.extend(preds.cpu().numpy())
                all_labels.extend(batch['y'].cpu().numpy())
                all_probs.extend(probs[:, 1].cpu().numpy())
        
        all_preds = np.array(all_preds)
        all_labels = np.array(all_labels)
        all_probs = np.array(all_probs)
        
        # Calculate graph-level predictions
        circuit_predictions = []
        circuit_labels = []
        
        for i, (circuit, (start, end)) in enumerate(zip(val_data, circuit_boundaries)):
            circuit_gate_preds = all_preds[start:end]
            
            # Graph is predicted as Trojaned if any gate is predicted as Trojan
            graph_pred = 1 if np.any(circuit_gate_preds) else 0
            graph_label = 1 if circuit['is_trojan_circuit'] else 0
            
            circuit_predictions.append(graph_pred)
            circuit_labels.append(graph_label)
        
        circuit_predictions = np.array(circuit_predictions)
        circuit_labels = np.array(circuit_labels)
        
        # Calculate gate-level metrics
        precision, recall, f1, _ = precision_recall_fscore_support(
            all_labels, all_preds, average='binary', pos_label=1, zero_division=0
        )
        
        # Calculate graph-level metrics
        graph_precision, graph_recall, graph_f1, _ = precision_recall_fscore_support(
            circuit_labels, circuit_predictions, average='binary', pos_label=1, zero_division=0
        )
        
        # Confusion matrix for gates
        cm = confusion_matrix(all_labels, all_preds)
        if cm.shape == (2, 2):
            tn, fp, fn, tp = cm.ravel()
            tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
            tnr = tn / (tn + fp) if (tn + fp) > 0 else 0
        else:
            tpr = tnr = 0
            tp = fp = fn = tn = 0
        
        # Confusion matrix for graphs
        cm_graph = confusion_matrix(circuit_labels, circuit_predictions)
        if cm_graph.shape == (2, 2):
            tn_g, fp_g, fn_g, tp_g = cm_graph.ravel()
        else:
            tp_g = fp_g = fn_g = tn_g = 0
        
        # AUC
        try:
            auc = roc_auc_score(all_labels, all_probs)
        except:
            auc = 0.5
        
        return {
            # Gate-level metrics
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'tpr': tpr,
            'tnr': tnr,
            'auc': auc,
            'tp': tp,
            'fp': fp,
            'fn': fn,
            'tn': tn,
            # Graph-level metrics
            'graph_precision': graph_precision,
            'graph_recall': graph_recall,
            'graph_f1': graph_f1,
            'graph_tp': tp_g,
            'graph_fp': fp_g,
            'graph_fn': fn_g,
            'graph_tn': tn_g
        }

def analyze_trojan_patterns(trojan_def_dir):
    """Analyze trojan patterns from definition files"""
    trojan_patterns = []
    
    if not os.path.exists(trojan_def_dir):
        return trojan_patterns
    
    for file in os.listdir(trojan_def_dir):
        if file.endswith('_converted.v'):
            filepath = os.path.join(trojan_def_dir, file)
            parser = FastNetlistParser()
            
            try:
                gates = parser.parse_netlist_fast(filepath)
                edge_list_fw, edge_list_bw, num_gates = parser.build_graph_fast(gates)
                features = parser.extract_features_enhanced(gates, edge_list_fw, num_gates)
                
                # Analyze patterns
                pattern_info = {
                    'name': file,
                    'num_gates': num_gates,
                    'gate_types': Counter([g['type'] for g in gates]),
                    'avg_features': np.mean(features, axis=0),
                    'feature_std': np.std(features, axis=0)
                }
                trojan_patterns.append(pattern_info)
                
            except Exception as e:
                print(f"Error analyzing {file}: {e}")
    
    return trojan_patterns


def save_checkpoint(detector, epoch, metrics, checkpoint_path='checkpoint.pth'):
    """Save training checkpoint with all necessary information"""
    # Get hidden dim from the first layer
    if hasattr(detector.model.fw_layers[0], 'out_channels'):
        hidden_dim = detector.model.fw_layers[0].out_channels
    else:
        # For GATConv, get the output dimension differently
        hidden_dim = 96  # Use the default or extract from model architecture
    
    checkpoint = {
        'model_state_dict': detector.model.state_dict(),
        'optimizer_state_dict': detector.optimizer.state_dict(),
        'scheduler_state_dict': detector.scheduler.state_dict(),
        'epoch': epoch,
        'best_threshold': detector.best_threshold,
        'metrics': metrics,
        'feature_dim': 30,
        'hidden_dim': hidden_dim,
        'learning_rate': detector.optimizer.param_groups[0]['lr'],
        'use_onecycle': detector.use_onecycle,
        'current_step': detector.current_step if detector.use_onecycle else 0
    }
    torch.save(checkpoint, checkpoint_path)
    print(f"  ✓ Saved checkpoint at epoch {epoch+1}")

def load_checkpoint(detector, checkpoint_path):
    """Load checkpoint and restore training state"""
    if not os.path.exists(checkpoint_path):
        return None
    
    checkpoint = torch.load(checkpoint_path, map_location=detector.device)
    detector.model.load_state_dict(checkpoint['model_state_dict'])
    detector.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
    
    # Handle scheduler state carefully for OneCycleLR
    if detector.use_onecycle and checkpoint.get('use_onecycle', False):
        try:
            detector.scheduler.load_state_dict(checkpoint['scheduler_state_dict'])
            detector.current_step = checkpoint.get('current_step', 0)
        except:
            print("  Warning: Could not load OneCycleLR state, restarting scheduler")
    
    detector.best_threshold = checkpoint.get('best_threshold', 0.5)
    
    return checkpoint


def main():
    parser = argparse.ArgumentParser(description='Improved Bi-GCN Training with Augmented Data Strategy and Resume Capability')
    parser.add_argument('--augmented-dir', type=str, default='../data/augmented_heavy', 
                        help='Directory containing augmented data (includes all train/val/test)')
    parser.add_argument('--trojan-def-dir', type=str, default='../data/TrojanDef')
    parser.add_argument('--hidden-dim', type=int, default=96)
    parser.add_argument('--epochs', type=int, default=60)
    parser.add_argument('--batch-size', type=int, default=64)
    parser.add_argument('--num-workers', type=int, default=None)
    parser.add_argument('--learning-rate', type=float, default=0.001)
    parser.add_argument('--weight-decay', type=float, default=5e-5)
    parser.add_argument('--clear-cache', action='store_true')
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--use-cache', action='store_true', help='Use cached data if available')
    parser.add_argument('--resume', action='store_true', help='Resume training from checkpoint')
    parser.add_argument('--checkpoint-path', type=str, default='../models/training_checkpoint.pth', 
                        help='Path to checkpoint file for resuming')
    parser.add_argument('--save-frequency', type=int, default=5, 
                        help='Save checkpoint every N epochs')
    args = parser.parse_args()
    
    # Set random seed
    set_seed(args.seed)
    
    # Clear cache if requested
    if args.clear_cache and os.path.exists('./cache'):
        import shutil
        shutil.rmtree('./cache')
        print("Cache cleared.")
    
    # Analyze trojan patterns if available
    trojan_patterns = []
    if os.path.exists(args.trojan_def_dir):
        print("Analyzing trojan definition patterns...")
        trojan_patterns = analyze_trojan_patterns(args.trojan_def_dir)
        if trojan_patterns:
            print(f"Found {len(trojan_patterns)} trojan patterns")
    
    # Load augmented data
    loader = OptimizedDataLoader()
    
    # Check cache
    cache_file = os.path.join(loader.cache_dir, 'augmented_data_processed.pkl')
    if args.use_cache and os.path.exists(cache_file):
        print("Loading from cache...")
        with open(cache_file, 'rb') as f:
            all_data = pickle.load(f)
        # Load scaler
        scaler_file = os.path.join(loader.cache_dir, 'augmented_data_scaler.pkl')
        if os.path.exists(scaler_file):
            with open(scaler_file, 'rb') as f:
                loader.scaler = pickle.load(f)
    else:
        print("\nLoading augmented data...")
        all_data = loader.load_augmented_data(
            args.augmented_dir,
            args.num_workers
        )
        
        if not all_data:
            print("No data found! Please check your augmented data directory.")
            return
        
        # Normalize features across all data
        print("\nNormalizing features...")
        all_features = np.vstack([d['features'] for d in all_data])
        loader.scaler.fit(all_features)
        
        for d in all_data:
            d['features'] = loader.scaler.transform(d['features'])
        
        # Save to cache if requested
        if args.use_cache:
            print("Saving to cache...")
            with open(cache_file, 'wb') as f:
                pickle.dump(all_data, f)
            with open(os.path.join(loader.cache_dir, 'augmented_data_scaler.pkl'), 'wb') as f:
                pickle.dump(loader.scaler, f)
    
    # Split data based on split assignments
    test_data = [d for d in all_data if d.get('split') == 'test']
    train_data = [d for d in all_data if d.get('split') == 'train']
    val_data = [d for d in all_data if d.get('split') == 'val']
    
    print(f"\nFinal dataset statistics:")
    print(f"  Test (original files): {len(test_data)} circuits")
    print(f"  Train (augmented): {len(train_data)} circuits")
    print(f"  Val (augmented): {len(val_data)} circuits")
    
    # Verify augmentation status
    test_aug = sum(1 for d in test_data if d.get('is_augmented', False))
    train_aug = sum(1 for d in train_data if d.get('is_augmented', False))
    val_aug = sum(1 for d in val_data if d.get('is_augmented', False))
    
    print(f"\nAugmentation check:")
    print(f"  Test augmented: {test_aug} (should be 0)")
    print(f"  Train augmented: {train_aug} (should be {len(train_data)})")
    print(f"  Val augmented: {val_aug} (should be {len(val_data)})")
    
    # Count Trojan gates
    for split_name, split_data in [('Test', test_data), ('Train', train_data), ('Val', val_data)]:
        if split_data:
            all_labels = np.concatenate([d['labels'] for d in split_data])
            n_trojan = np.sum(all_labels == 1)
            n_clean = np.sum(all_labels == 0)
            n_circuits_trojan = sum(1 for d in split_data if d['is_trojan_circuit'])
            n_circuits_clean = len(split_data) - n_circuits_trojan
            
            print(f"\n{split_name} statistics:")
            print(f"  Circuits: {n_circuits_trojan} trojan, {n_circuits_clean} clean")
            print(f"  Gates: {n_trojan} trojan, {n_clean} clean, Ratio: 1:{n_clean/max(n_trojan,1):.1f}")
    
    # Save scaler for inference
    print("\nSaving feature scaler for inference...")
    with open('../models/feature_scaler.pkl', 'wb') as f:
        pickle.dump(loader.scaler, f)
    
    # Train model
    if not train_data or not val_data:
        print("\nInsufficient data for training! Need both training and validation data.")
        return
    
    # Initialize detector
    detector = EfficientTrojanDetector(
        input_dim=30,
        hidden_dim=args.hidden_dim,
        learning_rate=args.learning_rate,
        weight_decay=args.weight_decay,
        total_epochs=args.epochs,
        train_data_size=len(train_data) if train_data else None,
        batch_size=args.batch_size
    )

    
    print(f"\nTraining improved Bi-GCN model...")
    print(f"Device: {detector.device}")
    
    # Initialize training variables
    start_epoch = 0
    best_val_f1 = 0
    best_graph_f1 = 0
    best_epoch = 0
    patience = 25
    patience_counter = 0
    
    # Resume from checkpoint if requested
    if args.resume:
        print(f"\nAttempting to resume from checkpoint: {args.checkpoint_path}")
        checkpoint = load_checkpoint(detector, args.checkpoint_path)
        if checkpoint:
            start_epoch = checkpoint['epoch'] + 1
            print(f"  ✓ Resumed from epoch {start_epoch}")
            print(f"  ✓ Best threshold: {detector.best_threshold:.3f}")
            if 'metrics' in checkpoint and checkpoint['metrics']:
                print(f"  ✓ Previous metrics - F1: {checkpoint['metrics'].get('f1', 0):.4f}, Graph F1: {checkpoint['metrics'].get('graph_f1', 0):.4f}")
            
            # Also try to load best model checkpoint to get best metrics
            if os.path.exists('../models/best_model_augmented.pth'):
                best_checkpoint = torch.load('../models/best_model_augmented.pth', map_location=detector.device)
                best_val_f1 = best_checkpoint.get('best_f1', 0)
                best_graph_f1 = best_checkpoint.get('best_graph_f1', 0)
                best_epoch = best_checkpoint.get('epoch', 0)
                print(f"  ✓ Best model so far - F1: {best_val_f1:.4f}, Graph F1: {best_graph_f1:.4f} at epoch {best_epoch+1}")
        else:
            print("  ! No checkpoint found, starting from scratch")
    
    # Training loop with checkpoint saving
    for epoch in range(start_epoch, args.epochs):
        start_epoch_time = time.time()
        
        # Train
        train_loss, train_prec, train_rec, train_f1 = detector.train_epoch_balanced(train_data, args.batch_size)
        
        # Update learning rate
        detector.scheduler.step()
        
        # Find optimal threshold every 5 epochs
        if epoch % 5 == 0:
            threshold, _ = detector.find_optimal_threshold(val_data)
            detector.best_threshold = threshold
        
        # Validate with both gate and graph metrics
        val_metrics = detector.evaluate_with_graph_metrics(val_data, batch_size=128)
        
        print(f"\nEpoch {epoch+1}/{args.epochs} (LR: {detector.optimizer.param_groups[0]['lr']:.2e})")
        print(f"  Train - Loss: {train_loss:.4f}, P: {train_prec:.4f}, R: {train_rec:.4f}, F1: {train_f1:.4f}")
        print(f"  Val   - Gate P: {val_metrics['precision']:.4f}, R: {val_metrics['recall']:.4f}, F1: {val_metrics['f1']:.4f}")
        print(f"  Val   - Graph P: {val_metrics['graph_precision']:.4f}, R: {val_metrics['graph_recall']:.4f}, F1: {val_metrics['graph_f1']:.4f}")
        print(f"  Val   - TP: {val_metrics['tp']}, FP: {val_metrics['fp']}, FN: {val_metrics['fn']}, TN: {val_metrics['tn']}")
        print(f"  Time: {time.time() - start_epoch_time:.2f}s")
        
        # Save checkpoint periodically
        if (epoch + 1) % args.save_frequency == 0:
            save_checkpoint(detector, epoch, val_metrics, args.checkpoint_path)
        
        # Determine if we should save the best model
        should_save = False
        save_reason = ""
        
        # Check if gate F1 is significantly better
        if val_metrics['f1'] > best_val_f1 + 0.0001:
            should_save = True
            save_reason = f"Gate F1 improved significantly: {best_val_f1:.4f} -> {val_metrics['f1']:.4f}"
        # If gate F1 improvement is small (within 0.001), check graph F1
        elif abs(val_metrics['f1'] - best_val_f1) <= 0.0001 and val_metrics['graph_f1'] > best_graph_f1:
            should_save = True
            save_reason = f"Gate F1 similar ({best_val_f1:.4f} -> {val_metrics['f1']:.4f}), but Graph F1 improved: {best_graph_f1:.4f} -> {val_metrics['graph_f1']:.4f}"
        
        # Save best model
        if should_save:
            best_val_f1 = val_metrics['f1']
            best_graph_f1 = val_metrics['graph_f1']
            best_epoch = epoch
            torch.save({
                'model_state_dict': detector.model.state_dict(),
                'optimizer_state_dict': detector.optimizer.state_dict(),
                'epoch': epoch,
                'best_f1': best_val_f1,
                'best_graph_f1': best_graph_f1,
                'best_threshold': detector.best_threshold,
                'metrics': val_metrics,
                'feature_dim': 30
            }, '../models/best_model_augmented.pth')
            print(f"  ✓ Saved best model - {save_reason}")
            patience_counter = 0
        else:
            patience_counter += 1
            if abs(val_metrics['f1'] - best_val_f1) <= 0.0001:
                print(f"  Gate F1 within threshold ({val_metrics['f1']:.4f} vs {best_val_f1:.4f}), Graph F1: {val_metrics['graph_f1']:.4f} vs {best_graph_f1:.4f}")
        
        # Early stopping
        if patience_counter >= patience:
            print(f"\nEarly stopping triggered after {epoch+1} epochs")
            break
    
    # Save final checkpoint
    save_checkpoint(detector, epoch, val_metrics, '../models/final_checkpoint.pth')
    
    # Save final model
    torch.save({
        'model_state_dict': detector.model.state_dict(),
        'optimizer_state_dict': detector.optimizer.state_dict(),
        'epoch': epoch,
        'metrics': val_metrics,
        'feature_dim': 30,
        'best_threshold': detector.best_threshold
    }, '../models/final_model_augmented.pth')
    
    print("\nTraining completed!")
    print(f"Best validation Gate F1: {best_val_f1:.4f}, Graph F1: {best_graph_f1:.4f} at epoch {best_epoch+1}")
    print(f"Best threshold: {detector.best_threshold:.3f}")
    
    # Load best model for final evaluation
    print("\nLoading best model for final evaluation...")
    checkpoint = torch.load('../models/best_model_augmented.pth')
    detector.model.load_state_dict(checkpoint['model_state_dict'])
    detector.best_threshold = checkpoint['best_threshold']
    
    # Evaluate on test data (original files only)
    if test_data:
        print("\nEvaluating on test data (original files only - prevents memorization):")
        test_metrics = detector.evaluate_with_graph_metrics(test_data, batch_size=128)
        print(f"  Test - Gate P: {test_metrics['precision']:.4f}, R: {test_metrics['recall']:.4f}, F1: {test_metrics['f1']:.4f}")
        print(f"  Test - Graph P: {test_metrics['graph_precision']:.4f}, R: {test_metrics['graph_recall']:.4f}, F1: {test_metrics['graph_f1']:.4f}")
        print(f"  Test - Gate TP: {test_metrics['tp']}, FP: {test_metrics['fp']}, FN: {test_metrics['fn']}, TN: {test_metrics['tn']}")
        print(f"  Test - Graph TP: {test_metrics['graph_tp']}, FP: {test_metrics['graph_fp']}, FN: {test_metrics['graph_fn']}, TN: {test_metrics['graph_tn']}")
        print(f"  Test - AUC: {test_metrics['auc']:.4f}")
        
        # Save test results
        with open('test_results.txt', 'w') as f:
            f.write(f"Test Results (Original Files Only)\n")
            f.write(f"==================================\n\n")
            f.write(f"Gate-Level Metrics:\n")
            f.write(f"  Precision: {test_metrics['precision']:.4f}\n")
            f.write(f"  Recall: {test_metrics['recall']:.4f}\n")
            f.write(f"  F1 Score: {test_metrics['f1']:.4f}\n")
            f.write(f"  AUC: {test_metrics['auc']:.4f}\n")
            f.write(f"  Confusion Matrix: TP={test_metrics['tp']}, FP={test_metrics['fp']}, FN={test_metrics['fn']}, TN={test_metrics['tn']}\n\n")
            f.write(f"Graph-Level Metrics:\n")
            f.write(f"  Precision: {test_metrics['graph_precision']:.4f}\n")
            f.write(f"  Recall: {test_metrics['graph_recall']:.4f}\n")
            f.write(f"  F1 Score: {test_metrics['graph_f1']:.4f}\n")
            f.write(f"  Confusion Matrix: TP={test_metrics['graph_tp']}, FP={test_metrics['graph_fp']}, FN={test_metrics['graph_fn']}, TN={test_metrics['graph_tn']}\n\n")
            f.write(f"Threshold: {detector.best_threshold:.3f}\n")
            f.write(f"Training completed at epoch: {epoch+1}\n")
            f.write(f"Best model from epoch: {best_epoch+1}\n")

if __name__ == "__main__":
    main()
                 