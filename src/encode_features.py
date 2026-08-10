#!/usr/bin/env python3
"""
Hardware Trojan Feature Encoder for GNN Training
Optimized for ICCAD contest format with primitive gates
Usage: python encode_features.py
"""

import os
import sys
import re
import numpy as np
import pickle
from collections import defaultdict
import argparse

class GateFeatureEncoder:
    def __init__(self):
        # Contest-specific primitive gates (exactly 9 types)
        self.primitive_gates = ['and', 'or', 'nand', 'nor', 'not', 'buf', 'xor', 'xnor', 'dff']
        
        # Create fixed mapping for one-hot encoding
        self.gate_type_to_idx = {gate: idx for idx, gate in enumerate(self.primitive_gates)}
        
        # Track primary I/O
        self.primary_inputs = set()
        self.primary_outputs = set()
        
    def parse_verilog_file(self, filepath):
        """Parse Verilog file following contest format"""
        gates = {}
        wires = set()
        dff_connections = {}
        
        with open(filepath, 'r') as f:
            content = f.read()
            
        # Remove comments
        content = re.sub(r'//.*?\n', '\n', content)
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        
        # Extract module definition - should be "module top(...)"
        module_match = re.search(r'module\s+(\w+)\s*\((.*?)\);', content, re.DOTALL)
        if module_match:
            module_name = module_match.group(1)
            io_section = module_match.group(2)
            
            # Parse inputs - handle both single and array formats
            # input clk, input rst_n, input [1:0] in
            input_pattern = r'input\s+(?:\[[\d:]+\]\s+)?(\w+)'
            for match in re.finditer(input_pattern, io_section):
                signal = match.group(1)
                self.primary_inputs.add(signal)
            
            # Parse outputs
            output_pattern = r'output\s+(?:\[[\d:]+\]\s+)?(\w+)'
            for match in re.finditer(output_pattern, io_section):
                signal = match.group(1)
                self.primary_outputs.add(signal)
        
        # Extract wire declarations
        wire_pattern = r'wire\s+(.*?);'
        for match in re.finditer(wire_pattern, content):
            wire_list = match.group(1)
            # Handle both single wires and comma-separated lists
            for wire in wire_list.split(','):
                wire = wire.strip()
                if wire:
                    wires.add(wire)
        
        # Parse DFF instantiations with named connections
        # dff g3 (.RN(rst_n), .SN(1'b1), .CK(clk), .D(n3), .Q(out[0]));
        dff_pattern = r'dff\s+(\w+)\s*\((.*?)\);'
        for match in re.finditer(dff_pattern, content, re.DOTALL):
            instance_name = match.group(1)
            ports_str = match.group(2)
            
            # Parse named connections
            connections = {}
            named_pattern = r'\.(\w+)\s*\(\s*([^)]+)\s*\)'
            for port_match in re.finditer(named_pattern, ports_str):
                port_name = port_match.group(1)
                wire_name = port_match.group(2).strip()
                connections[port_name] = wire_name
            
            dff_connections[instance_name] = connections
            
            # Add DFF as a gate
            gates[instance_name] = {
                'type': 'dff',
                'name': instance_name,
                'connections': connections,
                'output': connections.get('Q', ''),
                'inputs': [connections.get('D', ''), connections.get('CK', ''), 
                          connections.get('RN', ''), connections.get('SN', '')]
            }
        
        # Parse primitive gates
        # Format: gate_type gate_name (output, input1, input2);
        for gate_type in self.primitive_gates[:-1]:  # Exclude 'dff' as it's handled separately
            pattern = rf'{gate_type}\s+(\w+)\s*\((.*?)\);'
            
            for match in re.finditer(pattern, content):
                gate_name = match.group(1)
                ports_str = match.group(2)
                
                # Parse ports (positional)
                ports = [p.strip() for p in ports_str.split(',')]
                
                gate_info = {
                    'type': gate_type,
                    'name': gate_name,
                    'ports': ports,
                    'output': ports[0] if ports else None,
                    'inputs': ports[1:] if len(ports) > 1 else []
                }
                
                gates[gate_name] = gate_info
        
        return gates, wires, dff_connections
    
    def analyze_connections(self, gates, dff_connections):
        """Analyze special connections in the circuit"""
        connections = {}
        
        # Build wire-to-gate mapping
        wire_producers = {}  # which gate produces each wire
        wire_consumers = defaultdict(list)  # which gates consume each wire
        
        for gate_name, gate_info in gates.items():
            # Track output
            if 'output' in gate_info and gate_info['output']:
                wire_producers[gate_info['output']] = gate_name
            
            # Track inputs
            if 'inputs' in gate_info:
                for input_wire in gate_info['inputs']:
                    if input_wire and input_wire != "1'b1" and input_wire != "1'b0":
                        wire_consumers[input_wire].append(gate_name)
        
        # Analyze each gate's connections
        for gate_name, gate_info in gates.items():
            conn_features = {
                'connects_to_RN': False,
                'connects_to_SN': False,
                'connects_to_CK': False,
                'connects_to_D': False,
                'has_primary_input': False,
                'is_primary_output': False
            }
            
            # Check if this gate's output connects to any DFF special pins
            output_wire = gate_info.get('output', '')
            if output_wire:
                # Check all DFFs to see if this wire connects to their special pins
                for dff_name, dff_conns in dff_connections.items():
                    if dff_conns.get('RN') == output_wire:
                        conn_features['connects_to_RN'] = True
                    if dff_conns.get('SN') == output_wire:
                        conn_features['connects_to_SN'] = True
                    if dff_conns.get('CK') == output_wire:
                        conn_features['connects_to_CK'] = True
                    if dff_conns.get('D') == output_wire:
                        conn_features['connects_to_D'] = True
            
            # Check primary I/O
            if 'inputs' in gate_info:
                for input_wire in gate_info['inputs']:
                    # Handle array notation like in[0], in[1]
                    base_signal = input_wire.split('[')[0] if '[' in input_wire else input_wire
                    if base_signal in self.primary_inputs:
                        conn_features['has_primary_input'] = True
                        break
            
            if output_wire:
                base_signal = output_wire.split('[')[0] if '[' in output_wire else output_wire
                if base_signal in self.primary_outputs:
                    conn_features['is_primary_output'] = True
            
            connections[gate_name] = conn_features
        
        return connections
    
    def encode_gate_features(self, gates, dff_connections):
        """Encode gates into feature vectors"""
        features = {}
        connections = self.analyze_connections(gates, dff_connections)
        
        for gate_name, gate_info in gates.items():
            # 9 bits for gate types + 6 bits for connections = 15 total
            feature_vector = np.zeros(15)
            
            # Gate type encoding (one-hot) - first 9 bits
            gate_type = gate_info['type']
            if gate_type in self.gate_type_to_idx:
                feature_vector[self.gate_type_to_idx[gate_type]] = 1
            
            # Connection features - last 6 bits
            if gate_name in connections:
                conn = connections[gate_name]
                feature_vector[9] = 1 if conn['connects_to_RN'] else 0
                feature_vector[10] = 1 if conn['connects_to_SN'] else 0
                feature_vector[11] = 1 if conn['connects_to_CK'] else 0
                feature_vector[12] = 1 if conn['connects_to_D'] else 0
                feature_vector[13] = 1 if conn['has_primary_input'] else 0
                feature_vector[14] = 1 if conn['is_primary_output'] else 0
            
            features[gate_name] = feature_vector
        
        return features
    
    def build_adjacency_matrix(self, gates):
        """Build directed adjacency matrix"""
        gate_names = sorted(list(gates.keys()))
        gate_to_idx = {name: idx for idx, name in enumerate(gate_names)}
        n_gates = len(gate_names)
        
        adj_matrix = np.zeros((n_gates, n_gates))
        
        # Build wire-to-consumers mapping
        wire_consumers = defaultdict(list)
        for gate_name, gate_info in gates.items():
            if 'inputs' in gate_info:
                for input_wire in gate_info['inputs']:
                    if input_wire and input_wire != "1'b1" and input_wire != "1'b0":
                        wire_consumers[input_wire].append(gate_name)
        
        # Create edges
        for src_name, src_info in gates.items():
            if src_name not in gate_to_idx:
                continue
            
            src_idx = gate_to_idx[src_name]
            output_wire = src_info.get('output', '')
            
            if output_wire and output_wire in wire_consumers:
                for dst_name in wire_consumers[output_wire]:
                    if dst_name in gate_to_idx:
                        dst_idx = gate_to_idx[dst_name]
                        adj_matrix[src_idx, dst_idx] = 1
        
        return adj_matrix, gate_to_idx
    
    def load_reference_labels(self, ref_path):
        """Load trojan gate labels from reference file"""
        trojan_gates = set()
        
        if not os.path.exists(ref_path):
            return trojan_gates
        
        with open(ref_path, 'r') as f:
            lines = f.readlines()
        
        if lines and lines[0].strip() == 'TROJANED':
            in_trojan_section = False
            for line in lines[1:]:
                line = line.strip()
                if line == 'TROJAN_GATES':
                    in_trojan_section = True
                elif line == 'END_TROJAN_GATES':
                    break
                elif in_trojan_section and line:
                    trojan_gates.add(line)
        
        return trojan_gates
    
    def process_dataset(self, base_path='../data/raw_trusthub'):
        """Process all Verilog files in the dataset"""
        dataset = {
            'trojan_free': {},
            'trojan_infected': {}
        }
        
        print(f"Processing dataset from: {base_path}")
        
        if not os.path.exists(base_path):
            print(f"Error: Path {base_path} does not exist!")
            return dataset
        
        packages = [d for d in os.listdir(base_path) if os.path.isdir(os.path.join(base_path, d))]
        print(f"Found {len(packages)} packages")
        
        for package_name in packages:
            package_path = os.path.join(base_path, package_name)
            print(f"\nProcessing package: {package_name}")
            
            # Reset primary I/O for each file
            self.primary_inputs = set()
            self.primary_outputs = set()
            
            # Process Trojan-free file
            tjfree_path = os.path.join(package_path, 'TjFree_converted.v')
            if os.path.exists(tjfree_path):
                print(f"  Processing TjFree_converted.v")
                gates, wires, dff_connections = self.parse_verilog_file(tjfree_path)
                features = self.encode_gate_features(gates, dff_connections)
                adj_matrix, gate_to_idx = self.build_adjacency_matrix(gates)
                
                dataset['trojan_free'][package_name] = {
                    'gates': gates,
                    'features': features,
                    'adj_matrix': adj_matrix,
                    'gate_to_idx': gate_to_idx,
                    'num_gates': len(gates)
                }
                print(f"    Found {len(gates)} gates")
            
            # Reset for next file
            self.primary_inputs = set()
            self.primary_outputs = set()
            
            # Process Trojan-infected file
            tjin_path = os.path.join(package_path, 'TjIn_converted.v')
            if os.path.exists(tjin_path):
                print(f"  Processing TjIn_converted.v")
                gates, wires, dff_connections = self.parse_verilog_file(tjin_path)
                features = self.encode_gate_features(gates, dff_connections)
                adj_matrix, gate_to_idx = self.build_adjacency_matrix(gates)
                
                # Load reference labels
                ref_path = os.path.join(package_path, 'reference.txt')
                trojan_gates = self.load_reference_labels(ref_path)
                
                # Create labels
                labels = {}
                for gate_name in gates:
                    labels[gate_name] = 1 if gate_name in trojan_gates else 0
                
                # Debug: Check if trojan gates exist in parsed gates
                missing_trojans = trojan_gates - set(gates.keys())
                if missing_trojans:
                    print(f"    WARNING: {len(missing_trojans)} trojan gates not found in netlist")
                
                dataset['trojan_infected'][package_name] = {
                    'gates': gates,
                    'features': features,
                    'adj_matrix': adj_matrix,
                    'gate_to_idx': gate_to_idx,
                    'labels': labels,
                    'trojan_gates': trojan_gates,
                    'num_gates': len(gates),
                    'num_trojans': len(trojan_gates & set(gates.keys()))
                }
                print(f"    Found {len(gates)} gates, {len(trojan_gates & set(gates.keys()))} trojans")
        
        return dataset
    
    def create_training_data(self, dataset):
        """Create training data for GNN"""
        X_features = []
        X_adj = []
        y_labels = []
        circuit_names = []
        
        for package_name, data in dataset['trojan_infected'].items():
            gate_names = sorted(list(data['gates'].keys()))
            n_gates = len(gate_names)
            
            # Create feature matrix
            feature_matrix = np.zeros((n_gates, 15))
            for i, gate_name in enumerate(gate_names):
                if gate_name in data['features']:
                    feature_matrix[i] = data['features'][gate_name]
            
            # Get adjacency matrix
            adj_matrix = data['adj_matrix']
            
            # Create label vector
            label_vector = np.zeros(n_gates)
            for i, gate_name in enumerate(gate_names):
                if gate_name in data['labels']:
                    label_vector[i] = data['labels'][gate_name]
            
            X_features.append(feature_matrix)
            X_adj.append(adj_matrix)
            y_labels.append(label_vector)
            circuit_names.append(package_name)
        
        return X_features, X_adj, y_labels, circuit_names


def analyze_reference_format(base_path):
    """Analyze reference.txt format to debug high trojan ratio"""
    print("\n" + "="*60)
    print("Analyzing Reference Files")
    print("="*60)
    
    for package_name in os.listdir(base_path):
        package_path = os.path.join(base_path, package_name)
        if not os.path.isdir(package_path):
            continue
        
        ref_path = os.path.join(package_path, 'reference.txt')
        if os.path.exists(ref_path):
            print(f"\n{package_name}/reference.txt:")
            with open(ref_path, 'r') as f:
                lines = f.readlines()
            
            # Show first 10 lines
            for i, line in enumerate(lines[:10]):
                print(f"  Line {i}: {line.strip()}")
            
            if len(lines) > 10:
                print(f"  ... ({len(lines)} total lines)")


def main():
    parser = argparse.ArgumentParser(description='Hardware Trojan Feature Encoder')
    parser.add_argument('--data-path', type=str, default='../data/raw_trusthub',
                       help='Path to raw_trusthub directory')
    parser.add_argument('--output', type=str, default='processed_dataset.pkl',
                       help='Output filename for processed dataset')
    parser.add_argument('--analyze-refs', action='store_true',
                       help='Analyze reference file format')
    args = parser.parse_args()
    
    if args.analyze_refs:
        analyze_reference_format(args.data_path)
        return
    
    # Initialize encoder
    encoder = GateFeatureEncoder()
    
    # Process the dataset
    print("="*60)
    print("Hardware Trojan Feature Encoder")
    print("="*60)
    
    dataset = encoder.process_dataset(args.data_path)
    
    # Save processed dataset
    output_path = os.path.join('..', 'data', args.output)
    with open(output_path, 'wb') as f:
        pickle.dump(dataset, f)
    print(f"\nDataset saved to: {output_path}")
    
    # Create training data
    X_features, X_adj, y_labels, circuit_names = encoder.create_training_data(dataset)
    
    # Save training data
    training_data = {
        'X_features': X_features,
        'X_adj': X_adj,
        'y_labels': y_labels,
        'circuit_names': circuit_names
    }
    
    training_output_path = os.path.join('..', 'data', 'training_data.pkl')
    with open(training_output_path, 'wb') as f:
        pickle.dump(training_data, f)
    print(f"Training data saved to: {training_output_path}")
    
    # Show statistics
    print("\n" + "="*60)
    print("Dataset Statistics")
    print("="*60)
    
    if X_features:
        print(f"\nTotal circuits processed: {len(X_features)}")
        print(f"Feature dimension: {X_features[0].shape[1]}")
        print(f"Gate types: {encoder.primitive_gates}")
        
        total_gates = sum([len(f) for f in X_features])
        total_trojans = sum([sum(l) for l in y_labels])
        print(f"\nTotal gates: {total_gates}")
        print(f"Total trojan gates: {int(total_trojans)}")
        print(f"Average trojan ratio: {total_trojans/total_gates:.4%}")
        
        print("\nPer-circuit statistics:")
        print(f"{'Circuit':<20} {'Gates':<10} {'Trojans':<10} {'Ratio':<10}")
        print("-"*50)
        for i, name in enumerate(circuit_names):
            n_gates = len(X_features[i])
            n_trojans = int(sum(y_labels[i]))
            ratio = n_trojans / n_gates if n_gates > 0 else 0
            print(f"{name:<20} {n_gates:<10} {n_trojans:<10} {ratio:<10.2%}")
        
        # Feature analysis
        all_features = np.vstack(X_features)
        all_labels = np.concatenate(y_labels)
        
        print("\n" + "="*60)
        print("Feature Analysis")
        print("="*60)
        
        # Gate type distribution
        gate_type_features = all_features[:, :9]
        for i, gate_type in enumerate(encoder.primitive_gates):
            count = int(np.sum(gate_type_features[:, i]))
            if count > 0:
                print(f"{gate_type}: {count} gates")
        
        # Port connection analysis
        port_features = all_features[:, 9:]
        port_names = ['RN (Reset)', 'SN (Set)', 'CK (Clock)', 'D (Data)', 'Primary Input', 'Primary Output']
        
        print(f"\nPort connection usage:")
        for i, name in enumerate(port_names):
            usage = np.mean(port_features[:, i]) * 100
            if usage > 0:
                print(f"  {name}: {usage:.2f}% of gates")
        
        # Compare trojan vs normal
        if total_trojans > 0:
            trojan_mask = all_labels == 1
            normal_mask = all_labels == 0
            
            print(f"\nPort usage comparison (Trojan vs Normal):")
            for i, name in enumerate(port_names):
                trojan_usage = np.mean(all_features[trojan_mask, 9+i]) * 100 if np.any(trojan_mask) else 0
                normal_usage = np.mean(all_features[normal_mask, 9+i]) * 100 if np.any(normal_mask) else 0
                
                if trojan_usage > 0 or normal_usage > 0:
                    diff = trojan_usage - normal_usage
                    print(f"  {name}:")
                    print(f"    Trojan: {trojan_usage:.2f}%")
                    print(f"    Normal: {normal_usage:.2f}%")
                    print(f"    Difference: {diff:+.2f}%")


if __name__ == "__main__":
    main()