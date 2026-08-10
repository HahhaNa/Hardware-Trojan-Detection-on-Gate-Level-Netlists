#!/usr/bin/env python3
"""
Debug script that saves model predictions to result files for detailed analysis
"""

import os
import sys
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from collections import defaultdict
import pickle
from tqdm import tqdm
import json

# Add parent directory to path to import from train_bigcn.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from train_bigcn import ImprovedBiGCN, FastNetlistParser


class TrojanDetector:
    """Detector class for inference"""
    
    def __init__(self, model_path='../models/best_model_augmented.pth'):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        print(f"Using device: {self.device}")
        
        # Initialize model
        self.model = ImprovedBiGCN(input_dim=20, hidden_dim=64, output_dim=2).to(self.device)
        
        # Load trained weights
        if os.path.exists(model_path):
            print(f"Loading model from {model_path}")
            checkpoint = torch.load(model_path, map_location=self.device, weights_only=False)
            
            if isinstance(checkpoint, dict) and 'model_state_dict' in checkpoint:
                self.model.load_state_dict(checkpoint['model_state_dict'])
                print(f"Model loaded successfully. Best F1: {checkpoint.get('best_f1', 'N/A')}")
            else:
                self.model.load_state_dict(checkpoint)
        else:
            raise FileNotFoundError(f"Model file {model_path} not found")
        
        self.model.eval()
        
        # Initialize parser
        self.parser = FastNetlistParser()
        
        # Load feature scaler
        scaler_path = '../models/feature_scaler.pkl'
        if os.path.exists(scaler_path):
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
            print("Feature scaler loaded successfully")
        else:
            print("Warning: Feature scaler not found")
            self.scaler = None
    
    def detect_trojans_detailed(self, netlist_path):
        """Detailed detection that returns all information needed for debugging"""
        # Parse netlist
        gates = self.parser.parse_netlist_fast(netlist_path)
        
        if not gates:
            return None
        
        # Create gate name to index mapping
        gate_name_to_idx = {gate['name']: i for i, gate in enumerate(gates)}
        
        # Build graph structure
        edge_list_fw, edge_list_bw, num_gates = self.parser.build_graph_fast(gates)
        
        # Extract features
        features = self.parser.extract_features_enhanced(gates, edge_list_fw, num_gates)
        
        # Apply scaler if available
        if self.scaler:
            features_scaled = self.scaler.transform(features)
        else:
            features_scaled = features
        
        # Convert to PyTorch tensors
        x = torch.FloatTensor(features_scaled).to(self.device)
        
        if edge_list_fw:
            edge_index_fw = torch.LongTensor(edge_list_fw).t().contiguous().to(self.device)
            edge_index_bw = torch.LongTensor(edge_list_bw).t().contiguous().to(self.device)
        else:
            edge_index_fw = torch.LongTensor([[], []]).to(self.device)
            edge_index_bw = torch.LongTensor([[], []]).to(self.device)
        
        # Run inference
        with torch.no_grad():
            out, hidden = self.model(x, edge_index_fw, edge_index_bw)
            probs = F.softmax(out, dim=1)
            preds = out.argmax(dim=1)
        
        # Prepare detailed results
        results = {
            'gates': gates,
            'features': features,  # Original features
            'features_scaled': features_scaled,
            'predictions': preds.cpu().numpy(),
            'probabilities': probs.cpu().numpy(),
            'logits': out.cpu().numpy(),
            'hidden_features': hidden.cpu().numpy(),
            'edge_list_fw': edge_list_fw,
            'edge_list_bw': edge_list_bw
        }
        
        return results


def parse_result_file(result_path):
    """Parse the golden result file to get ground truth"""
    with open(result_path, 'r') as f:
        content = f.read().strip()
    
    is_trojaned = False
    trojan_gates = []
    
    lines = content.split('\n')
    if lines[0] == 'TROJANED':
        is_trojaned = True
        in_trojan_section = False
        for line in lines[1:]:
            line = line.strip()
            if line == 'TROJAN_GATES':
                in_trojan_section = True
            elif line == 'END_TROJAN_GATES':
                break
            elif in_trojan_section and line:
                trojan_gates.append(line)
    
    return is_trojaned, trojan_gates


def save_debug_results(model_path='../models/best_model_augmented.pth', data_dir='../data/release_official', output_dir='../results/debug_results'):
    """Save detailed prediction results for debugging"""
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Initialize detector
    print(f"Loading model from {model_path}")
    detector = TrojanDetector(model_path=model_path)
    
    # Process all circuits
    all_results = []
    
    # Process trojan circuits
    trojan_dir = os.path.join(data_dir, 'trojan')
    print(f"\nProcessing trojan circuits from {trojan_dir}")
    
    for design_file in sorted([f for f in os.listdir(trojan_dir) if f.endswith('.v')]):
        design_name = design_file.replace('.v', '')
        design_path = os.path.join(trojan_dir, design_file)
        result_path = os.path.join(trojan_dir, f'result{design_name[6:]}.txt')
        
        if not os.path.exists(result_path):
            print(f"Warning: No result file for {design_name}")
            continue
        
        print(f"Processing {design_name}...")
        
        # Get ground truth
        true_is_trojaned, true_trojan_gates = parse_result_file(result_path)
        
        # Get detailed predictions
        results = detector.detect_trojans_detailed(design_path)
        if results is None:
            continue
        
        # Add ground truth
        results['true_is_trojaned'] = true_is_trojaned
        results['true_trojan_gates'] = true_trojan_gates
        results['circuit_name'] = design_name
        results['is_trojan_folder'] = True
        
        # Save individual circuit results
        circuit_output_dir = os.path.join(output_dir, design_name)
        os.makedirs(circuit_output_dir, exist_ok=True)
        
        # Save prediction results
        save_circuit_results(circuit_output_dir, results)
        
        all_results.append(results)
    
    # Process trojan-free circuits
    trojan_free_dir = os.path.join(data_dir, 'trojan_free')
    print(f"\nProcessing trojan-free circuits from {trojan_free_dir}")
    
    for design_file in sorted([f for f in os.listdir(trojan_free_dir) if f.endswith('.v')]):
        design_name = design_file.replace('.v', '')
        design_path = os.path.join(trojan_free_dir, design_file)
        
        print(f"Processing {design_name}...")
        
        # Get detailed predictions
        results = detector.detect_trojans_detailed(design_path)
        if results is None:
            continue
        
        # Add ground truth (no trojans)
        results['true_is_trojaned'] = False
        results['true_trojan_gates'] = []
        results['circuit_name'] = design_name
        results['is_trojan_folder'] = False
        
        # Save individual circuit results
        circuit_output_dir = os.path.join(output_dir, design_name)
        os.makedirs(circuit_output_dir, exist_ok=True)
        
        # Save prediction results
        save_circuit_results(circuit_output_dir, results)
        
        all_results.append(results)
    
    # Generate summary statistics
    generate_summary(output_dir, all_results)
    
    print(f"\nDebug results saved to {output_dir}/")


def save_circuit_results(output_dir, results):
    """Save detailed results for a single circuit"""
    
    # 1. Save predicted result.txt format
    pred_trojan_indices = np.where(results['predictions'] == 1)[0]
    pred_trojan_gates = [results['gates'][idx]['name'] for idx in pred_trojan_indices]
    
    with open(os.path.join(output_dir, 'predicted_result.txt'), 'w') as f:
        if len(pred_trojan_gates) > 0:
            f.write("TROJANED\n")
            f.write("TROJAN_GATES\n")
            for gate in pred_trojan_gates:
                f.write(f"{gate}\n")
            f.write("END_TROJAN_GATES\n")
        else:
            f.write("NO_TROJAN\n")
    
    # 2. Save ground truth result.txt format
    with open(os.path.join(output_dir, 'ground_truth.txt'), 'w') as f:
        if results['true_is_trojaned']:
            f.write("TROJANED\n")
            f.write("TROJAN_GATES\n")
            for gate in results['true_trojan_gates']:
                f.write(f"{gate}\n")
            f.write("END_TROJAN_GATES\n")
        else:
            f.write("NO_TROJAN\n")
    
    # 3. Save detailed gate analysis
    gate_analysis = []
    gate_name_to_idx = {g['name']: i for i, g in enumerate(results['gates'])}
    
    for i, gate in enumerate(results['gates']):
        is_true_trojan = gate['name'] in results['true_trojan_gates']
        is_pred_trojan = results['predictions'][i] == 1
        
        analysis = {
            'index': int(i),
            'name': gate['name'],
            'type': int(gate['type']),
            'inputs': gate['inputs'],
            'output': gate['output'],
            'true_label': 1 if is_true_trojan else 0,
            'pred_label': int(results['predictions'][i]),
            'trojan_probability': float(results['probabilities'][i][1]),
            'normal_probability': float(results['probabilities'][i][0]),
            'logit_normal': float(results['logits'][i][0]),
            'logit_trojan': float(results['logits'][i][1]),
            'features': [float(x) for x in results['features'][i]],
            'features_scaled': [float(x) for x in results['features_scaled'][i]],
            'status': 'TP' if is_true_trojan and is_pred_trojan else
                     'TN' if not is_true_trojan and not is_pred_trojan else
                     'FP' if not is_true_trojan and is_pred_trojan else 'FN'
        }
        gate_analysis.append(analysis)
    
    # Save as JSON for easy analysis
    with open(os.path.join(output_dir, 'gate_analysis.json'), 'w') as f:
        json.dump(gate_analysis, f, indent=2)
    
    # 4. Save summary statistics
    summary = {
        'circuit_name': results['circuit_name'],
        'total_gates': len(results['gates']),
        'true_trojans': len(results['true_trojan_gates']),
        'pred_trojans': int(np.sum(results['predictions'] == 1)),
        'true_positives': sum(1 for g in gate_analysis if g['status'] == 'TP'),
        'true_negatives': sum(1 for g in gate_analysis if g['status'] == 'TN'),
        'false_positives': sum(1 for g in gate_analysis if g['status'] == 'FP'),
        'false_negatives': sum(1 for g in gate_analysis if g['status'] == 'FN'),
        'avg_trojan_prob_for_true_trojans': float(np.mean([g['trojan_probability'] for g in gate_analysis if g['true_label'] == 1])) if any(g['true_label'] == 1 for g in gate_analysis) else 0.0,
        'avg_trojan_prob_for_pred_trojans': float(np.mean([g['trojan_probability'] for g in gate_analysis if g['pred_label'] == 1])) if any(g['pred_label'] == 1 for g in gate_analysis) else 0.0,
        'avg_trojan_prob_for_normal_gates': float(np.mean([g['trojan_probability'] for g in gate_analysis if g['true_label'] == 0])) if any(g['true_label'] == 0 for g in gate_analysis) else 0.0,
    }
    
    with open(os.path.join(output_dir, 'summary.json'), 'w') as f:
        json.dump(summary, f, indent=2)
    
    # 5. Save high-confidence mistakes
    mistakes = {
        'false_positives': sorted([g for g in gate_analysis if g['status'] == 'FP'], 
                                 key=lambda x: x['trojan_probability'], reverse=True)[:20],
        'false_negatives': sorted([g for g in gate_analysis if g['status'] == 'FN'], 
                                 key=lambda x: x['trojan_probability'])[:20]
    }
    
    with open(os.path.join(output_dir, 'mistakes.json'), 'w') as f:
        json.dump(mistakes, f, indent=2)


def generate_summary(output_dir, all_results):
    """Generate overall summary statistics"""
    
    summary = {
        'total_circuits': len(all_results),
        'trojan_circuits': sum(1 for r in all_results if r['true_is_trojaned']),
        'clean_circuits': sum(1 for r in all_results if not r['true_is_trojaned']),
        'circuit_level': {
            'true_positive_circuits': 0,
            'true_negative_circuits': 0,
            'false_positive_circuits': [],
            'false_negative_circuits': []
        },
        'gate_level': {
            'total_gates': 0,
            'total_trojan_gates': 0,
            'total_predicted_trojans': 0,
            'true_positives': 0,
            'false_positives': 0,
            'false_negatives': 0,
            'true_negatives': 0
        },
        'per_circuit_stats': []
    }
    
    for results in all_results:
        circuit_name = results['circuit_name']
        true_is_trojaned = results['true_is_trojaned']
        pred_is_trojaned = np.any(results['predictions'] == 1)
        
        # Circuit-level stats
        if true_is_trojaned and pred_is_trojaned:
            summary['circuit_level']['true_positive_circuits'] += 1
        elif not true_is_trojaned and not pred_is_trojaned:
            summary['circuit_level']['true_negative_circuits'] += 1
        elif not true_is_trojaned and pred_is_trojaned:
            summary['circuit_level']['false_positive_circuits'].append(circuit_name)
        else:
            summary['circuit_level']['false_negative_circuits'].append(circuit_name)
        
        # Gate-level stats
        gate_name_to_idx = {g['name']: i for i, g in enumerate(results['gates'])}
        true_labels = np.zeros(len(results['gates']))
        for gate_name in results['true_trojan_gates']:
            if gate_name in gate_name_to_idx:
                true_labels[gate_name_to_idx[gate_name]] = 1
        
        tp = int(np.sum((true_labels == 1) & (results['predictions'] == 1)))
        fp = int(np.sum((true_labels == 0) & (results['predictions'] == 1)))
        fn = int(np.sum((true_labels == 1) & (results['predictions'] == 0)))
        tn = int(np.sum((true_labels == 0) & (results['predictions'] == 0)))
        
        summary['gate_level']['total_gates'] += len(results['gates'])
        summary['gate_level']['total_trojan_gates'] += int(np.sum(true_labels))
        summary['gate_level']['total_predicted_trojans'] += int(np.sum(results['predictions'] == 1))
        summary['gate_level']['true_positives'] += tp
        summary['gate_level']['false_positives'] += fp
        summary['gate_level']['false_negatives'] += fn
        summary['gate_level']['true_negatives'] += tn
        
        # Per-circuit stats
        circuit_stat = {
            'circuit': circuit_name,
            'is_trojan': true_is_trojaned,
            'total_gates': len(results['gates']),
            'true_trojans': int(np.sum(true_labels)),
            'pred_trojans': int(np.sum(results['predictions'] == 1)),
            'tp': tp,
            'fp': fp,
            'fn': fn,
            'tn': tn,
            'recall': float(tp / np.sum(true_labels)) if np.sum(true_labels) > 0 else 0.0,
            'precision': float(tp / np.sum(results['predictions'] == 1)) if np.sum(results['predictions'] == 1) > 0 else 0.0
        }
        summary['per_circuit_stats'].append(circuit_stat)
    
    # Calculate metrics
    if summary['gate_level']['true_positives'] + summary['gate_level']['false_negatives'] > 0:
        summary['gate_level']['recall'] = float(summary['gate_level']['true_positives']) / float(summary['gate_level']['true_positives'] + summary['gate_level']['false_negatives'])
    else:
        summary['gate_level']['recall'] = 0.0
    
    if summary['gate_level']['true_positives'] + summary['gate_level']['false_positives'] > 0:
        summary['gate_level']['precision'] = float(summary['gate_level']['true_positives']) / float(summary['gate_level']['true_positives'] + summary['gate_level']['false_positives'])
    else:
        summary['gate_level']['precision'] = 0.0
    
    if summary['gate_level']['precision'] + summary['gate_level']['recall'] > 0:
        summary['gate_level']['f1'] = 2.0 * summary['gate_level']['precision'] * summary['gate_level']['recall'] / (summary['gate_level']['precision'] + summary['gate_level']['recall'])
    else:
        summary['gate_level']['f1'] = 0.0
    
    # Save summary
    with open(os.path.join(output_dir, 'overall_summary.json'), 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"\nOverall Summary:")
    print(f"Circuit-level: TP={summary['circuit_level']['true_positive_circuits']}, "
          f"TN={summary['circuit_level']['true_negative_circuits']}, "
          f"FP={len(summary['circuit_level']['false_positive_circuits'])}, "
          f"FN={len(summary['circuit_level']['false_negative_circuits'])}")
    print(f"Gate-level: Precision={summary['gate_level']['precision']:.3f}, "
          f"Recall={summary['gate_level']['recall']:.3f}, "
          f"F1={summary['gate_level']['f1']:.3f}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Debug Bi-GCN predictions')
    parser.add_argument('--model', type=str, default='../models/best_model_augmented.pth',
                       help='Path to trained model')
    parser.add_argument('--data-dir', type=str, default='../data/release_official',
                       help='Path to official test data directory')
    parser.add_argument('--output-dir', type=str, default='../results/debug_results',
                       help='Directory to save debug results')
    args = parser.parse_args()
    
    # Check if model exists
    if not os.path.exists(args.model):
        print(f"Error: Model file {args.model} not found")
        sys.exit(1)
    
    # Check if data directory exists
    if not os.path.exists(args.data_dir):
        print(f"Error: Data directory {args.data_dir} not found")
        sys.exit(1)
    
    # Save debug results
    save_debug_results(args.model, args.data_dir, args.output_dir)


if __name__ == "__main__":
    main()