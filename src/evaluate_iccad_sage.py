#!/usr/bin/env python3
"""
ICCAD Contest Evaluation Script
Evaluates model performance according to contest criteria and generates CSV report
"""

import torch
import torch.nn.functional as F
import numpy as np
import pandas as pd
import os
import re
import argparse
from collections import defaultdict
import pickle
from tqdm import tqdm
import time

# Import necessary components from your training script
import sys
sys.path.append('.')  # Add current directory to path

# We'll need to import the model and data processing components
# You may need to adjust these imports based on your file structure
try:
    from train_bigcn import (
        ImprovedBiGCN, 
        FastNetlistParser,
        set_seed
    )
except ImportError:
    print("Error: Could not import from train_bigcn.py. Make sure it's in the same directory.")
    print("Alternatively, copy the necessary classes into this script.")
    exit(1)


def load_ground_truth(result_file):
    """Load ground truth from result file"""
    if not os.path.exists(result_file):
        return "NO_TROJAN", []
    
    with open(result_file, 'r') as f:
        lines = f.readlines()
    
    # Parse the result file
    status = lines[0].strip()
    trojan_gates = []
    
    if status == "TROJANED":
        in_trojan_section = False
        for line in lines[1:]:
            line = line.strip()
            if line == "TROJAN_GATES":
                in_trojan_section = True
            elif line == "END_TROJAN_GATES":
                break
            elif in_trojan_section and line:
                trojan_gates.append(line)
    
    return status, trojan_gates


def predict_circuit(model, parser, filepath, scaler, device, threshold=0.5, min_trojan_gates=1):
    """Predict trojan status and gates for a single circuit
    
    Args:
        model: Trained model
        parser: Netlist parser
        filepath: Path to circuit file
        scaler: Feature scaler
        device: Torch device
        threshold: Probability threshold for gate classification
        min_trojan_gates: Minimum number of trojan gates required to classify circuit as TROJANED
    """
    try:
        # Parse netlist
        gates = parser.parse_netlist_fast(filepath)
        edge_list_fw, edge_list_bw, num_gates = parser.build_graph_fast(gates)
        features = parser.extract_features_enhanced(gates, edge_list_fw, num_gates)
        
        # Normalize features
        features = scaler.transform(features)
        
        # Convert to tensors
        x = torch.FloatTensor(features).to(device)
        edge_index_fw = torch.LongTensor(edge_list_fw).t().contiguous().to(device)
        edge_index_bw = torch.LongTensor(edge_list_bw).t().contiguous().to(device)
        
        # Predict
        model.eval()
        with torch.no_grad():
            out, _ = model(x, edge_index_fw, edge_index_bw)
            probs = F.softmax(out, dim=1)
            preds = (probs[:, 1] > threshold).cpu().numpy()
        
        # Get trojan gates
        trojan_gate_names = []
        for i, (pred, gate) in enumerate(zip(preds, gates)):
            if pred == 1:
                trojan_gate_names.append(gate['name'])
        
        # Apply minimum trojan gates filter
        # If fewer than min_trojan_gates are detected, classify as NO_TROJAN
        if len(trojan_gate_names) < min_trojan_gates:
            return "NO_TROJAN", []
        else:
            return "TROJANED", trojan_gate_names
        
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return "NO_TROJAN", []


def calculate_f1_score(predicted_gates, true_gates):
    """Calculate F1 score for gate-level predictions"""
    if not true_gates and not predicted_gates:
        # Both empty - perfect score for Trojan-free circuit
        return 1.0, 1.0, 1.0, 0, 0, 0
    
    if not true_gates:
        # No true trojan gates but we predicted some (all FP)
        fp = len(predicted_gates)
        return 0.0, 0.0, 0.0, 0, fp, 0
    
    if not predicted_gates:
        # True trojan gates exist but we predicted none (all FN)
        fn = len(true_gates)
        return 0.0, 0.0, 0.0, 0, 0, fn
    
    # Calculate TP, FP, FN
    true_set = set(true_gates)
    pred_set = set(predicted_gates)
    
    tp = len(true_set.intersection(pred_set))
    fp = len(pred_set - true_set)
    fn = len(true_set - pred_set)
    
    # Calculate precision, recall, F1
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return precision, recall, f1, tp, fp, fn


def evaluate_directory(model_path, data_dir, output_csv, scaler_path='../models/feature_scaler.pkl', 
                      threshold=None, min_trojan_gates=10, device=None):
    """Evaluate model on all circuits in directory and generate CSV report
    
    Args:
        model_path: Path to model checkpoint
        data_dir: Directory containing test data
        output_csv: Output CSV file path
        scaler_path: Path to feature scaler
        threshold: Probability threshold for gate classification
        min_trojan_gates: Minimum number of trojan gates to classify circuit as TROJANED
        device: Torch device
    """
    
    # Set device
    if device is None:
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    
    # Load model
    print(f"Loading model from {model_path}...")
    checkpoint = torch.load(model_path, map_location=device)
    
    # Initialize model
    model = ImprovedBiGCN(
        input_dim=checkpoint.get('feature_dim', 30),
        hidden_dim=96,
        output_dim=2
    ).to(device)
    
    model.load_state_dict(checkpoint['model_state_dict'])
    model.eval()
    
    # Get threshold
    if threshold is None:
        threshold = checkpoint.get('best_threshold', 0.5)
    print(f"Using threshold: {threshold:.3f}")
    print(f"Minimum trojan gates for TROJANED classification: {min_trojan_gates}")
    
    # Load scaler
    print(f"Loading feature scaler from {scaler_path}...")
    with open(scaler_path, 'rb') as f:
        scaler = pickle.load(f)
    
    # Initialize parser
    parser = FastNetlistParser()
    
    # Prepare results storage
    results = []
    
    # Process trojan directory
    trojan_dir = os.path.join(data_dir, 'trojan')
    trojan_free_dir = os.path.join(data_dir, 'trojan_free')
    
    print("\nEvaluating Trojan circuits...")
    if os.path.exists(trojan_dir):
        trojan_files = sorted([f for f in os.listdir(trojan_dir) if f.endswith('.v')])
        
        for design_file in tqdm(trojan_files, desc="Trojan circuits"):
            design_num = int(re.match(r'design(\d+)\.v', design_file).group(1))
            design_path = os.path.join(trojan_dir, design_file)
            result_path = os.path.join(trojan_dir, f'result{design_num}.txt')
            
            # Get ground truth
            true_status, true_gates = load_ground_truth(result_path)
            
            # Get predictions
            start_time = time.time()
            pred_status, pred_gates = predict_circuit(model, parser, design_path, scaler, device, threshold, min_trojan_gates)
            inference_time = time.time() - start_time
            
            # Calculate scores
            circuit_correct = (pred_status == true_status)
            
            if circuit_correct and true_status == "TROJANED":
                # Calculate F1 score for trojan gates
                precision, recall, f1, tp, fp, fn = calculate_f1_score(pred_gates, true_gates)
                points = 2.0 + f1  # 2 points for correct + F1 score
            elif circuit_correct:
                # Correctly identified as NO_TROJAN (shouldn't happen in trojan dir)
                precision = recall = f1 = 1.0
                tp = fp = fn = 0
                points = 2.0
            else:
                # Incorrect circuit classification
                precision = recall = f1 = 0.0
                tp = fp = fn = 0
                points = 0.0
            
            results.append({
                'Design': design_file,
                'Type': 'Trojan',
                'True_Status': true_status,
                'Pred_Status': pred_status,
                'Circuit_Correct': circuit_correct,
                'True_Gates': len(true_gates),
                'Pred_Gates': len(pred_gates),
                'TP': tp,
                'FP': fp,
                'FN': fn,
                'Precision': precision,
                'Recall': recall,
                'F1_Score': f1,
                'Points': points,
                'Inference_Time': inference_time
            })
    
    print("\nEvaluating Trojan-free circuits...")
    if os.path.exists(trojan_free_dir):
        trojan_free_files = sorted([f for f in os.listdir(trojan_free_dir) if f.endswith('.v')])
        
        for design_file in tqdm(trojan_free_files, desc="Trojan-free circuits"):
            design_path = os.path.join(trojan_free_dir, design_file)
            
            # Ground truth is always NO_TROJAN for trojan_free directory
            true_status = "NO_TROJAN"
            true_gates = []
            
            # Get predictions
            start_time = time.time()
            pred_status, pred_gates = predict_circuit(model, parser, design_path, scaler, device, threshold, min_trojan_gates)
            inference_time = time.time() - start_time
            
            # Calculate scores
            circuit_correct = (pred_status == true_status)
            
            if circuit_correct:
                # Correctly identified as NO_TROJAN
                precision = recall = f1 = 1.0
                tp = fp = fn = 0
                points = 2.0
            else:
                # Incorrectly identified as TROJANED
                precision = recall = f1 = 0.0
                tp = 0
                fp = len(pred_gates)
                fn = 0
                points = 0.0
            
            results.append({
                'Design': design_file,
                'Type': 'Trojan-free',
                'True_Status': true_status,
                'Pred_Status': pred_status,
                'Circuit_Correct': circuit_correct,
                'True_Gates': 0,
                'Pred_Gates': len(pred_gates),
                'TP': tp,
                'FP': fp,
                'FN': fn,
                'Precision': precision,
                'Recall': recall,
                'F1_Score': f1,
                'Points': points,
                'Inference_Time': inference_time
            })
    
    # Create DataFrame
    df = pd.DataFrame(results)
    
    # Calculate summary statistics
    total_circuits = len(df)
    correct_circuits = df['Circuit_Correct'].sum()
    circuit_accuracy = correct_circuits / total_circuits if total_circuits > 0 else 0
    
    trojan_df = df[df['Type'] == 'Trojan']
    trojan_free_df = df[df['Type'] == 'Trojan-free']
    
    # Calculate aggregated metrics
    total_points = df['Points'].sum()
    max_possible_points = len(trojan_df) * 3.0 + len(trojan_free_df) * 2.0  # Max 3 points for trojan, 2 for clean
    score_percentage = (total_points / max_possible_points * 100) if max_possible_points > 0 else 0
    
    # Add summary row
    summary = {
        'Design': 'TOTAL/AVERAGE',
        'Type': 'Summary',
        'True_Status': '',
        'Pred_Status': '',
        'Circuit_Correct': circuit_accuracy,
        'True_Gates': df['True_Gates'].sum(),
        'Pred_Gates': df['Pred_Gates'].sum(),
        'TP': df['TP'].sum(),
        'FP': df['FP'].sum(),
        'FN': df['FN'].sum(),
        'Precision': df['TP'].sum() / (df['TP'].sum() + df['FP'].sum()) if (df['TP'].sum() + df['FP'].sum()) > 0 else 0,
        'Recall': df['TP'].sum() / (df['TP'].sum() + df['FN'].sum()) if (df['TP'].sum() + df['FN'].sum()) > 0 else 0,
        'F1_Score': '',
        'Points': total_points,
        'Inference_Time': df['Inference_Time'].mean()
    }
    
    # Calculate overall F1
    if summary['Precision'] + summary['Recall'] > 0:
        summary['F1_Score'] = 2 * summary['Precision'] * summary['Recall'] / (summary['Precision'] + summary['Recall'])
    else:
        summary['F1_Score'] = 0.0
    
    df = pd.concat([df, pd.DataFrame([summary])], ignore_index=True)
    
    # Save to CSV
    df.to_csv(output_csv, index=False, float_format='%.4f')
    print(f"\nResults saved to {output_csv}")
    
    # Print summary
    print("\n" + "="*60)
    print("EVALUATION SUMMARY")
    print("="*60)
    print(f"Total circuits evaluated: {total_circuits}")
    print(f"Correct circuit classifications: {correct_circuits}/{total_circuits} ({circuit_accuracy*100:.2f}%)")
    print(f"\nTrojan circuits: {len(trojan_df)}")
    print(f"  - Correctly identified: {trojan_df['Circuit_Correct'].sum()}/{len(trojan_df)}")
    print(f"  - Average F1 score: {trojan_df['F1_Score'].mean():.4f}")
    print(f"\nTrojan-free circuits: {len(trojan_free_df)}")
    print(f"  - Correctly identified: {trojan_free_df['Circuit_Correct'].sum()}/{len(trojan_free_df)}")
    print(f"\nGate-level metrics (overall):")
    print(f"  - True Positives: {summary['TP']}")
    print(f"  - False Positives: {summary['FP']}")
    print(f"  - False Negatives: {summary['FN']}")
    print(f"  - Precision: {summary['Precision']:.4f}")
    print(f"  - Recall: {summary['Recall']:.4f}")
    print(f"  - F1 Score: {summary['F1_Score']:.4f}")
    print(f"\nContest Scoring:")
    print(f"  - Total points: {total_points:.4f}")
    print(f"  - Maximum possible points: {max_possible_points:.4f}")
    print(f"  - Score percentage: {score_percentage:.2f}%")
    print(f"\nAverage inference time: {df[df['Design'] != 'TOTAL/AVERAGE']['Inference_Time'].mean():.4f} seconds")
    print("="*60)
    
    return df


def main():
    parser = argparse.ArgumentParser(description='ICCAD Contest Evaluation Script')
    parser.add_argument('--model', type=str, default='../models/best_model_augmented_sage.pth',
                        help='Path to trained model checkpoint')
    parser.add_argument('--data-dir', type=str, default='../data/release_official',
                        help='Directory containing test data')
    parser.add_argument('--output', type=str, default='../results/evaluation_results_sage.csv',
                        help='Output CSV file path')
    parser.add_argument('--scaler', type=str, default='../models/feature_scaler.pkl',
                        help='Path to feature scaler')
    parser.add_argument('--threshold', type=float, default=None,
                        help='Classification threshold (default: use model\'s best threshold)')
    parser.add_argument('--min-trojan-gates', type=int, default=10,
                        help='Minimum number of trojan gates to classify circuit as TROJANED (default: 10)')
    parser.add_argument('--seed', type=int, default=42,
                        help='Random seed for reproducibility')
    
    args = parser.parse_args()
    
    # Set random seed
    set_seed(args.seed)
    
    # Verify paths exist
    if not os.path.exists(args.model):
        print(f"Error: Model file {args.model} not found!")
        return
    
    if not os.path.exists(args.data_dir):
        print(f"Error: Data directory {args.data_dir} not found!")
        return
    
    if not os.path.exists(args.scaler):
        print(f"Error: Scaler file {args.scaler} not found!")
        return
    
    # Run evaluation
    evaluate_directory(
        model_path=args.model,
        data_dir=args.data_dir,
        output_csv=args.output,
        scaler_path=args.scaler,
        threshold=args.threshold,
        min_trojan_gates=args.min_trojan_gates
    )


if __name__ == "__main__":
    main()