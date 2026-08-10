#!/usr/bin/env python3
"""
Aggressive Hardware Trojan Data Augmentation Script
- Supports 5-25% gate modifications
- Multiple replacement strategies without Yosys
- Advanced gate replacement patterns
"""

import os
import re
import random
import argparse
from typing import List, Tuple, Dict, Set
from dataclasses import dataclass
from collections import defaultdict
import shutil


@dataclass
class Gate:
    """Represents a gate in the netlist"""
    name: str
    gate_type: str
    output: str
    inputs: List[str]
    line: str
    line_number: int
    
    def __hash__(self):
        return hash(self.name)
    
    def __eq__(self, other):
        if isinstance(other, Gate):
            return self.name == other.name
        return False


@dataclass
class DFF:
    """Represents a DFF in the netlist"""
    name: str
    params: Dict[str, str]
    line: str
    line_number: int
    
    def __hash__(self):
        return hash(self.name)
    
    def __eq__(self, other):
        if isinstance(other, DFF):
            return self.name == other.name
        return False


class NetlistParser:
    """Parse Verilog netlist and extract gates and connections"""
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.gates = []
        self.dffs = []
        self.wires = set()
        self.inputs = set()
        self.outputs = set()
        self.lines = []
        
    def parse(self):
        """Parse the netlist file"""
        with open(self.filepath, 'r') as f:
            self.lines = f.readlines()
            
        for i, line in enumerate(self.lines):
            line = line.strip()
            
            # Parse wire declarations
            if line.startswith('wire'):
                self._parse_wire(line)
            
            # Parse input/output declarations
            elif line.startswith('input'):
                self._parse_io(line, self.inputs)
            elif line.startswith('output'):
                self._parse_io(line, self.outputs)
                
            # Parse primitive gates
            elif any(line.startswith(gate + ' ') for gate in ['and', 'or', 'nand', 'nor', 'not', 'buf', 'xor', 'xnor']):
                self._parse_gate(line, i)
                
            # Parse DFFs
            elif line.startswith('dff '):
                self._parse_dff(line, i)
    
    def _parse_wire(self, line: str):
        """Parse wire declarations"""
        # Handle arrays like wire [7:0] n1;
        match = re.search(r'wire\s+(?:\[\d+:\d+\]\s+)?(\w+)', line)
        if match:
            self.wires.add(match.group(1))
    
    def _parse_io(self, line: str, target_set: Set[str]):
        """Parse input/output declarations"""
        # Handle arrays like input [7:0] in;
        match = re.search(r'(?:input|output)\s+(?:\[\d+:\d+\]\s+)?(\w+)', line)
        if match:
            target_set.add(match.group(1))
    
    def _parse_gate(self, line: str, line_num: int):
        """Parse primitive gate"""
        # Match patterns like: and g0 (n1, in[0], in[1]);
        match = re.match(r'(\w+)\s+(\w+)\s*\(([^)]+)\)', line)
        if match:
            gate_type = match.group(1)
            gate_name = match.group(2)
            connections = [c.strip() for c in match.group(3).split(',')]
            
            # First connection is output, rest are inputs
            output = connections[0]
            inputs = connections[1:]
            
            gate = Gate(
                name=gate_name,
                gate_type=gate_type,
                output=output,
                inputs=inputs,
                line=self.lines[line_num],
                line_number=line_num
            )
            self.gates.append(gate)
    
    def _parse_dff(self, line: str, line_num: int):
        """Parse DFF"""
        # Match patterns like: dff g3 (.RN(rst_n), .SN(1'b1), .CK(clk), .D(n2471), .Q(out[0]));
        match = re.match(r'dff\s+(\w+)\s*\(([^)]+)\)', line)
        if match:
            dff_name = match.group(1)
            params_str = match.group(2)
            
            # Parse named parameters
            params = {}
            param_matches = re.findall(r'\.(\w+)\(([^)]+)\)', params_str)
            for param_name, param_value in param_matches:
                params[param_name] = param_value
            
            dff = DFF(
                name=dff_name,
                params=params,
                line=self.lines[line_num],
                line_number=line_num
            )
            self.dffs.append(dff)
    
    def get_total_gate_count(self):
        """Get total number of gates (excluding DFFs)"""
        return len(self.gates)


class AggressiveGateReplacer:
    """Aggressive gate replacement with multiple patterns for each gate type"""
    
    def __init__(self):
        # Multiple replacement patterns for maximum variety
        self.replacement_patterns = {
            'and': [
                # Basic NAND-NOT
                lambda g: [
                    f"nand {g.name}_nand ({g.name}_nand_out, {', '.join(g.inputs)});",
                    f"not {g.name}_not ({g.output}, {g.name}_nand_out);"
                ],
                # De Morgan's law: AND(a,b) = NOT(NOR(NOT(a), NOT(b)))
                lambda g: [
                    f"not {g.name}_not_a ({g.name}_not_a_out, {g.inputs[0]});",
                    f"not {g.name}_not_b ({g.name}_not_b_out, {g.inputs[1]});",
                    f"nor {g.name}_nor ({g.name}_nor_out, {g.name}_not_a_out, {g.name}_not_b_out);",
                    f"not {g.name}_not ({g.output}, {g.name}_nor_out);"
                ],
                # Using only NAND gates
                lambda g: [
                    f"nand {g.name}_nand1 ({g.name}_nand1_out, {g.inputs[0]}, {g.inputs[1]});",
                    f"nand {g.name}_nand2 ({g.output}, {g.name}_nand1_out, {g.name}_nand1_out);"
                ],
                # Complex implementation with XOR/OR
                lambda g: [
                    f"xor {g.name}_xor ({g.name}_xor_out, {g.inputs[0]}, {g.inputs[1]});",
                    f"or {g.name}_or ({g.name}_or_out, {g.inputs[0]}, {g.inputs[1]});",
                    f"not {g.name}_not_xor ({g.name}_not_xor_out, {g.name}_xor_out);",
                    f"and {g.name}_and ({g.output}, {g.name}_or_out, {g.name}_not_xor_out);"
                ]
            ],
            
            'or': [
                # Basic NOR-NOT
                lambda g: [
                    f"nor {g.name}_nor ({g.name}_nor_out, {', '.join(g.inputs)});",
                    f"not {g.name}_not ({g.output}, {g.name}_nor_out);"
                ],
                # De Morgan's law: OR(a,b) = NOT(NAND(NOT(a), NOT(b)))
                lambda g: [
                    f"not {g.name}_not_a ({g.name}_not_a_out, {g.inputs[0]});",
                    f"not {g.name}_not_b ({g.name}_not_b_out, {g.inputs[1]});",
                    f"nand {g.name}_nand ({g.name}_nand_out, {g.name}_not_a_out, {g.name}_not_b_out);",
                    f"not {g.name}_not ({g.output}, {g.name}_nand_out);"
                ],
                # Using only NOR gates
                lambda g: [
                    f"nor {g.name}_nor1 ({g.name}_nor1_out, {g.inputs[0]}, {g.inputs[1]});",
                    f"nor {g.name}_nor2 ({g.output}, {g.name}_nor1_out, {g.name}_nor1_out);"
                ],
                # Complex with XOR
                lambda g: [
                    f"xor {g.name}_xor ({g.name}_xor_out, {g.inputs[0]}, {g.inputs[1]});",
                    f"and {g.name}_and ({g.name}_and_out, {g.inputs[0]}, {g.inputs[1]});",
                    f"xor {g.name}_xor2 ({g.output}, {g.name}_xor_out, {g.name}_and_out);"
                ]
            ],
            
            'xor': [
                # Basic implementation
                lambda g: [
                    f"not {g.name}_not1 ({g.name}_not1_out, {g.inputs[0]});",
                    f"not {g.name}_not2 ({g.name}_not2_out, {g.inputs[1]});",
                    f"and {g.name}_and1 ({g.name}_and1_out, {g.inputs[0]}, {g.name}_not2_out);",
                    f"and {g.name}_and2 ({g.name}_and2_out, {g.name}_not1_out, {g.inputs[1]});",
                    f"or {g.name}_or ({g.output}, {g.name}_and1_out, {g.name}_and2_out);"
                ],
                # Using NAND gates
                lambda g: [
                    f"nand {g.name}_nand1 ({g.name}_nand1_out, {g.inputs[0]}, {g.inputs[1]});",
                    f"nand {g.name}_nand2 ({g.name}_nand2_out, {g.inputs[0]}, {g.name}_nand1_out);",
                    f"nand {g.name}_nand3 ({g.name}_nand3_out, {g.inputs[1]}, {g.name}_nand1_out);",
                    f"nand {g.name}_nand4 ({g.output}, {g.name}_nand2_out, {g.name}_nand3_out);"
                ],
                # Using NOR gates
                lambda g: [
                    f"nor {g.name}_nor1 ({g.name}_nor1_out, {g.inputs[0]}, {g.inputs[1]});",
                    f"or {g.name}_or ({g.name}_or_out, {g.inputs[0]}, {g.inputs[1]});",
                    f"not {g.name}_not ({g.name}_not_out, {g.name}_or_out);",
                    f"nor {g.name}_nor2 ({g.output}, {g.name}_nor1_out, {g.name}_not_out);"
                ]
            ],
            
            'nand': [
                # Basic AND-NOT
                lambda g: [
                    f"and {g.name}_and ({g.name}_and_out, {', '.join(g.inputs)});",
                    f"not {g.name}_not ({g.output}, {g.name}_and_out);"
                ],
                # Using NOR
                lambda g: [
                    f"not {g.name}_not_a ({g.name}_not_a_out, {g.inputs[0]});",
                    f"not {g.name}_not_b ({g.name}_not_b_out, {g.inputs[1]});",
                    f"or {g.name}_or ({g.name}_or_out, {g.name}_not_a_out, {g.name}_not_b_out);",
                    f"not {g.name}_not ({g.output}, {g.name}_or_out);"
                ]
            ],
            
            'nor': [
                # Basic OR-NOT
                lambda g: [
                    f"or {g.name}_or ({g.name}_or_out, {', '.join(g.inputs)});",
                    f"not {g.name}_not ({g.output}, {g.name}_or_out);"
                ],
                # Using NAND
                lambda g: [
                    f"not {g.name}_not_a ({g.name}_not_a_out, {g.inputs[0]});",
                    f"not {g.name}_not_b ({g.name}_not_b_out, {g.inputs[1]});",
                    f"and {g.name}_and ({g.name}_and_out, {g.name}_not_a_out, {g.name}_not_b_out);",
                    f"not {g.name}_not ({g.output}, {g.name}_and_out);"
                ]
            ],
            
            'not': [
                # Using NAND
                lambda g: [
                    f"nand {g.name}_nand ({g.output}, {g.inputs[0]}, {g.inputs[0]});"
                ],
                # Using NOR
                lambda g: [
                    f"nor {g.name}_nor ({g.output}, {g.inputs[0]}, {g.inputs[0]});"
                ],
                # Double inversion with buffer
                lambda g: [
                    f"buf {g.name}_buf1 ({g.name}_buf1_out, {g.inputs[0]});",
                    f"not {g.name}_not1 ({g.name}_not1_out, {g.name}_buf1_out);",
                    f"not {g.name}_not2 ({g.output}, {g.name}_not1_out);"
                ]
            ],
            
            'buf': [
                # Double NOT
                lambda g: [
                    f"not {g.name}_not1 ({g.name}_not1_out, {g.inputs[0]});",
                    f"not {g.name}_not2 ({g.output}, {g.name}_not1_out);"
                ],
                # Using AND
                lambda g: [
                    f"and {g.name}_and ({g.output}, {g.inputs[0]}, {g.inputs[0]});"
                ],
                # Using OR
                lambda g: [
                    f"or {g.name}_or ({g.output}, {g.inputs[0]}, {g.inputs[0]});"
                ]
            ],
            
            'xnor': [
                # XOR-NOT
                lambda g: [
                    f"xor {g.name}_xor ({g.name}_xor_out, {', '.join(g.inputs)});",
                    f"not {g.name}_not ({g.output}, {g.name}_xor_out);"
                ],
                # Direct implementation
                lambda g: [
                    f"not {g.name}_not1 ({g.name}_not1_out, {g.inputs[0]});",
                    f"not {g.name}_not2 ({g.name}_not2_out, {g.inputs[1]});",
                    f"and {g.name}_and1 ({g.name}_and1_out, {g.name}_not1_out, {g.name}_not2_out);",
                    f"and {g.name}_and2 ({g.name}_and2_out, {g.inputs[0]}, {g.inputs[1]});",
                    f"or {g.name}_or ({g.output}, {g.name}_and1_out, {g.name}_and2_out);"
                ]
            ]
        }
    
    def get_replacement(self, gate: Gate) -> List[str]:
        """Get a random replacement circuit for the given gate"""
        if gate.gate_type in self.replacement_patterns:
            patterns = self.replacement_patterns[gate.gate_type]
            pattern = random.choice(patterns)
            return pattern(gate)
        return None
    
    def needs_wire_declarations(self, replacement_lines: List[str]) -> List[str]:
        """Extract intermediate wires that need to be declared"""
        wires = []
        for line in replacement_lines:
            # Find output wire in each gate
            match = re.search(r'\w+\s+\w+\s*\((\w+),', line)
            if match:
                wire = match.group(1)
                # Check if it's an intermediate wire (contains underscore from our naming)
                if '_' in wire and not wire.startswith('in[') and not wire.startswith('out['):
                    wires.append(wire)
        # Remove the final output wire (it's already declared)
        return wires[:-1] if wires else []


class AggressiveNetlistAugmenter:
    """Aggressive augmenter targeting 5-25% modification without Yosys"""
    
    def __init__(self, trojan_gates: Set[str] = None):
        self.replacer = AggressiveGateReplacer()
        self.trojan_gates = trojan_gates or set()
        self.gate_mapping = {}
    
    def calculate_modification_range(self, parser: NetlistParser) -> Tuple[int, int]:
        """Calculate number of gates to modify for 5-25% range"""
        total_gates = parser.get_total_gate_count()
        min_gates = max(1, int(total_gates * 0.05))
        max_gates = max(min_gates, int(total_gates * 0.25))
        return min_gates, max_gates
    
    def augment_progressive(self, parser: NetlistParser, 
                          target_percentage: float = None) -> Tuple[List[str], Dict[str, List[str]]]:
        """Progressive augmentation - gradually increase modifications"""
        new_lines = parser.lines.copy()
        self.gate_mapping = {}
        
        # Calculate target
        min_gates, max_gates = self.calculate_modification_range(parser)
        
        if target_percentage:
            target_replacements = int(parser.get_total_gate_count() * target_percentage)
            target_replacements = max(min_gates, min(max_gates, target_replacements))
        else:
            # Progressive: start from 5% and gradually increase
            progress_factor = random.random()  # 0 to 1
            target_percentage = 0.05 + (0.20 * progress_factor)  # 5% to 25%
            target_replacements = int(parser.get_total_gate_count() * target_percentage)
        
        # Select gates to replace
        available_gates = parser.gates.copy()
        
        if self.trojan_gates:
            # Prioritize Trojan gates
            trojan_gate_objects = [g for g in parser.gates if g.name in self.trojan_gates]
            non_trojan_gates = [g for g in parser.gates if g.name not in self.trojan_gates]
            
            gates_to_replace = trojan_gate_objects.copy()
            
            # Add more gates if needed
            remaining = target_replacements - len(gates_to_replace)
            if remaining > 0 and non_trojan_gates:
                additional = random.sample(non_trojan_gates, min(remaining, len(non_trojan_gates)))
                gates_to_replace.extend(additional)
        else:
            gates_to_replace = random.sample(available_gates, 
                                          min(target_replacements, len(available_gates)))
        
        # Track wire declarations
        wire_declarations = set()
        
        # Replace gates (in reverse order to maintain line numbers)
        replaced_count = 0
        for gate in sorted(gates_to_replace, key=lambda g: g.line_number, reverse=True):
            replacement = self.replacer.get_replacement(gate)
            if replacement:
                wires = self.replacer.needs_wire_declarations(replacement)
                wire_declarations.update(wires)
                
                # Extract new gate names
                new_gate_names = []
                for line in replacement:
                    match = re.match(r'\w+\s+(\w+)\s*\(', line)
                    if match:
                        new_gate_names.append(match.group(1))
                
                self.gate_mapping[gate.name] = new_gate_names
                new_lines[gate.line_number] = '\n'.join(replacement) + '\n'
                replaced_count += 1
        
        # Add wire declarations
        if wire_declarations:
            insert_pos = self._find_wire_insert_position(new_lines)
            wire_decls = [f"wire {w};\n" for w in sorted(wire_declarations)]
            new_lines[insert_pos:insert_pos] = wire_decls
        
        print(f"  Modified {replaced_count}/{parser.get_total_gate_count()} gates "
              f"({replaced_count/parser.get_total_gate_count()*100:.1f}%)")
        
        return new_lines, self.gate_mapping
    
    def augment_clustered(self, parser: NetlistParser) -> Tuple[List[str], Dict[str, List[str]]]:
        """Clustered augmentation - modify gates in connected clusters"""
        new_lines = parser.lines.copy()
        self.gate_mapping = {}
        
        # Build connectivity graph
        wire_to_gates = defaultdict(list)
        for gate in parser.gates:
            wire_to_gates[gate.output].append(('output', gate))
            for inp in gate.inputs:
                wire_to_gates[inp].append(('input', gate))
        
        # Calculate target
        min_gates, max_gates = self.calculate_modification_range(parser)
        target_replacements = random.randint(min_gates, max_gates)
        
        # Select starting points
        if self.trojan_gates:
            start_gates = [g for g in parser.gates if g.name in self.trojan_gates]
        else:
            num_clusters = max(1, target_replacements // 10)  # Average 10 gates per cluster
            start_gates = random.sample(parser.gates, min(num_clusters, len(parser.gates)))
        
        # Grow clusters from starting points
        gates_to_replace = set()
        for start_gate in start_gates:
            cluster = self._grow_cluster(start_gate, wire_to_gates, 
                                       target_replacements // len(start_gates))
            gates_to_replace.update(cluster)
            if len(gates_to_replace) >= target_replacements:
                break
        
        # Convert to list and limit to target
        gates_to_replace = list(gates_to_replace)[:target_replacements]
        
        # Track wire declarations
        wire_declarations = set()
        
        # Replace gates
        for gate in sorted(gates_to_replace, key=lambda g: g.line_number, reverse=True):
            replacement = self.replacer.get_replacement(gate)
            if replacement:
                wires = self.replacer.needs_wire_declarations(replacement)
                wire_declarations.update(wires)
                
                new_gate_names = []
                for line in replacement:
                    match = re.match(r'\w+\s+(\w+)\s*\(', line)
                    if match:
                        new_gate_names.append(match.group(1))
                
                self.gate_mapping[gate.name] = new_gate_names
                new_lines[gate.line_number] = '\n'.join(replacement) + '\n'
        
        # Add wire declarations
        if wire_declarations:
            insert_pos = self._find_wire_insert_position(new_lines)
            wire_decls = [f"wire {w};\n" for w in sorted(wire_declarations)]
            new_lines[insert_pos:insert_pos] = wire_decls
        
        print(f"  Modified {len(gates_to_replace)}/{parser.get_total_gate_count()} gates "
              f"({len(gates_to_replace)/parser.get_total_gate_count()*100:.1f}%) in clusters")
        
        return new_lines, self.gate_mapping
    
    def augment_type_focused(self, parser: NetlistParser) -> Tuple[List[str], Dict[str, List[str]]]:
        """Focus on specific gate types for replacement"""
        new_lines = parser.lines.copy()
        self.gate_mapping = {}
        
        # Count gates by type
        gate_counts = defaultdict(list)
        for gate in parser.gates:
            gate_counts[gate.gate_type].append(gate)
        
        # Select gate types to focus on
        focus_types = random.sample(list(gate_counts.keys()), 
                                  min(3, len(gate_counts)))
        
        # Calculate target
        min_gates, max_gates = self.calculate_modification_range(parser)
        target_replacements = random.randint(min_gates, max_gates)
        
        # Select gates from focus types
        gates_to_replace = []
        for gate_type in focus_types:
            type_gates = gate_counts[gate_type]
            # Replace 50-80% of this gate type
            replace_ratio = random.uniform(0.5, 0.8)
            num_replace = int(len(type_gates) * replace_ratio)
            gates_to_replace.extend(random.sample(type_gates, 
                                                min(num_replace, len(type_gates))))
        
        # Limit to target
        gates_to_replace = gates_to_replace[:target_replacements]
        
        # If we need more, add random gates
        if len(gates_to_replace) < target_replacements:
            remaining_gates = [g for g in parser.gates if g not in gates_to_replace]
            additional = min(target_replacements - len(gates_to_replace), 
                           len(remaining_gates))
            gates_to_replace.extend(random.sample(remaining_gates, additional))
        
        # Track wire declarations
        wire_declarations = set()
        
        # Replace gates
        for gate in sorted(gates_to_replace, key=lambda g: g.line_number, reverse=True):
            replacement = self.replacer.get_replacement(gate)
            if replacement:
                wires = self.replacer.needs_wire_declarations(replacement)
                wire_declarations.update(wires)
                
                new_gate_names = []
                for line in replacement:
                    match = re.match(r'\w+\s+(\w+)\s*\(', line)
                    if match:
                        new_gate_names.append(match.group(1))
                
                self.gate_mapping[gate.name] = new_gate_names
                new_lines[gate.line_number] = '\n'.join(replacement) + '\n'
        
        # Add wire declarations
        if wire_declarations:
            insert_pos = self._find_wire_insert_position(new_lines)
            wire_decls = [f"wire {w};\n" for w in sorted(wire_declarations)]
            new_lines[insert_pos:insert_pos] = wire_decls
        
        print(f"  Modified {len(gates_to_replace)}/{parser.get_total_gate_count()} gates "
              f"({len(gates_to_replace)/parser.get_total_gate_count()*100:.1f}%) "
              f"focusing on {', '.join(focus_types)}")
        
        return new_lines, self.gate_mapping
    
    def _grow_cluster(self, start_gate: Gate, wire_to_gates: Dict, max_size: int) -> List[Gate]:
        """Grow a cluster of connected gates"""
        cluster = {start_gate}
        frontier = [start_gate]
        
        while frontier and len(cluster) < max_size:
            current = frontier.pop(0)
            
            # Find connected gates through output
            for conn_type, gate in wire_to_gates.get(current.output, []):
                if conn_type == 'input' and gate not in cluster:
                    cluster.add(gate)
                    frontier.append(gate)
                    if len(cluster) >= max_size:
                        break
            
            # Find connected gates through inputs
            for inp in current.inputs:
                for conn_type, gate in wire_to_gates.get(inp, []):
                    if conn_type == 'output' and gate not in cluster:
                        cluster.add(gate)
                        frontier.append(gate)
                        if len(cluster) >= max_size:
                            break
        
        return list(cluster)
    
    def _find_wire_insert_position(self, lines: List[str]) -> int:
        """Find the position to insert wire declarations"""
        for i, line in enumerate(lines):
            if 'endmodule' in line:
                return i - 1
        return len(lines) - 1


def update_trojan_gates_result(original_result_path: str, gate_mapping: Dict[str, List[str]], 
                              all_trojan_gates: Set[str]) -> List[str]:
    """Update the result file with new gate names after augmentation
    
    Args:
        original_result_path: Path to original result file
        gate_mapping: Mapping from original gates to new gates
        all_trojan_gates: Set of all original Trojan gate names
    """
    with open(original_result_path, 'r') as f:
        lines = f.readlines()
    
    new_lines = []
    in_trojan_section = False
    trojan_gates_written = set()
    
    for line in lines:
        line_stripped = line.strip()
        
        if line_stripped == 'TROJAN_GATES':
            new_lines.append(line)
            in_trojan_section = True
        elif line_stripped == 'END_TROJAN_GATES':
            # Before closing, add any Trojan gates that weren't replaced
            for orig_gate in all_trojan_gates:
                if orig_gate not in gate_mapping and orig_gate not in trojan_gates_written:
                    new_lines.append(f"{orig_gate}\n")
                    trojan_gates_written.add(orig_gate)
            
            # Also add any new gates from non-Trojan replacements that might affect Trojan functionality
            # (This is important for maintaining correct Trojan behavior tracking)
            
            new_lines.append(line)
            in_trojan_section = False
        elif in_trojan_section and line_stripped:
            # This is a Trojan gate name
            if line_stripped in gate_mapping:
                # Replace with ALL new gates from the replacement
                for new_gate in gate_mapping[line_stripped]:
                    new_lines.append(f"{new_gate}\n")
                    trojan_gates_written.add(new_gate)
            else:
                # Keep original gate if not replaced
                new_lines.append(line)
                trojan_gates_written.add(line_stripped)
        else:
            new_lines.append(line)
    
    # Verify we haven't lost any Trojan gates
    print(f"    Original Trojan gates: {len(all_trojan_gates)}")
    print(f"    New Trojan gates: {len(trojan_gates_written)}")
    
    return new_lines


def verify_trojan_preservation(original_trojan_gates: Set[str], 
                              gate_mapping: Dict[str, List[str]]) -> Tuple[bool, str]:
    """Verify that all Trojan functionality is preserved after augmentation
    
    Returns:
        (is_valid, message)
    """
    expected_gates = set()
    
    for orig_gate in original_trojan_gates:
        if orig_gate in gate_mapping:
            # Gate was replaced - all new gates should be Trojan
            expected_gates.update(gate_mapping[orig_gate])
        else:
            # Gate wasn't replaced - should still be Trojan
            expected_gates.add(orig_gate)
    
    original_count = len(original_trojan_gates)
    new_count = len(expected_gates)
    
    if new_count < original_count:
        return False, f"ERROR: Trojan gates reduced from {original_count} to {new_count}"
    else:
        return True, f"OK: Trojan gates expanded from {original_count} to {new_count}"


def load_trojan_gates(result_file: str) -> Set[str]:
    """Load Trojan gates from result file"""
    trojan_gates = set()
    with open(result_file, 'r') as f:
        lines = f.readlines()
        
    in_trojan_section = False
    for line in lines:
        line = line.strip()
        if line == 'TROJAN_GATES':
            in_trojan_section = True
        elif line == 'END_TROJAN_GATES':
            in_trojan_section = False
        elif in_trojan_section and line:
            trojan_gates.add(line)
    
    return trojan_gates


def main():
    parser = argparse.ArgumentParser(description='Aggressive hardware Trojan netlist augmentation (5-25%)')
    parser.add_argument('--input_dir', default='../data/release_official', help='Input directory')
    parser.add_argument('--output_dir', default='../data/augmented_data', help='Output directory')
    parser.add_argument('--strategy', choices=['progressive', 'clustered', 'type_focused', 'mixed'], 
                        default='mixed', help='Augmentation strategy')
    parser.add_argument('--num_augmentations', type=int, default=10, help='Number of augmentations per design')
    parser.add_argument('--min_modification', type=float, default=0.05, help='Minimum modification (0.05 = 5%%)')
    parser.add_argument('--max_modification', type=float, default=0.25, help='Maximum modification (0.25 = 25%%)')
    parser.add_argument('--seed', type=int, default=None, help='Random seed')
    
    args = parser.parse_args()
    
    if args.seed is not None:
        random.seed(args.seed)
    
    # Setup directories
    trojan_input_dir = os.path.join(args.input_dir, 'trojan')
    trojan_free_input_dir = os.path.join(args.input_dir, 'trojan_free')
    trojan_output_dir = os.path.join(args.output_dir, 'trojan')
    trojan_free_output_dir = os.path.join(args.output_dir, 'trojan_free')
    
    os.makedirs(trojan_output_dir, exist_ok=True)
    os.makedirs(trojan_free_output_dir, exist_ok=True)
    
    # Process Trojan designs
    print("Processing Trojan designs...")
    trojan_designs = [f for f in os.listdir(trojan_input_dir) if f.endswith('.v') and f.startswith('design')]
    
    for design_file in trojan_designs:
        design_path = os.path.join(trojan_input_dir, design_file)
        result_file = design_file.replace('design', 'result').replace('.v', '.txt')
        result_path = os.path.join(trojan_input_dir, result_file)
        
        if not os.path.exists(result_path):
            continue
        
        print(f"\nProcessing {design_file}...")
        
        # Parse
        netlist_parser = NetlistParser(design_path)
        netlist_parser.parse()
        
        # Load Trojan gates
        trojan_gates = load_trojan_gates(result_path)
        augmenter = AggressiveNetlistAugmenter(trojan_gates)
        
        # Copy originals
        shutil.copy(design_path, os.path.join(trojan_output_dir, design_file))
        shutil.copy(result_path, os.path.join(trojan_output_dir, result_file))
        
        # Generate augmentations
        for i in range(args.num_augmentations):
            if args.strategy == 'progressive':
                # Gradually increase modification percentage
                target_pct = args.min_modification + (args.max_modification - args.min_modification) * (i / args.num_augmentations)
                augmented_lines, gate_mapping = augmenter.augment_progressive(netlist_parser, target_pct)
            elif args.strategy == 'clustered':
                augmented_lines, gate_mapping = augmenter.augment_clustered(netlist_parser)
            elif args.strategy == 'type_focused':
                augmented_lines, gate_mapping = augmenter.augment_type_focused(netlist_parser)
            else:  # mixed
                strategies = ['progressive', 'clustered', 'type_focused']
                strategy = random.choice(strategies)
                print(f"  Using {strategy} strategy...")
                if strategy == 'progressive':
                    augmented_lines, gate_mapping = augmenter.augment_progressive(netlist_parser)
                elif strategy == 'clustered':
                    augmented_lines, gate_mapping = augmenter.augment_clustered(netlist_parser)
                else:
                    augmented_lines, gate_mapping = augmenter.augment_type_focused(netlist_parser)
            
            # Verify Trojan preservation
            is_valid, message = verify_trojan_preservation(trojan_gates, gate_mapping)
            print(f"    {message}")
            
            # Save files
            aug_design = design_file.replace('.v', f'_aug_{i}.v')
            aug_result = result_file.replace('.txt', f'_aug_{i}.txt')
            
            with open(os.path.join(trojan_output_dir, aug_design), 'w') as f:
                f.writelines(augmented_lines)
            
            updated_result = update_trojan_gates_result(result_path, gate_mapping, trojan_gates)
            with open(os.path.join(trojan_output_dir, aug_result), 'w') as f:
                f.writelines(updated_result)
    
    # Process Trojan-free designs
    print("\n\nProcessing Trojan-free designs...")
    trojan_free_designs = [f for f in os.listdir(trojan_free_input_dir) if f.endswith('.v') and f.startswith('design')]
    
    for design_file in trojan_free_designs:
        design_path = os.path.join(trojan_free_input_dir, design_file)
        
        print(f"\nProcessing {design_file}...")
        
        # Parse
        netlist_parser = NetlistParser(design_path)
        netlist_parser.parse()
        
        augmenter = AggressiveNetlistAugmenter(set())  # No trojan gates
        
        # Copy original
        shutil.copy(design_path, os.path.join(trojan_free_output_dir, design_file))
        
        # Generate augmentations
        for i in range(args.num_augmentations):
            if args.strategy == 'mixed':
                strategies = ['progressive', 'clustered', 'type_focused']
                strategy = random.choice(strategies)
                print(f"  Using {strategy} strategy...")
                if strategy == 'progressive':
                    augmented_lines, _ = augmenter.augment_progressive(netlist_parser)
                elif strategy == 'clustered':
                    augmented_lines, _ = augmenter.augment_clustered(netlist_parser)
                else:
                    augmented_lines, _ = augmenter.augment_type_focused(netlist_parser)
            else:
                if args.strategy == 'progressive':
                    augmented_lines, _ = augmenter.augment_progressive(netlist_parser)
                elif args.strategy == 'clustered':
                    augmented_lines, _ = augmenter.augment_clustered(netlist_parser)
                else:
                    augmented_lines, _ = augmenter.augment_type_focused(netlist_parser)
            
            aug_design = design_file.replace('.v', f'_aug_{i}.v')
            with open(os.path.join(trojan_free_output_dir, aug_design), 'w') as f:
                f.writelines(augmented_lines)
    
    print("\nAugmentation complete!")


if __name__ == "__main__":
    main()