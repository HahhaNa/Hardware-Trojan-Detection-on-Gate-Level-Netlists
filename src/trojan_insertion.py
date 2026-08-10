#!/usr/bin/env python3
"""
Updated Trojan Insertion Script
Inserts trojans from TrojanDef into clean circuits from self_data/trojan_free
Outputs to self_data/trojan with proper naming convention
"""

import os
import re
import sys
from pathlib import Path
from collections import defaultdict
import random
import shutil


class VerilogParser:
    def __init__(self):
        self.module_name = None
        self.inputs = []
        self.outputs = []
        self.wires = []
        self.gates = []
        self.wire_connections = defaultdict(list)
        
    def parse_file(self, filepath):
        """Parse a Verilog file and extract components"""
        with open(filepath, 'r') as f:
            content = f.read()
        
        # Remove comments
        content = re.sub(r'//.*', '', content)
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        
        # Extract module name
        module_match = re.search(r'module\s+(\w+)', content)
        if module_match:
            self.module_name = module_match.group(1)
        
        # Extract inputs
        input_matches = re.findall(r'input\s+(?:wire\s+)?(?:\[(\d+):(\d+)\]\s+)?(\w+)', content)
        for match in input_matches:
            if match[0] and match[1]:  # Bus signal
                high = int(match[0])
                low = int(match[1])
                for i in range(low, high + 1):
                    self.inputs.append(f"{match[2]}[{i}]")
            else:  # Single signal
                self.inputs.append(match[2])
        
        # Extract outputs
        output_matches = re.findall(r'output\s+(?:wire\s+|reg\s+)?(?:\[(\d+):(\d+)\]\s+)?(\w+)', content)
        for match in output_matches:
            if match[0] and match[1]:  # Bus signal
                high = int(match[0])
                low = int(match[1])
                for i in range(low, high + 1):
                    self.outputs.append(f"{match[2]}[{i}]")
            else:  # Single signal
                self.outputs.append(match[2])
        
        # Extract wires
        wire_matches = re.findall(r'wire\s+(?:\[(\d+):(\d+)\]\s+)?(\w+)', content)
        for match in wire_matches:
            if match[0] and match[1]:  # Bus signal
                high = int(match[0])
                low = int(match[1])
                for i in range(low, high + 1):
                    self.wires.append(f"{match[2]}[{i}]")
            else:  # Single signal
                self.wires.append(match[2])
        
        # Extract gates
        gate_pattern = r'(and|or|nand|nor|not|buf|xor|xnor|dff)\s+(\w+)\s*\((.*?)\);'
        gate_matches = re.findall(gate_pattern, content, re.DOTALL)
        
        for match in gate_matches:
            gate_type = match[0]
            gate_name = match[1]
            connections = match[2]
            
            gate_info = {
                'type': gate_type,
                'name': gate_name,
                'connections': connections.strip()
            }
            
            self.gates.append(gate_info)
            
            # Parse connections to track wire usage
            if gate_type == 'dff':
                # Parse named connections for DFF
                conn_dict = self._parse_dff_connections(connections)
                if 'Q' in conn_dict:
                    self.wire_connections[conn_dict['Q']].append(gate_name)
            else:
                # Parse positional connections for other gates
                conn_list = [c.strip() for c in connections.split(',')]
                if conn_list:
                    output_wire = conn_list[0]
                    self.wire_connections[output_wire].append(gate_name)
        
        return self
    
    def _parse_dff_connections(self, connections):
        """Parse DFF named connections"""
        conn_dict = {}
        # Match named connections like .RN(rst_n)
        matches = re.findall(r'\.(\w+)\s*\(\s*([^)]+)\s*\)', connections)
        for match in matches:
            conn_dict[match[0]] = match[1].strip()
        return conn_dict


class TrojanInserter:
    def __init__(self):
        """Initialize the Trojan inserter with fixed paths"""
        self.trojan_def_dir = Path("../data/TrojanDef")
        self.trojan_free_dir = Path("../data/self_data/trojan_free")
        self.output_dir = Path("../data/self_data/trojan")
        self.output_dir.mkdir(exist_ok=True, parents=True)
        
    def get_clean_base_name(self, filename):
        """Extract clean base name from filename"""
        # Remove .v extension
        name = filename.stem
        # Remove design_ prefix if present
        if name.startswith('design_'):
            name = name[7:]  # Remove 'design_'
        # Remove _converted suffix if present
        elif name.endswith('_converted'):
            name = name[:-10]  # Remove '_converted'
        return name
    
    def get_trojan_number(self, filename):
        """Extract trojan number from filename"""
        match = re.search(r'trojan(\d+)', filename.stem)
        if match:
            return match.group(1)
        return None
    
    def rename_clean_files(self):
        """Rename clean files in trojan_free directory to follow design_ convention"""
        print("Renaming clean files in trojan_free directory...")
        clean_files = list(self.trojan_free_dir.glob("*.v"))
        
        renamed_count = 0
        for clean_file in clean_files:
            if not clean_file.name.startswith('design_'):
                base_name = self.get_clean_base_name(clean_file)
                new_name = f"design_{base_name}.v"
                new_path = clean_file.parent / new_name
                
                # Only rename if target doesn't exist
                if not new_path.exists():
                    clean_file.rename(new_path)
                    print(f"  Renamed: {clean_file.name} -> {new_name}")
                    renamed_count += 1
                else:
                    print(f"  Skipped: {new_name} already exists")
        
        print(f"Renamed {renamed_count} files")
        return renamed_count
    
    def get_available_files(self):
        """Get lists of clean and trojan files"""
        # Get trojan files from TrojanDef
        trojan_files = list(self.trojan_def_dir.glob("*.v"))
        trojan_files = [f for f in trojan_files if f.is_file()]
        
        # Get clean files from trojan_free (any .v file)
        clean_files = list(self.trojan_free_dir.glob("*.v"))
        clean_files = [f for f in clean_files if f.is_file()]
        
        return clean_files, trojan_files
    
    def insert_trojan(self, clean_file, trojan_file):
        """Insert a trojan into a clean netlist"""
        # Parse both files
        clean_parser = VerilogParser().parse_file(clean_file)
        trojan_parser = VerilogParser().parse_file(trojan_file)
        
        # Get base names
        clean_base = self.get_clean_base_name(clean_file)
        trojan_num = self.get_trojan_number(trojan_file)
        
        # Generate output filenames - no extra design_ prefix
        output_base = f"design_{clean_base}_tj{trojan_num}"
        output_verilog = self.output_dir / f"{output_base}.v"
        output_result = self.output_dir / f"result_{clean_base}_tj{trojan_num}.txt"
        
        # Generate unique names for trojan gates to avoid conflicts
        trojan_gate_mapping = {}
        trojan_wire_mapping = {}
        
        # Create mappings for trojan components
        for gate in trojan_parser.gates:
            new_name = f"tj_{gate['name']}"
            trojan_gate_mapping[gate['name']] = new_name
        
        # Map trojan wires (except inputs/outputs which will be connected to clean circuit)
        for wire in trojan_parser.wires:
            if wire not in trojan_parser.inputs and wire not in trojan_parser.outputs:
                new_name = f"tj_{wire}"
                trojan_wire_mapping[wire] = new_name
        
        # Select connection points
        connection_points = self._select_connection_points(clean_parser, trojan_parser)
        
        # Generate the inserted netlist
        inserted_content = self._generate_inserted_netlist(
            clean_parser, trojan_parser, trojan_gate_mapping, 
            trojan_wire_mapping, connection_points
        )
        
        # Write Verilog file
        with open(output_verilog, 'w') as f:
            f.write(inserted_content)
        
        # Write result file with all trojan gates
        with open(output_result, 'w') as f:
            f.write("TROJANED\n")
            f.write("TROJAN_GATES\n")
            # Write all trojan gates
            for original_name in sorted(trojan_gate_mapping.keys()):
                f.write(f"{trojan_gate_mapping[original_name]}\n")
            # Also write XOR gates used for payload
            for trojan_out in trojan_parser.outputs:
                if trojan_out in connection_points:
                    f.write(f"tj_xor_{trojan_out}\n")
            f.write("END_TROJAN_GATES\n")
        
        print(f"Created {output_verilog.name} with trojan{trojan_num} inserted into {clean_base}")
        
        return output_verilog, output_result
    
    def _select_connection_points(self, clean_parser, trojan_parser):
        """Select appropriate connection points for trojan insertion"""
        connections = {}
        
        # Get available wires from clean circuit
        available_wires = (clean_parser.inputs + clean_parser.outputs + 
                          clean_parser.wires)
        
        # Remove constant values
        available_wires = [w for w in available_wires if not re.match(r"\d+'b[01]", w)]
        
        # For each trojan input, randomly select a wire from clean circuit
        for trojan_input in trojan_parser.inputs:
            if available_wires:
                connections[trojan_input] = random.choice(available_wires)
        
        # For trojan outputs, select internal wires to modify
        internal_wires = [w for w in clean_parser.wires 
                         if w not in clean_parser.inputs 
                         and w not in clean_parser.outputs]
        
        for trojan_output in trojan_parser.outputs:
            if internal_wires:
                connections[trojan_output] = random.choice(internal_wires)
            elif clean_parser.wires:
                connections[trojan_output] = random.choice(clean_parser.wires)
        
        return connections
    
    def _generate_inserted_netlist(self, clean_parser, trojan_parser, 
                                  gate_mapping, wire_mapping, connections):
        """Generate the complete inserted netlist"""
        lines = []
        
        # Module header - use generic name
        lines.append("module top (")
        
        # Inputs
        input_lines = []
        for inp in clean_parser.inputs:
            base_name = inp.split('[')[0] if '[' in inp else inp
            if base_name not in [i.split('[')[0] if '[' in i else i for i in input_lines]:
                # Check if it's a bus signal
                bus_signals = [i for i in clean_parser.inputs if i.startswith(base_name + '[')]
                if bus_signals:
                    # Extract bus width
                    indices = [int(re.search(r'\[(\d+)\]', s).group(1)) for s in bus_signals]
                    max_idx = max(indices)
                    min_idx = min(indices)
                    input_lines.append(f"input [{max_idx}:{min_idx}] {base_name}")
                else:
                    input_lines.append(f"input {base_name}")
        
        # Outputs
        output_lines = []
        for out in clean_parser.outputs:
            base_name = out.split('[')[0] if '[' in out else out
            if base_name not in [o.split('[')[0] if '[' in o else o for o in output_lines]:
                bus_signals = [o for o in clean_parser.outputs if o.startswith(base_name + '[')]
                if bus_signals:
                    indices = [int(re.search(r'\[(\d+)\]', s).group(1)) for s in bus_signals]
                    max_idx = max(indices)
                    min_idx = min(indices)
                    output_lines.append(f"output [{max_idx}:{min_idx}] {base_name}")
                else:
                    output_lines.append(f"output {base_name}")
        
        # Combine all I/O declarations
        all_io = []
        for line in input_lines:
            all_io.append(f"  {line}")
        for line in output_lines:
            all_io.append(f"  {line}")
        
        # Add commas
        for i, line in enumerate(all_io):
            if i < len(all_io) - 1:
                lines.append(line + ",")
            else:
                lines.append(line)
        
        lines.append(");")
        lines.append("")
        
        # Wire declarations - original wires
        for wire in clean_parser.wires:
            base_name = wire.split('[')[0] if '[' in wire else wire
            # Check if we already declared this base
            if not any(base_name in l for l in lines):
                bus_signals = [w for w in clean_parser.wires if w.startswith(base_name + '[')]
                if bus_signals:
                    indices = [int(re.search(r'\[(\d+)\]', s).group(1)) for s in bus_signals]
                    max_idx = max(indices)
                    min_idx = min(indices)
                    lines.append(f"wire [{max_idx}:{min_idx}] {base_name};")
                else:
                    lines.append(f"wire {base_name};")
        
        # Trojan internal wires
        for orig_wire, new_wire in wire_mapping.items():
            lines.append(f"wire {new_wire};")
        
        # Modified wire versions (if trojan modifies existing wires)
        for trojan_out in trojan_parser.outputs:
            if trojan_out in connections:
                victim_wire = connections[trojan_out]
                lines.append(f"wire {victim_wire}_original;")
                lines.append(f"wire tj_{trojan_out};")
        
        lines.append("")
        
        # Original gates (with modifications for trojan connections)
        lines.append("// Original circuit gates")
        for gate in clean_parser.gates:
            gate_line = self._format_gate(gate)
            
            # Check if output needs to be redirected
            for trojan_out in trojan_parser.outputs:
                if trojan_out in connections:
                    victim_wire = connections[trojan_out]
                    # Replace first occurrence (output) with _original version
                    if victim_wire in gate_line:
                        parts = gate_line.split('(', 1)
                        if len(parts) == 2:
                            conn_part = parts[1].rstrip(');')
                            conns = [c.strip() for c in conn_part.split(',')]
                            if conns and conns[0] == victim_wire:
                                conns[0] = f"{victim_wire}_original"
                                gate_line = f"{parts[0]}({', '.join(conns)});"
            
            lines.append(gate_line)
        
        lines.append("")
        lines.append("// Trojan gates")
        
        # Trojan gates
        for gate in trojan_parser.gates:
            # Format gate with renamed components
            gate_line = f"{gate['type']} {gate_mapping[gate['name']]} ("
            
            # Parse and update connections
            if gate['type'] == 'dff':
                # Handle DFF named connections
                gate_line += gate['connections']
                # Update wire names in connections
                for old_wire, new_wire in wire_mapping.items():
                    gate_line = re.sub(r'\b' + re.escape(old_wire) + r'\b', new_wire, gate_line)
                # Update input connections
                for trojan_signal, clean_signal in connections.items():
                    if trojan_signal in trojan_parser.inputs:
                        gate_line = re.sub(r'\b' + re.escape(trojan_signal) + r'\b', 
                                         clean_signal, gate_line)
                # Update output connections
                for trojan_signal in trojan_parser.outputs:
                    gate_line = re.sub(r'\b' + re.escape(trojan_signal) + r'\b', 
                                     f"tj_{trojan_signal}", gate_line)
            else:
                # Handle positional connections
                conns = [c.strip() for c in gate['connections'].split(',')]
                new_conns = []
                
                for i, conn in enumerate(conns):
                    # First connection is output for standard gates
                    if i == 0 and conn in trojan_parser.outputs:
                        new_conns.append(f"tj_{conn}")
                    elif conn in wire_mapping:
                        new_conns.append(wire_mapping[conn])
                    elif conn in connections and conn in trojan_parser.inputs:
                        new_conns.append(connections[conn])
                    else:
                        new_conns.append(conn)
                
                gate_line += f"{', '.join(new_conns)}"
            
            gate_line += ");"
            lines.append(gate_line)
        
        # Add XOR gates to combine trojan outputs with victim wires
        lines.append("")
        lines.append("// Trojan payload connections")
        
        for trojan_out in trojan_parser.outputs:
            if trojan_out in connections:
                victim_wire = connections[trojan_out]
                xor_name = f"tj_xor_{trojan_out}"
                lines.append(f"xor {xor_name} ({victim_wire}, {victim_wire}_original, tj_{trojan_out});")
                # Add XOR gate to mapping for result file
                gate_mapping[f"xor_{trojan_out}"] = xor_name
        
        lines.append("")
        lines.append("endmodule")
        
        return '\n'.join(lines)
    
    def _format_gate(self, gate):
        """Format a gate instantiation"""
        return f"{gate['type']} {gate['name']} ({gate['connections']});"
    
    def insert_all_combinations(self):
        """Insert all trojan-clean combinations"""
        # First, rename clean files if needed
        self.rename_clean_files()
        
        # Get available files
        clean_files, trojan_files = self.get_available_files()
        
        print(f"\nFound {len(clean_files)} clean files and {len(trojan_files)} trojan files")
        
        if not clean_files:
            print("No clean files found! Make sure files are in ../data/self_data/trojan_free/")
            return
        
        if not trojan_files:
            print("No trojan files found! Make sure files are in ../data/TrojanDef/")
            return
        
        total_combinations = len(clean_files) * len(trojan_files)
        print(f"Will create {total_combinations} trojan-inserted designs")
        
        created_count = 0
        for trojan_file in trojan_files:
            trojan_num = self.get_trojan_number(trojan_file)
            print(f"\nProcessing trojan{trojan_num} from {trojan_file.name}")
            
            for clean_file in clean_files:
                clean_base = self.get_clean_base_name(clean_file)
                
                # Check if output already exists
                output_name = f"design_{clean_base}_tj{trojan_num}.v"
                if (self.output_dir / output_name).exists():
                    print(f"  Skipping {clean_base} + trojan{trojan_num} - already exists")
                    continue
                
                try:
                    output_v, output_txt = self.insert_trojan(clean_file, trojan_file)
                    created_count += 1
                except Exception as e:
                    print(f"  Error inserting trojan{trojan_num} into {clean_file.name}: {e}")
                    import traceback
                    traceback.print_exc()
                    continue
        
        print(f"\nCompleted! Created {created_count} trojan-inserted designs")
        print(f"Output directory: {self.output_dir}")
        
        # List some example outputs
        output_files = list(self.output_dir.glob("design_*.v"))
        if output_files:
            print("\nExample outputs:")
            for f in sorted(output_files)[:5]:
                result_file = f.with_name(f.name.replace('design_', 'result_').replace('.v', '.txt'))
                if result_file.exists():
                    print(f"  {f.name} + {result_file.name}")
                else:
                    print(f"  {f.name}")
            if len(output_files) > 5:
                print(f"  ... and {len(output_files) - 5} more")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Insert Trojans into clean netlists')
    parser.add_argument('--skip-rename', action='store_true',
                       help='Skip renaming clean files')
    parser.add_argument('--force', action='store_true',
                       help='Force overwrite existing outputs')
    
    args = parser.parse_args()
    
    # Create inserter and run
    inserter = TrojanInserter()
    
    # Verify directories exist
    if not inserter.trojan_def_dir.exists():
        print(f"Error: Trojan definition directory not found: {inserter.trojan_def_dir}")
        print("Please make sure ../data/TrojanDef/ exists and contains trojan .v files")
        return
    
    if not inserter.trojan_free_dir.exists():
        print(f"Error: Clean circuits directory not found: {inserter.trojan_free_dir}")
        print("Please make sure ../data/self_data/trojan_free/ exists and contains clean .v files")
        return
    
    # Run insertion
    inserter.insert_all_combinations()


if __name__ == "__main__":
    main()