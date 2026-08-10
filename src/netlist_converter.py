#!/usr/bin/env python3
"""
Netlist Format Converter for ICCAD Hardware Trojan Detection Contest
Uses Yosys for synthesis then converts to the required gate-level format
"""

import re
import sys
import os
import subprocess
import tempfile
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional
import argparse
import difflib

class NetlistConverter:
    def __init__(self, use_yosys=True, trojan_detection=False):
        self.use_yosys = use_yosys
        self.trojan_detection = trojan_detection
        self.trojan_gates = set()  # Set of gate instances that are trojans
        self.use_yosys = use_yosys
        # Primitive gates mapping
        self.primitive_gates = {
            'and', 'or', 'nand', 'nor', 'not', 'buf', 'xor', 'xnor'
        }
        
        # Yosys gate mapping to primitives
        self.yosys_to_primitive = {
            # Basic Yosys gates
            '$_AND_': 'and', '$_OR_': 'or', '$_NAND_': 'nand', '$_NOR_': 'nor',
            '$_NOT_': 'not', '$_BUF_': 'buf', '$_XOR_': 'xor', '$_XNOR_': 'xnor',
            '$_INV_': 'not',  # Alternative notation for NOT
            # Complex gates that need to be decomposed
            '$_AOI3_': 'aoi3', '$_OAI3_': 'oai3', '$_AOI4_': 'aoi4', '$_OAI4_': 'oai4',
            '$_ANDNOT_': 'andnot', '$_ORNOT_': 'ornot',
            # MUX
            '$_MUX_': 'mux',
            # Latches
            '$_DLATCH_P_': 'dlatch', '$_DLATCH_N_': 'dlatch',
            '$_DLATCHSR_PPP_': 'dlatch', '$_DLATCHSR_PPN_': 'dlatch',
            '$_DLATCHSR_PNP_': 'dlatch', '$_DLATCHSR_PNN_': 'dlatch',
            '$_DLATCHSR_NPP_': 'dlatch', '$_DLATCHSR_NPN_': 'dlatch',
            '$_DLATCHSR_NNP_': 'dlatch', '$_DLATCHSR_NNN_': 'dlatch',
            # DFF variations
            '$_DFF_P_': 'dff', '$_DFF_N_': 'dff', 
            '$_DFF_PP0_': 'dff', '$_DFF_PP1_': 'dff', '$_DFF_PN0_': 'dff', '$_DFF_PN1_': 'dff',
            '$_DFF_NP0_': 'dff', '$_DFF_NP1_': 'dff', '$_DFF_NN0_': 'dff', '$_DFF_NN1_': 'dff',
            '$_DFFE_PP_': 'dff', '$_DFFE_PN_': 'dff', '$_DFFE_NP_': 'dff', '$_DFFE_NN_': 'dff',
            '$_DFFE_PP0P_': 'dff', '$_DFFE_PP0N_': 'dff', '$_DFFE_PP1P_': 'dff', '$_DFFE_PP1N_': 'dff',
            '$_DFFE_PN0P_': 'dff', '$_DFFE_PN0N_': 'dff', '$_DFFE_PN1P_': 'dff', '$_DFFE_PN1N_': 'dff',
            '$_DFFE_NP0P_': 'dff', '$_DFFE_NP0N_': 'dff', '$_DFFE_NP1P_': 'dff', '$_DFFE_NP1N_': 'dff',
            '$_DFFE_NN0P_': 'dff', '$_DFFE_NN0N_': 'dff', '$_DFFE_NN1P_': 'dff', '$_DFFE_NN1N_': 'dff',
            '$_DFFSR_PPP_': 'dff', '$_DFFSR_PPN_': 'dff', '$_DFFSR_PNP_': 'dff', '$_DFFSR_PNN_': 'dff',
            '$_DFFSR_NPP_': 'dff', '$_DFFSR_NPN_': 'dff', '$_DFFSR_NNP_': 'dff', '$_DFFSR_NNN_': 'dff',
            # Synchronous DFF variations
            '$_SDFF_PP0_': 'dff', '$_SDFF_PP1_': 'dff', '$_SDFF_PN0_': 'dff', '$_SDFF_PN1_': 'dff',
            '$_SDFF_NP0_': 'dff', '$_SDFF_NP1_': 'dff', '$_SDFF_NN0_': 'dff', '$_SDFF_NN1_': 'dff',
            '$_SDFFE_PP0P_': 'dff', '$_SDFFE_PP0N_': 'dff', '$_SDFFE_PP1P_': 'dff', '$_SDFFE_PP1N_': 'dff',
            '$_SDFFE_PN0P_': 'dff', '$_SDFFE_PN0N_': 'dff', '$_SDFFE_PN1P_': 'dff', '$_SDFFE_PN1N_': 'dff',
            '$_SDFFE_NP0P_': 'dff', '$_SDFFE_NP0N_': 'dff', '$_SDFFE_NP1P_': 'dff', '$_SDFFE_NP1N_': 'dff',
            '$_SDFFE_NN0P_': 'dff', '$_SDFFE_NN0N_': 'dff', '$_SDFFE_NN1P_': 'dff', '$_SDFFE_NN1N_': 'dff',
            '$_SDFFCE_PP0P_': 'dff', '$_SDFFCE_PP0N_': 'dff', '$_SDFFCE_PP1P_': 'dff', '$_SDFFCE_PP1N_': 'dff',
            '$_SDFFCE_PN0P_': 'dff', '$_SDFFCE_PN0N_': 'dff', '$_SDFFCE_PN1P_': 'dff', '$_SDFFCE_PN1N_': 'dff',
            '$_SDFFCE_NP0P_': 'dff', '$_SDFFCE_NP0N_': 'dff', '$_SDFFCE_NP1P_': 'dff', '$_SDFFCE_NP1N_': 'dff',
            '$_SDFFCE_NN0P_': 'dff', '$_SDFFCE_NN0N_': 'dff', '$_SDFFCE_NN1P_': 'dff', '$_SDFFCE_NN1N_': 'dff',

            '$_ALDFF_PP_': 'dff', '$_ALDFF_PN_': 'dff', '$_ALDFF_NP_': 'dff', '$_ALDFF_NN_': 'dff',
            '$_ALDFFE_PPP_': 'dff', '$_ALDFFE_PPN_': 'dff', '$_ALDFFE_PNP_': 'dff', '$_ALDFFE_PNN_': 'dff',
            '$_ALDFFE_NPP_': 'dff', '$_ALDFFE_NPN_': 'dff', '$_ALDFFE_NNP_': 'dff', '$_ALDFFE_NNN_': 'dff',

        }
        
        self.wires = set()
        self.inputs = []
        self.outputs = []
        self.gate_instances = []
        self.gate_counter = 0
        self.wire_counter = 0
        self.implicit_wires = set()

    def is_gate_level_netlist(self, verilog_file: str) -> bool:
        tech_cells = ['AO', 'NAND', 'INV', 'DFF', 'SDFF', 'MUX', 'OA', 'NBUFF', 'LSDNEN']
        with open(verilog_file, 'r') as f:
            for _ in range(500):
                line = f.readline()
                if any(cell in line for cell in tech_cells):
                    return True
        return False

    def parse_gate_level_netlist(self, verilog_file: str):
        tech_map = {
            'INVX0': 'not',
            'NBUFFX2': 'buf',
            'NAND2X0': 'nand',
            'NAND4X0': 'nand',
            'AO221X1': 'or',
            'OA21X1': 'or',
            'SDFFX1': 'dff',
            'LSDNENX1': 'dff',
            'DFFX1': 'dff',
        }

        with open(verilog_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('//'):
                    continue
                match = re.match(r'^(\w+)\s+(\w+)\s*\((.*)\);', line)
                if not match:
                    continue

                cell_type, inst_name, port_str = match.groups()
                gate_type = tech_map.get(cell_type, None)
                if gate_type is None:
                    continue

                port_map = {}
                for pair in port_str.split(','):
                    m = re.match(r'\.(\w+)\s*\(\s*([^\s\)]+)?\s*\)', pair.strip())
                    if m:
                        port, signal = m.groups()
                        port_map[port] = signal

                if gate_type == 'dff':
                    self.add_dff(inst_name,
                                port_map.get("D", ""),
                                port_map.get("CLK", ""),
                                port_map.get("Q", ""))
                else:
                    inputs = [v for k, v in port_map.items() if k.upper() not in ["Q", "CLK", "QN"]]
                    output = port_map.get("Q", "") or port_map.get("QN", "")
                    self.add_raw_gate(gate_type, inst_name, inputs + [output])

    
    def detect_trojan_gates(self, tjfree_file: str, tjin_file: str) -> Set[str]:
        """Compare TjFree and TjIn netlists to identify trojan gates"""
        print(f"Detecting trojan gates by comparing {tjfree_file} and {tjin_file}...")
        
        # Convert both files to gate-level netlists
        temp_free = tjfree_file + ".temp_free.v"
        temp_in = tjin_file + ".temp_in.v"
        
        # Convert TjFree
        converter_free = NetlistConverter(use_yosys=self.use_yosys, trojan_detection=False)
        converter_free.convert_file(tjfree_file, temp_free)
        
        # Convert TjIn
        converter_in = NetlistConverter(use_yosys=self.use_yosys, trojan_detection=False)
        converter_in.convert_file(tjin_file, temp_in)
        
        # Parse the converted netlists
        with open(temp_free, 'r') as f:
            free_content = f.read()
        with open(temp_in, 'r') as f:
            in_content = f.read()
            
        # Extract gate instances from both netlists
        free_gates = self.extract_gates_from_netlist(free_content)
        in_gates = self.extract_gates_from_netlist(in_content)
        
        # Find gates that exist in TjIn but not in TjFree
        trojan_gates = set()
        
        # Compare gate instances
        for gate_type, gates in in_gates.items():
            if gate_type not in free_gates:
                # All gates of this type are trojans
                trojan_gates.update(gates)
            else:
                # Check for additional gates
                free_set = set(free_gates[gate_type])
                in_set = set(gates)
                additional = in_set - free_set
                trojan_gates.update(additional)
        
        # Clean up temp files
        if os.path.exists(temp_free):
            os.unlink(temp_free)
        if os.path.exists(temp_in):
            os.unlink(temp_in)
            
        print(f"Found {len(trojan_gates)} trojan gates")
        return trojan_gates
    
    def extract_gates_from_netlist(self, content: str) -> Dict[str, List[str]]:
        """Extract gate instances from a netlist content"""
        gates = defaultdict(list)
        
        # Pattern to match gate instances
        # Format: gate_type instance_name (connections);
        gate_pattern = r'(and|or|nand|nor|not|buf|xor|xnor|dff)\s+(\w+)\s*\([^;]+\);'
        
        for match in re.finditer(gate_pattern, content):
            gate_type = match.group(1)
            instance_name = match.group(2)
            gates[gate_type].append(instance_name)
            
        return gates
        """Use Yosys to synthesize RTL to gate-level netlist"""
        try:
            # Create Yosys script
            yosys_script = f"""
# Read the design
read_verilog {input_file}

# Find the top module automatically
hierarchy -auto-top

# Elaborate design hierarchy
hierarchy -check
proc

# Convert processes to netlists
proc
opt_expr
opt_clean

# Technology mapping to simple gates
techmap
opt

# Use simpler mapping that includes all basic gates
simplemap
opt

# Map any remaining complex cells
abc -g simple

# Additional cleanup
opt_clean -purge

# Write flattened netlist
flatten
clean -purge
write_verilog -noattr -noexpr {output_file}
"""
            
            # Write script to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.ys', delete=False) as f:
                f.write(yosys_script)
                script_file = f.name
            
            # Run Yosys
            result = subprocess.run(
                ['yosys', '-s', script_file],
                capture_output=True,
                text=True
            )
            
            # Clean up script file
            os.unlink(script_file)
            
            if result.returncode != 0:
                print(f"Yosys error: {result.stderr}")
                return False
                
            return True
            
        except Exception as e:
            print(f"Error running Yosys: {str(e)}")
            return False
    
    def parse_yosys_netlist(self, content: str) -> Dict:
        """Parse Yosys output netlist"""
        # Remove comments
        content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        
        # Find module
        module_match = re.search(r'module\s+(\w+)\s*\((.*?)\);(.*?)endmodule', 
                               content, re.DOTALL)
        
        if not module_match:
            raise ValueError("No module found in Yosys output")
            
        module_name = module_match.group(1)
        ports = module_match.group(2)
        body = module_match.group(3)
        
        module_info = {
            'name': module_name,
            'inputs': [],
            'outputs': [],
            'wires': set(),
            'instances': []
        }
        
        # Parse ports from body (Yosys format)
        input_matches = re.findall(r'input\s+(?:\[(\d+):(\d+)\]\s+)?(\w+);', body)
        for msb, lsb, name in input_matches:
            if msb and lsb:
                width = int(msb) - int(lsb) + 1
                module_info['inputs'].append({
                    'name': name,
                    'width': width,
                    'range': f'[{msb}:{lsb}]'
                })
            else:
                module_info['inputs'].append({'name': name, 'width': 1})
        
        output_matches = re.findall(r'output\s+(?:\[(\d+):(\d+)\]\s+)?(\w+);', body)
        for msb, lsb, name in output_matches:
            if msb and lsb:
                width = int(msb) - int(lsb) + 1
                module_info['outputs'].append({
                    'name': name,
                    'width': width,
                    'range': f'[{msb}:{lsb}]'
                })
            else:
                module_info['outputs'].append({'name': name, 'width': 1})
        
        # Parse wires
        wire_matches = re.findall(r'wire\s+(?:\[(\d+):(\d+)\]\s+)?([^;]+);', body)
        for msb, lsb, wire_list in wire_matches:
            wires = [w.strip() for w in wire_list.split(',')]
            for wire in wires:
                if wire and not wire.startswith('\\'):  # Skip escaped names
                    module_info['wires'].add(wire)
        
        # Parse gate instances
        # Yosys format: $_GATE_ _instance_ (.A(signal), .Y(signal));
        gate_pattern = r'(\$_?\w+_?)\s+(\\\S+|\w+)\s*\((.*?)\);'
        gates = re.findall(gate_pattern, body, re.DOTALL)
        
        for gate_type, inst_name, connections in gates:
            # Clean instance name
            if inst_name.startswith('\\'):
                inst_name = inst_name[1:]
            # Normalize gate type
            if gate_type.startswith('$') and not gate_type.startswith('$_'):
                # Convert $not to $_NOT_, $and to $_AND_, etc.
                normalized = '$_' + gate_type[1:].upper() + '_'
                module_info['instances'].append({
                    'type': normalized,
                    'name': inst_name,
                    'connections': connections
                })
            else:
                module_info['instances'].append({
                    'type': gate_type,
                    'name': inst_name,
                    'connections': connections
                })
        
        # Also look for standard gates that might remain
        std_gate_pattern = r'\b(and|or|nand|nor|not|buf|xor|xnor)\s+(\w+)\s*\((.*?)\);'
        std_gates = re.findall(std_gate_pattern, body, re.DOTALL)
        
        for gate_type, inst_name, connections in std_gates:
            module_info['instances'].append({
                'type': gate_type,
                'name': inst_name,
                'connections': connections
            })
        
        return module_info
    
    def convert_yosys_gates(self, module_info: Dict) -> None:
        """Convert Yosys gates to contest primitive format"""
        # Reset counters
        self.gate_counter = 0
        self.wire_counter = 0
        
        # Process inputs/outputs
        for inp in module_info['inputs']:
            if inp['width'] > 1:
                for i in range(inp['width']):
                    self.inputs.append(f"{inp['name']}[{i}]")
            else:
                self.inputs.append(inp['name'])
        
        for out in module_info['outputs']:
            if out['width'] > 1:
                for i in range(out['width']):
                    self.outputs.append(f"{out['name']}[{i}]")
            else:
                self.outputs.append(out['name'])
        
        # Add wires
        self.wires.update(module_info['wires'])
        
        # Process each gate instance
        for inst in module_info['instances']:
            self.convert_yosys_gate_instance(inst)
    
    def convert_yosys_gate_instance(self, inst: Dict) -> None:
        """Convert a single Yosys gate to primitive format"""
        gate_type = inst['type']
        connections = self.parse_connections(inst['connections'])
        
        if gate_type in self.yosys_to_primitive:
            primitive = self.yosys_to_primitive[gate_type]
            
            if primitive == 'dff':
                self.convert_yosys_dff(gate_type, connections)
            elif primitive == 'dlatch':
                self.convert_yosys_latch_to_dff(gate_type, connections)
            elif primitive in ['not', 'buf']:
                # Unary gates: (output, input)
                output = connections.get('Y') or connections.get('Q')
                input_sig = connections.get('A') or connections.get('D')
                if output and input_sig:
                    self.add_gate(primitive, [output, input_sig])
            elif primitive in ['and', 'or', 'nand', 'nor', 'xor', 'xnor']:
                # Binary gates: (output, input1, input2)
                output = connections.get('Y')
                input_a = connections.get('A')
                input_b = connections.get('B')
                if output and input_a and input_b:
                    self.add_gate(primitive, [output, input_a, input_b])
            elif primitive == 'andnot':
                # ANDNOT: Y = A & ~B
                output = connections.get('Y')
                input_a = connections.get('A')
                input_b = connections.get('B')
                if output and input_a and input_b:
                    not_b = self.get_new_wire()
                    self.add_gate('not', [not_b, input_b])
                    self.add_gate('and', [output, input_a, not_b])
            elif primitive == 'ornot':
                # ORNOT: Y = A | ~B
                output = connections.get('Y')
                input_a = connections.get('A')
                input_b = connections.get('B')
                if output and input_a and input_b:
                    not_b = self.get_new_wire()
                    self.add_gate('not', [not_b, input_b])
                    self.add_gate('or', [output, input_a, not_b])
            elif primitive == 'aoi3':
                # AOI3: Y = ~((A & B) | C)
                output = connections.get('Y')
                input_a = connections.get('A')
                input_b = connections.get('B')
                input_c = connections.get('C')
                if output and input_a and input_b and input_c:
                    and_out = self.get_new_wire()
                    or_out = self.get_new_wire()
                    self.add_gate('and', [and_out, input_a, input_b])
                    self.add_gate('or', [or_out, and_out, input_c])
                    self.add_gate('not', [output, or_out])
            elif primitive == 'oai3':
                # OAI3: Y = ~((A | B) & C)
                output = connections.get('Y')
                input_a = connections.get('A')
                input_b = connections.get('B')
                input_c = connections.get('C')
                if output and input_a and input_b and input_c:
                    or_out = self.get_new_wire()
                    and_out = self.get_new_wire()
                    self.add_gate('or', [or_out, input_a, input_b])
                    self.add_gate('and', [and_out, or_out, input_c])
                    self.add_gate('not', [output, and_out])
            elif primitive == 'mux':
                # MUX: Y = S ? B : A
                output = connections.get('Y')
                input_a = connections.get('A')
                input_b = connections.get('B')
                sel = connections.get('S')
                if output and input_a and input_b and sel:
                    self.create_mux(output, input_a, input_b, sel)
        elif gate_type in self.primitive_gates:
            # Already a primitive gate
            self.convert_primitive_gate(inst)
        else:
            print(f"Warning: Unknown Yosys gate type '{gate_type}'")
            # Try to approximate with buffer
            if connections:
                output = connections.get('Y') or connections.get('Q') or connections.get('O')
                input_sig = connections.get('A') or connections.get('D') or connections.get('I')
                if output and input_sig:
                    self.add_gate('buf', [output, input_sig])
    
    def convert_yosys_dff(self, gate_type: str, connections: Dict) -> None:
        """Convert Yosys DFF variations to standard DFF"""
        # Map Yosys DFF pins to standard pins
        clk = connections.get('C') or connections.get('CLK') or 'clk'
        d = connections.get('D') or self.get_new_wire()
        q = connections.get('Q') or self.get_new_wire()
        
        # Handle different DFF types
        rst_n = "1'b1"
        set_n = "1'b1"
        
        # Check for enable signal
        if 'E' in connections:
            # Create mux for enable
            mux_out = self.get_new_wire()
            self.create_mux(mux_out, q, d, connections['E'])
            d = mux_out
        
        # Parse gate type for reset/set behavior
        if '_PP0_' in gate_type or '_PN0_' in gate_type or '_NP0_' in gate_type or '_NN0_' in gate_type:
            # Async/sync reset to 0
            if 'R' in connections:
                rst_n = connections['R']
                # Handle active low reset for _N variants
                if '_PN' in gate_type or '_NN' in gate_type:
                    not_rst = self.get_new_wire()
                    self.add_gate('not', [not_rst, rst_n])
                    rst_n = not_rst
            else:
                rst_n = "1'b0"  # Default active
        elif '_PP1_' in gate_type or '_PN1_' in gate_type or '_NP1_' in gate_type or '_NN1_' in gate_type:
            # Async/sync set to 1
            if 'R' in connections:
                set_n = connections['R']
                # Handle active low set for _N variants
                if '_PN' in gate_type or '_NN' in gate_type:
                    not_set = self.get_new_wire()
                    self.add_gate('not', [not_set, set_n])
                    set_n = not_set
            else:
                set_n = "1'b0"  # Default active
        elif 'SR' in gate_type:
            # Has both set and reset
            rst_n = connections.get('R') or "1'b1"
            set_n = connections.get('S') or "1'b1"
            # Handle active low variants
            if '_PNN_' in gate_type or '_NNN_' in gate_type:
                not_set = self.get_new_wire()
                self.add_gate('not', [not_set, set_n])
                set_n = not_set
            if '_NPN_' in gate_type or '_NNN_' in gate_type:
                not_rst = self.get_new_wire()
                self.add_gate('not', [not_rst, rst_n])
                rst_n = not_rst
        
        # Handle clock polarity
        if '_N' in gate_type and gate_type.index('_N') == 5:  # Negative edge triggered
            not_clk = self.get_new_wire()
            self.add_gate('not', [not_clk, clk])
            clk = not_clk
        
        # Add as standard DFF
        self.add_dff(q, d, clk, rst_n, set_n)
    
    def convert_yosys_latch_to_dff(self, gate_type: str, connections: Dict) -> None:
        """Convert Yosys latch to DFF (approximation)"""
        # For latches, we approximate with a DFF
        # This is not exact but maintains synchronous design
        enable = connections.get('E') or connections.get('EN') or 'clk'
        d = connections.get('D') or self.get_new_wire()
        q = connections.get('Q') or self.get_new_wire()
        
        # For negative level latches, invert enable
        if '_N_' in gate_type:
            not_en = self.get_new_wire()
            self.add_gate('not', [not_en, enable])
            enable = not_en
        
        # Add as DFF with enable as clock (approximation)
        self.add_dff(q, d, enable, "1'b1", "1'b1")
    
    def parse_connections(self, conn_str: str) -> Dict[str, str]:
        """Parse named connections (.A(x), .B(y))"""
        connections = {}
        # Match .PIN(signal) patterns
        matches = re.findall(r'\.(\w+)\s*\(\s*([^)]+)\s*\)', conn_str)
        for pin, signal in matches:
            # Clean signal name
            signal = signal.strip()
            # Remove backslashes from escaped names
            if signal.startswith('\\'):
                signal = signal[1:].split()[0]
            connections[pin] = signal
        return connections
    
    def convert_primitive_gate(self, inst: Dict) -> None:
        """Convert primitive gate instance"""
        connections = self.parse_connections(inst['connections'])
        if connections:
            # Named connections - need to determine order
            if inst['type'] in ['not', 'buf']:
                output = connections.get('Y') or connections.get('O')
                input_sig = connections.get('A') or connections.get('I')
                if output and input_sig:
                    self.add_gate(inst['type'], [output, input_sig])
            else:
                # Binary gates
                output = connections.get('Y') or connections.get('O')
                input_a = connections.get('A') or connections.get('I0')
                input_b = connections.get('B') or connections.get('I1')
                if output and input_a and input_b:
                    self.add_gate(inst['type'], [output, input_a, input_b])
        else:
            # Positional connections
            pins = [p.strip() for p in inst['connections'].split(',')]
            if len(pins) >= 2:
                self.add_gate(inst['type'], pins)
    
    def create_mux(self, output: str, in0: str, in1: str, sel: str) -> None:
        """Create 2-to-1 mux using primitive gates"""
        not_sel = self.get_new_wire()
        and0_out = self.get_new_wire()
        and1_out = self.get_new_wire()
        
        self.add_gate('not', [not_sel, sel])
        self.add_gate('and', [and0_out, in0, not_sel])
        self.add_gate('and', [and1_out, in1, sel])
        self.add_gate('or', [output, and0_out, and1_out])
    
    def add_gate(self, gate_type: str, pins: List[str]) -> None:
        """Add a primitive gate instance"""
        # Track all signals
        for pin in pins:
            if pin and not pin.startswith("1'b"):
                # Clean signal name
                pin = pin.strip()
                if pin.startswith('\\'):
                    pin = pin[1:].split()[0]
                self.implicit_wires.add(pin)
        
        # Generate instance name with trojan prefix if needed
        inst_name = f"g{self.gate_counter}"
        if self.trojan_detection and inst_name in self.trojan_gates:
            inst_name = f"tj_{inst_name}"
        
        self.gate_counter += 1
        
        if gate_type in ['not', 'buf']:
            self.gate_instances.append(f"{gate_type} {inst_name} ({pins[0]}, {pins[1]});")
        else:
            self.gate_instances.append(f"{gate_type} {inst_name} ({pins[0]}, {pins[1]}, {pins[2]});")
    
    def add_raw_gate(self, gate_type: str, inst_name: str, pins: List[str]) -> None:
        # override inst_name to gNNN to enable comparison
        inst_name_std = f"g{self.gate_counter}"
        if self.trojan_detection and inst_name_std in self.trojan_gates:
            inst_name_std = f"tj_{inst_name_std}"

        pin_str = ", ".join(pins)
        self.gate_instances.append(f"{gate_type} {inst_name_std} ({pin_str});")
        self.gate_counter += 1


    def add_dff(self, q: str, d: str, clk: str, rst_n: str, set_n: str = "1'b1") -> None:
        """Add a DFF instance"""
        for signal in [q, d, clk, rst_n, set_n]:
            if signal and not signal.startswith("1'b"):
                signal = signal.strip()
                if signal.startswith('\\'):
                    signal = signal[1:].split()[0]
                self.implicit_wires.add(signal)
        
        # Generate instance name with trojan prefix if needed
        inst_name = f"g{self.gate_counter}"
        if self.trojan_detection and inst_name in self.trojan_gates:
            inst_name = f"tj_{inst_name}"
            
        self.gate_counter += 1
        self.gate_instances.append(
            f"dff {inst_name} (.RN({rst_n}), .SN({set_n}), .CK({clk}), .D({d}), .Q({q}));"
        )
    
    def get_new_wire(self) -> str:
        """Generate a new wire name"""
        wire_name = f"n{self.wire_counter}"
        self.wire_counter += 1
        self.wires.add(wire_name)
        return wire_name
    
    def generate_output(self) -> str:
        """Generate the final output netlist"""
        # Determine which wires need to be declared
        io_signals = set(self.inputs + self.outputs)
        declared_wires = self.wires.copy()
        
        # Add implicit wires that aren't already in I/O or declared
        for wire in self.implicit_wires:
            # Clean wire name
            wire = wire.strip()
            if wire.startswith('\\'):
                wire = wire[1:].split()[0]
            if wire not in io_signals and wire not in declared_wires and not wire.startswith("1'b"):
                declared_wires.add(wire)
        
        # Remove I/O signals from wire declarations
        declared_wires -= io_signals
        
        # Build output
        output = []
        
        # Module header - always named 'top'
        port_list = []
        if self.inputs:
            port_list.append(f"input {', '.join(self.inputs)}")
        # Always include clk and rst_n if not already present
        if 'clk' not in self.inputs:
            port_list.append("input clk")
        if 'rst_n' not in self.inputs:
            port_list.append("input rst_n")
        if self.outputs:
            port_list.append(f"output {', '.join(self.outputs)}")
        
        output.append(f"module top({', '.join(port_list)});")
        
        # Wire declarations
        if declared_wires:
            # Sort wires for consistent output
            sorted_wires = sorted(declared_wires)
            # Group wires by prefix for better readability
            wire_groups = defaultdict(list)
            for wire in sorted_wires:
                prefix = re.match(r'^[a-zA-Z_]+', wire)
                if prefix:
                    wire_groups[prefix.group()].append(wire)
                else:
                    wire_groups['_numeric'].append(wire)
            
            for prefix in sorted(wire_groups.keys()):
                wires = wire_groups[prefix]
                # Output in groups of 10 for readability
                for i in range(0, len(wires), 10):
                    output.append(f"wire {', '.join(wires[i:i+10])};")
        
        output.append("")
        
        # Gate instances
        for inst in self.gate_instances:
            output.append(inst)
        
        output.append("")
        output.append("endmodule")
        
        return '\n'.join(output)
    
    def synthesize_with_yosys(self, input_file: str, output_file: str) -> bool:
        """Use Yosys synthesis following the lab's exact pattern"""
        try:
            # Create Yosys script that follows lab pattern exactly
            yosys_script = f"""
    # Read the RTL design
    read_verilog {input_file}

    # Set hierarchy with top module (auto-detect or manual)
    hierarchy -auto-top

    # Convert processes to logic (essential for always blocks)
    proc

    # Flatten hierarchy (remove module boundaries)
    flatten

    # Technology mapping to basic gates
    techmap

    # Use ABC with liberty file approach
    # Since we don't have the exact liberty file, we'll use a safer approach
    # that mimics abc -liberty behavior without hanging

    # First try basic abc without complex optimization
    abc

    # Split multi-bit nets into individual wires
    splitnets -ports

    # Write the output in contest format
    write_verilog -noattr -noexpr {output_file}
    """
            
            # Write script to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.ys', delete=False) as f:
                f.write(yosys_script)
                script_file = f.name
            
            print(f"Running Yosys with lab-style script...")
            
            # Run Yosys with timeout to prevent hanging
            try:
                result = subprocess.run(
                    ['yosys', '-s', script_file],
                    capture_output=True,
                    text=True,
                    timeout=30  # 30 second timeout
                )
            except subprocess.TimeoutExpired:
                print("ABC hanging detected, trying alternative approach...")
                os.unlink(script_file)
                return self.synthesize_with_yosys_no_abc(input_file, output_file)
            
            # Clean up script file
            os.unlink(script_file)
            
            if result.returncode != 0:
                print(f"Yosys failed: {result.stderr}")
                print("Trying synthesis without ABC...")
                return self.synthesize_with_yosys_no_abc(input_file, output_file)
            
            # Check if output file was created properly
            if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
                print("Yosys produced empty output, trying without ABC...")
                return self.synthesize_with_yosys_no_abc(input_file, output_file)
                
            # Check if the output actually contains gates
            with open(output_file, 'r') as f:
                content = f.read()
                
            # Look for actual gate instances or wire declarations
            if not any(keyword in content for keyword in ['wire', 'assign', 'input', 'output']):
                print("Yosys output appears empty, trying without ABC...")
                return self.synthesize_with_yosys_no_abc(input_file, output_file)
                
            print(f"Lab-style Yosys synthesis successful!")
            return True
            
        except Exception as e:
            print(f"Error in lab-style synthesis: {str(e)}")
            return self.synthesize_with_yosys_no_abc(input_file, output_file)

    def synthesize_with_yosys_no_abc(self, input_file: str, output_file: str) -> bool:
        """Yosys synthesis without ABC - for complex arithmetic like Trojan8"""
        try:
            # Alternative script that avoids ABC entirely
            yosys_script = f"""
    # Read the design
    read_verilog {input_file}

    # Set top module
    hierarchy -auto-top

    # Convert processes (always blocks) to combinational logic
    proc

    # Flatten to single module
    flatten

    # Map technology primitives (converts * + - to gate networks)
    techmap

    # Convert remaining high-level constructs to basic gates
    # This handles arithmetic operations without ABC
    alumacc
    opt

    # Convert multiplexers and other complex structures
    muxcover
    opt

    # Simplemap converts everything to basic 2-input gates
    simplemap

    # Final optimization without ABC
    opt_clean

    # Write output
    write_verilog -noattr -noexpr {output_file}
    """
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.ys', delete=False) as f:
                f.write(yosys_script)
                script_file = f.name
            
            print(f"Running Yosys without ABC (for arithmetic operations)...")
            
            result = subprocess.run(
                ['yosys', '-s', script_file],
                capture_output=True,
                text=True,
                timeout=60  # Longer timeout for complex synthesis
            )
            
            os.unlink(script_file)
            
            if result.returncode != 0:
                print(f"No-ABC synthesis failed: {result.stderr}")
                return False
            
            if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
                print("No-ABC synthesis produced empty output")
                return False
                
            print(f"No-ABC synthesis successful!")
            return True
            
        except Exception as e:
            print(f"Error in no-ABC synthesis: {str(e)}")
            return False

    def synthesize_with_yosys_contest_format(self, input_file: str, output_file: str) -> bool:
        """Specialized synthesis for contest primitive gate format"""
        try:
            # This approach focuses on producing only the gates allowed by the contest
            yosys_script = f"""
    # Read design
    read_verilog {input_file}

    # Setup hierarchy
    hierarchy -auto-top

    # Convert behavioral code
    proc

    # Flatten design
    flatten

    # Handle memory and arithmetic
    memory
    techmap

    # Convert arithmetic to gate-level representation
    # This is crucial for multiplication and addition in Trojan8
    alumacc

    # Convert to basic logic operations
    opt_expr
    opt_clean

    # Map everything to 2-input primitives (contest requirement)
    simplemap

    # Clean up
    opt_clean

    # Write in contest format
    write_verilog -noattr -noexpr {output_file}
    """
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.ys', delete=False) as f:
                f.write(yosys_script)
                script_file = f.name
            
            print(f"Running contest-format synthesis...")
            
            result = subprocess.run(['yosys', '-s', script_file], 
                                capture_output=True, text=True, timeout=45)
            
            os.unlink(script_file)
            
            if result.returncode == 0 and os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                print("Contest-format synthesis successful!")
                return True
            else:
                print(f"Contest synthesis failed: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"Error in contest synthesis: {str(e)}")
            return False
    
    def preprocess_tech_cells(self, content: str) -> str:
        """Preprocess technology library cells to primitives before Yosys"""
        # Technology library cell mapping
        tech_cell_replacements = {
            # Basic gates
            'AND2X1': 'and2_gate', 'AND2X2': 'and2_gate', 'AND3X1': 'and3_gate', 'AND4X1': 'and4_gate',
            'OR2X1': 'or2_gate', 'OR2X2': 'or2_gate', 'OR3X1': 'or3_gate', 'OR4X1': 'or4_gate',
            'NAND2X0': 'nand2_gate', 'NAND2X1': 'nand2_gate', 'NAND2X2': 'nand2_gate', 
            'NAND3X0': 'nand3_gate', 'NAND3X1': 'nand3_gate', 'NAND4X0': 'nand4_gate', 'NAND4X1': 'nand4_gate',
            'NOR2X0': 'nor2_gate', 'NOR2X1': 'nor2_gate', 'NOR2X2': 'nor2_gate', 
            'NOR3X0': 'nor3_gate', 'NOR3X1': 'nor3_gate', 'NOR4X0': 'nor4_gate', 'NOR4X1': 'nor4_gate',
            'XOR2X1': 'xor2_gate', 'XOR2X2': 'xor2_gate', 'XNOR2X1': 'xnor2_gate', 'XNOR2X2': 'xnor2_gate',
            'INVX0': 'inv_gate', 'INVX1': 'inv_gate', 'INVX2': 'inv_gate', 'INVX4': 'inv_gate', 'INVX8': 'inv_gate',
            'NBUFFX2': 'buf_gate', 'NBUFFX4': 'buf_gate', 'NBUFFX8': 'buf_gate', 'BUFX2': 'buf_gate', 'BUFX4': 'buf_gate',
            # Complex gates - inverted output
            'AOI21X1': 'aoi21_gate', 'AOI22X1': 'aoi22_gate', 'AOI221X1': 'aoi221_gate', 'AOI222X1': 'aoi222_gate',
            'OAI21X1': 'oai21_gate', 'OAI22X1': 'oai22_gate', 'OAI221X1': 'oai221_gate', 'OAI222X1': 'oai222_gate',
            # Complex gates - non-inverted output  
            'AO21X1': 'ao21_gate', 'AO22X1': 'ao22_gate', 'AO221X1': 'ao221_gate', 'AO222X1': 'ao222_gate',
            'OA21X1': 'oa21_gate', 'OA22X1': 'oa22_gate', 'OA221X1': 'oa221_gate', 'OA222X1': 'oa222_gate',
            # Mux
            'MUX21X1': 'mux2_gate', 'MX2X1': 'mux2_gate', 'MX4X1': 'mux4_gate',
            'ISOLANDX1': 'and2_gate', 'ISOLANDX2': 'and2_gate', 'ISOLANDX4': 'and2_gate', 'ISOLANDX8': 'and2_gate',
            # Flip-flops
            'DFFX1': 'dff_cell', 'DFFX2': 'dff_cell', 'DFFASX1': 'dffas_cell', 'DFFASRX1': 'dffasr_cell',
            'SDFFX1': 'sdff_cell', 'SDFFX2': 'sdff_cell', 'SDFFARX1': 'sdffar_cell', 'SDFFASRX1': 'sdffasr_cell',
            'LATCHX1': 'latch_cell', 'LATCHX2': 'latch_cell',
        }
        
        # Create module definitions for tech cells
        tech_modules = []
        
        # Add module definitions for basic gates
        tech_modules.append("""
// Technology cell replacements
module and2_gate (output Y, input A, B); 
    assign Y = A & B; 
endmodule

module and3_gate (output Y, input A, B, C); 
    assign Y = A & B & C; 
endmodule

module and4_gate (output Y, input A, B, C, D); 
    assign Y = A & B & C & D; 
endmodule

module or2_gate (output Y, input A, B); 
    assign Y = A | B; 
endmodule

module or3_gate (output Y, input A, B, C); 
    assign Y = A | B | C; 
endmodule

module or4_gate (output Y, input A, B, C, D); 
    assign Y = A | B | C | D; 
endmodule

module nand2_gate (output Y, input A, B); 
    assign Y = ~(A & B); 
endmodule

module nand3_gate (output Y, input A, B, C); 
    assign Y = ~(A & B & C); 
endmodule

module nand4_gate (output Y, input A, B, C, D); 
    assign Y = ~(A & B & C & D); 
endmodule

module nor2_gate (output Y, input A, B); 
    assign Y = ~(A | B); 
endmodule

module nor3_gate (output Y, input A, B, C); 
    assign Y = ~(A | B | C); 
endmodule

module nor4_gate (output Y, input A, B, C, D); 
    assign Y = ~(A | B | C | D); 
endmodule

module xor2_gate (output Y, input A, B); 
    assign Y = A ^ B; 
endmodule

module xnor2_gate (output Y, input A, B); 
    assign Y = ~(A ^ B); 
endmodule

module inv_gate (output Y, input A); 
    assign Y = ~A; 
endmodule

module buf_gate (output Y, input A); 
    assign Y = A; 
endmodule

module aoi21_gate (output Y, input A, B, C); 
    assign Y = ~((A & B) | C); 
endmodule

module aoi22_gate (output Y, input A, B, C, D); 
    assign Y = ~((A & B) | (C & D)); 
endmodule

module aoi221_gate (output Y, input A, B, C, D, E); 
    assign Y = ~((A & B) | (C & D) | E); 
endmodule

module aoi222_gate (output Y, input A, B, C, D, E, F); 
    assign Y = ~((A & B) | (C & D) | (E & F)); 
endmodule

module oai21_gate (output Y, input A, B, C); 
    assign Y = ~((A | B) & C); 
endmodule

module oai22_gate (output Y, input A, B, C, D); 
    assign Y = ~((A | B) & (C | D)); 
endmodule

module oai221_gate (output Y, input A, B, C, D, E); 
    assign Y = ~((A | B) & (C | D) & E); 
endmodule

module oai222_gate (output Y, input A, B, C, D, E, F); 
    assign Y = ~((A | B) & (C | D) & (E | F)); 
endmodule

module ao21_gate (output Y, input A, B, C); 
    assign Y = (A & B) | C; 
endmodule

module ao22_gate (output Y, input A, B, C, D); 
    assign Y = (A & B) | (C & D); 
endmodule

module ao221_gate (output Y, input A, B, C, D, E); 
    assign Y = (A & B) | (C & D) | E; 
endmodule

module ao222_gate (output Y, input A, B, C, D, E, F); 
    assign Y = (A & B) | (C & D) | (E & F); 
endmodule

module oa21_gate (output Y, input A, B, C); 
    assign Y = (A | B) & C; 
endmodule

module oa22_gate (output Y, input A, B, C, D); 
    assign Y = (A | B) & (C | D); 
endmodule

module oa221_gate (output Y, input A, B, C, D, E); 
    assign Y = (A | B) & (C | D) & E; 
endmodule

module oa222_gate (output Y, input A, B, C, D, E, F); 
    assign Y = (A | B) & (C | D) & (E | F); 
endmodule

module mux2_gate (output Y, input A, B, S); 
    assign Y = S ? B : A; 
endmodule

module mux4_gate (output Y, input I0, I1, I2, I3, S0, S1); 
    assign Y = S1 ? (S0 ? I3 : I2) : (S0 ? I1 : I0); 
endmodule

module sdff_cell (output reg Q, output QN, input D, SI, SE, CLK);
    always @(posedge CLK) Q <= SE ? SI : D;
    assign QN = ~Q;
endmodule

module dff_cell (output reg Q, output QN, input D, CLK);
    always @(posedge CLK) Q <= D;
    assign QN = ~Q;
endmodule

module dffas_cell (output reg Q, output QN, input D, CLK, SETB);
    always @(posedge CLK or negedge SETB)
        if (!SETB) Q <= 1'b1;
        else Q <= D;
    assign QN = ~Q;
endmodule

module dffasr_cell (output reg Q, output QN, input D, CLK, SETB, RSTB);
    always @(posedge CLK or negedge SETB or negedge RSTB)
        if (!RSTB) Q <= 1'b0;
        else if (!SETB) Q <= 1'b1;
        else Q <= D;
    assign QN = ~Q;
endmodule

module sdffar_cell (output reg Q, output QN, input D, SI, SE, CLK, RSTB);
    always @(posedge CLK or negedge RSTB)
        if (!RSTB) Q <= 1'b0;
        else Q <= SE ? SI : D;
    assign QN = ~Q;
endmodule

module sdffasr_cell (output reg Q, output QN, input D, SI, SE, CLK, SETB, RSTB);
    always @(posedge CLK or negedge SETB or negedge RSTB)
        if (!RSTB) Q <= 1'b0;
        else if (!SETB) Q <= 1'b1;
        else Q <= SE ? SI : D;
    assign QN = ~Q;
endmodule

module latch_cell (output reg Q, output QN, input D, G);
    always @(*) if (G) Q <= D;
    assign QN = ~Q;
endmodule
""")
        
        # Simple replacement approach - replace cell types directly
        for tech_cell, primitive in tech_cell_replacements.items():
            # Use word boundary to ensure exact matches
            pattern = rf'\b{tech_cell}\b'
            content = re.sub(pattern, primitive, content)
        
        # Now we need to normalize ALL pin names to our standard format
        # Our standard: A, B, C, D for inputs, Y for output
        
        # First pass: handle all variations of pin names
        # This approach processes each gate instance to normalize pins
        
        # Find all gate instances and normalize their pins
        gate_types = '|'.join([
            'and2_gate', 'and3_gate', 'and4_gate',
            'or2_gate', 'or3_gate', 'or4_gate',
            'nand2_gate', 'nand3_gate', 'nand4_gate',
            'nor2_gate', 'nor3_gate', 'nor4_gate',
            'xor2_gate', 'xnor2_gate',
            'inv_gate', 'buf_gate',
            'aoi21_gate', 'aoi22_gate', 'aoi221_gate', 'aoi222_gate',
            'oai21_gate', 'oai22_gate', 'oai221_gate', 'oai222_gate',
            'ao21_gate', 'ao22_gate', 'ao221_gate', 'ao222_gate',
            'oa21_gate', 'oa22_gate', 'oa221_gate', 'oa222_gate',
            'mux2_gate', 'mux4_gate'
        ])
        
        # Process each gate type with its specific pin mappings
        # 2-input gates
        for gate in ['and2_gate', 'or2_gate', 'nand2_gate', 'nor2_gate', 'xor2_gate', 'xnor2_gate']:
            # Handle IN1/IN2/Q format
            content = re.sub(
                rf'\b({gate})\s+(\w+)\s*\(\s*\.IN1\s*\(([^)]+)\)\s*,\s*\.IN2\s*\(([^)]+)\)\s*,\s*\.Q\s*\(([^)]+)\)\s*\)',
                r'\1 \2 (.A(\3), .B(\4), .Y(\5))',
                content
            )
            # Handle IN1/IN2/QN format with inverter
            pattern = rf'\b({gate})\s+(\w+)\s*\(\s*\.IN1\s*\(([^)]+)\)\s*,\s*\.IN2\s*\(([^)]+)\)\s*,\s*\.QN\s*\(([^)]+)\)\s*\)'
            for match in re.finditer(pattern, content):
                gate_type, inst_name, in1, in2, qn = match.groups()
                if gate in ['nand2_gate', 'nor2_gate']:
                    # For NAND/NOR, QN is the non-inverted output
                    replacement = f"{gate_type} {inst_name} (.A({in1}), .B({in2}), .Y(_n_{inst_name}_inv));\n"
                    replacement += f"  wire _n_{inst_name}_inv;\n"
                    replacement += f"  inv_gate {inst_name}_inv (.A(_n_{inst_name}_inv), .Y({qn}))"
                else:
                    # For AND/OR, QN is the inverted output
                    replacement = f"{gate_type} {inst_name} (.A({in1}), .B({in2}), .Y(_n_{inst_name}_q));\n"
                    replacement += f"  wire _n_{inst_name}_q;\n"
                    replacement += f"  inv_gate {inst_name}_qn (.A(_n_{inst_name}_q), .Y({qn}))"
                content = content[:match.start()] + replacement + content[match.end():]
            # Handle A/B/Y format (already standard)
            content = re.sub(
                rf'\b({gate})\s+(\w+)\s*\(\s*\.A\s*\(([^)]+)\)\s*,\s*\.B\s*\(([^)]+)\)\s*,\s*\.Y\s*\(([^)]+)\)\s*\)',
                r'\1 \2 (.A(\3), .B(\4), .Y(\5))',
                content
            )
        
        # 3-input gates
        for gate in ['and3_gate', 'or3_gate', 'nand3_gate', 'nor3_gate']:
            # Handle IN1/IN2/IN3/Q format
            content = re.sub(
                rf'\b({gate})\s+(\w+)\s*\(\s*\.IN1\s*\(([^)]+)\)\s*,\s*\.IN2\s*\(([^)]+)\)\s*,\s*\.IN3\s*\(([^)]+)\)\s*,\s*\.Q\s*\(([^)]+)\)\s*\)',
                r'\1 \2 (.A(\3), .B(\4), .C(\5), .Y(\6))',
                content
            )
            # Handle IN1/IN2/IN3/QN format
            pattern = rf'\b({gate})\s+(\w+)\s*\(\s*\.IN1\s*\(([^)]+)\)\s*,\s*\.IN2\s*\(([^)]+)\)\s*,\s*\.IN3\s*\(([^)]+)\)\s*,\s*\.QN\s*\(([^)]+)\)\s*\)'
            for match in re.finditer(pattern, content):
                gate_type, inst_name, in1, in2, in3, qn = match.groups()
                if gate in ['nand3_gate', 'nor3_gate']:
                    replacement = f"{gate_type} {inst_name} (.A({in1}), .B({in2}), .C({in3}), .Y(_n_{inst_name}_inv));\n"
                    replacement += f"  wire _n_{inst_name}_inv;\n"
                    replacement += f"  inv_gate {inst_name}_inv (.A(_n_{inst_name}_inv), .Y({qn}))"
                else:
                    replacement = f"{gate_type} {inst_name} (.A({in1}), .B({in2}), .C({in3}), .Y(_n_{inst_name}_q));\n"
                    replacement += f"  wire _n_{inst_name}_q;\n"
                    replacement += f"  inv_gate {inst_name}_qn (.A(_n_{inst_name}_q), .Y({qn}))"
                content = content[:match.start()] + replacement + content[match.end():]
        
        # 4-input gates
        for gate in ['and4_gate', 'or4_gate', 'nand4_gate', 'nor4_gate']:
            # Handle IN1/IN2/IN3/IN4/Q format
            content = re.sub(
                rf'\b({gate})\s+(\w+)\s*\(\s*\.IN1\s*\(([^)]+)\)\s*,\s*\.IN2\s*\(([^)]+)\)\s*,\s*\.IN3\s*\(([^)]+)\)\s*,\s*\.IN4\s*\(([^)]+)\)\s*,\s*\.Q\s*\(([^)]+)\)\s*\)',
                r'\1 \2 (.A(\3), .B(\4), .C(\5), .D(\6), .Y(\7))',
                content
            )
            # Handle IN1/IN2/IN3/IN4/QN format
            pattern = rf'\b({gate})\s+(\w+)\s*\(\s*\.IN1\s*\(([^)]+)\)\s*,\s*\.IN2\s*\(([^)]+)\)\s*,\s*\.IN3\s*\(([^)]+)\)\s*,\s*\.IN4\s*\(([^)]+)\)\s*,\s*\.QN\s*\(([^)]+)\)\s*\)'
            for match in re.finditer(pattern, content):
                gate_type, inst_name, in1, in2, in3, in4, qn = match.groups()
                if gate in ['nand4_gate', 'nor4_gate']:
                    replacement = f"{gate_type} {inst_name} (.A({in1}), .B({in2}), .C({in3}), .D({in4}), .Y(_n_{inst_name}_inv));\n"
                    replacement += f"  wire _n_{inst_name}_inv;\n"
                    replacement += f"  inv_gate {inst_name}_inv (.A(_n_{inst_name}_inv), .Y({qn}))"
                else:
                    replacement = f"{gate_type} {inst_name} (.A({in1}), .B({in2}), .C({in3}), .D({in4}), .Y(_n_{inst_name}_q));\n"
                    replacement += f"  wire _n_{inst_name}_q;\n"
                    replacement += f"  inv_gate {inst_name}_qn (.A(_n_{inst_name}_q), .Y({qn}))"
                content = content[:match.start()] + replacement + content[match.end():]
        
        # AOI/OAI gates (inverted output) - QN is natural output
        for gate in ['aoi21_gate', 'oai21_gate']:
            content = re.sub(
                rf'\b({gate})\s+(\w+)\s*\(\s*\.IN1\s*\(([^)]+)\)\s*,\s*\.IN2\s*\(([^)]+)\)\s*,\s*\.IN3\s*\(([^)]+)\)\s*,\s*\.QN\s*\(([^)]+)\)\s*\)',
                r'\1 \2 (.A(\3), .B(\4), .C(\5), .Y(\6))',
                content
            )
        
        for gate in ['aoi22_gate', 'oai22_gate']:
            content = re.sub(
                rf'\b({gate})\s+(\w+)\s*\(\s*\.IN1\s*\(([^)]+)\)\s*,\s*\.IN2\s*\(([^)]+)\)\s*,\s*\.IN3\s*\(([^)]+)\)\s*,\s*\.IN4\s*\(([^)]+)\)\s*,\s*\.QN\s*\(([^)]+)\)\s*\)',
                r'\1 \2 (.A(\3), .B(\4), .C(\5), .D(\6), .Y(\7))',
                content
            )
        
        # AO/OA gates (non-inverted output) - Q is natural output
        for gate in ['ao21_gate', 'oa21_gate']:
            content = re.sub(
                rf'\b({gate})\s+(\w+)\s*\(\s*\.IN1\s*\(([^)]+)\)\s*,\s*\.IN2\s*\(([^)]+)\)\s*,\s*\.IN3\s*\(([^)]+)\)\s*,\s*\.Q\s*\(([^)]+)\)\s*\)',
                r'\1 \2 (.A(\3), .B(\4), .C(\5), .Y(\6))',
                content
            )
        
        for gate in ['ao22_gate', 'oa22_gate']:
            content = re.sub(
                rf'\b({gate})\s+(\w+)\s*\(\s*\.IN1\s*\(([^)]+)\)\s*,\s*\.IN2\s*\(([^)]+)\)\s*,\s*\.IN3\s*\(([^)]+)\)\s*,\s*\.IN4\s*\(([^)]+)\)\s*,\s*\.Q\s*\(([^)]+)\)\s*\)',
                r'\1 \2 (.A(\3), .B(\4), .C(\5), .D(\6), .Y(\7))',
                content
            )
        
        # Inverters and buffers
        # Handle IN/Q format
        content = re.sub(
            r'\b(inv_gate|buf_gate)\s+(\w+)\s*\(\s*\.IN\s*\(([^)]+)\)\s*,\s*\.Q\s*\(([^)]+)\)\s*\)',
            r'\1 \2 (.A(\3), .Y(\4))',
            content
        )
        # Handle IN/QN format (for inverters, QN is same as Q)
        content = re.sub(
            r'\b(inv_gate)\s+(\w+)\s*\(\s*\.IN\s*\(([^)]+)\)\s*,\s*\.QN\s*\(([^)]+)\)\s*\)',
            r'\1 \2 (.A(\3), .Y(\4))',
            content
        )
        # Handle I/Z or I/ZN format
        content = re.sub(
            r'\b(inv_gate|buf_gate)\s+(\w+)\s*\(\s*\.I\s*\(([^)]+)\)\s*,\s*\.ZN?\s*\(([^)]+)\)\s*\)',
            r'\1 \2 (.A(\3), .Y(\4))',
            content
        )
        
        # Add tech module definitions at the beginning
        content = '\n'.join(tech_modules) + '\n' + content
        
        return content

    def convert_file(self, input_file: str, output_file: str):
        """Convert a netlist file with multiple synthesis strategies"""
        if self.use_yosys:
            temp_file = output_file + ".yosys_temp.v"
            print(f"Running Yosys synthesis on {input_file}...")
            
            # Try synthesis strategies in order of preference
            strategies = [
                ("contest_format", self.synthesize_with_yosys_contest_format),
                ("no_abc", self.synthesize_with_yosys_no_abc),
                ("lab_style", self.synthesize_with_yosys),
            ]
            
            synthesis_success = False
            for strategy_name, strategy_func in strategies:
                try:
                    print(f"Trying {strategy_name} synthesis...")
                    if strategy_func(input_file, temp_file):
                        # Verify the output has actual content
                        with open(temp_file, 'r') as f:
                            content = f.read()
                        
                        # Check for meaningful content (not just empty module)
                        lines = [line.strip() for line in content.split('\n') if line.strip()]
                        meaningful_lines = [line for line in lines if not line.startswith('//')]
                        
                        if len(meaningful_lines) > 3:  # More than just module/endmodule
                            print(f"{strategy_name} synthesis successful with {len(meaningful_lines)} lines!")
                            synthesis_success = True
                            break
                        else:
                            print(f"{strategy_name} produced minimal output, trying next strategy...")
                            
                except Exception as e:
                    print(f"{strategy_name} synthesis error: {e}")
                    continue
            
            if not synthesis_success:
                print("All synthesis strategies failed, trying gate-level parsing fallback...")
                self.reset_state()
                try:
                    # Check if input file might already be gate-level
                    if self.is_gate_level_netlist(input_file):
                        print("Input appears to be gate-level, parsing directly...")
                        self.parse_gate_level_netlist(input_file)
                    else:
                        # Try to extract any behavioral patterns we can handle
                        print("Attempting behavioral parsing fallback...")
                        self.parse_behavioral_fallback(input_file)
                        
                    output_content = self.generate_output()
                    with open(output_file, 'w') as f:
                        f.write(output_content)
                    print(f"Fallback parsing succeeded with {self.gate_counter} gates")
                    return
                except Exception as e2:
                    raise Exception(f"All conversion methods failed: {e2}")
            
            # Process successful Yosys output
            try:
                print(f"Processing Yosys output...")
                with open(temp_file, 'r') as f:
                    content = f.read()
                
                print(f"Yosys output preview (first 10 lines):")
                for i, line in enumerate(content.split('\n')[:10]):
                    if line.strip():
                        print(f"  {i+1}: {line}")
                
                module_info = self.parse_yosys_netlist(content)
                print(f"Parsed module '{module_info['name']}' with:")
                print(f"  - {len(module_info['inputs'])} inputs")
                print(f"  - {len(module_info['outputs'])} outputs") 
                print(f"  - {len(module_info['instances'])} gate instances")
                
                self.convert_yosys_gates(module_info)
                output_content = self.generate_output()

                with open(output_file, 'w') as f:
                    f.write(output_content)

                print(f"Successfully converted {input_file} to {output_file}")
                print(f"Final result: {self.gate_counter} primitive gate instances")

            except Exception as e:
                print(f"Error processing Yosys output: {e}")
                print("Using direct fallback parsing...")
                self.reset_state()
                try:
                    if self.is_gate_level_netlist(input_file):
                        self.parse_gate_level_netlist(input_file)
                    else:
                        self.parse_behavioral_fallback(input_file)
                    output_content = self.generate_output()
                    with open(output_file, 'w') as f:
                        f.write(output_content)
                    print(f"Fallback parsing succeeded")
                except Exception as e2:
                    raise Exception(f"Final fallback failed: {e2}")

            finally:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)

        else:
            raise NotImplementedError("Direct conversion not supported for complex RTL")

    def parse_behavioral_fallback(self, input_file: str):
        """Fallback parser for simple behavioral Verilog"""
        print("Attempting to parse behavioral constructs...")
        
        with open(input_file, 'r') as f:
            content = f.read()
        
        # Extract module info
        module_match = re.search(r'module\s+(\w+)\s*\((.*?)\);', content, re.DOTALL)
        if not module_match:
            raise Exception("No module found")
        
        # Parse port declarations
        input_matches = re.findall(r'input\s+(?:wire\s+)?(?:\[.*?\]\s+)?(\w+)', content)
        output_matches = re.findall(r'output\s+(?:wire\s+)?(?:\[.*?\]\s+)?(\w+)', content)
        
        self.inputs.extend(input_matches)
        self.outputs.extend(output_matches)
        
        # Look for simple assign statements we can convert
        assign_matches = re.findall(r'assign\s+(\w+)\s*=\s*([^;]+);', content)
        
        for output_sig, expression in assign_matches:
            # Try to convert simple expressions to gates
            expr = expression.strip()
            
            # Handle simple binary operations
            if '&' in expr and '|' not in expr and '^' not in expr:
                # Simple AND
                operands = [op.strip() for op in expr.split('&')]
                if len(operands) == 2:
                    self.add_gate('and', [output_sig, operands[0], operands[1]])
            elif '|' in expr and '&' not in expr and '^' not in expr:
                # Simple OR
                operands = [op.strip() for op in expr.split('|')]
                if len(operands) == 2:
                    self.add_gate('or', [output_sig, operands[0], operands[1]])
            elif '^' in expr:
                # XOR
                operands = [op.strip() for op in expr.split('^')]
                if len(operands) == 2:
                    self.add_gate('xor', [output_sig, operands[0], operands[1]])
            elif expr.startswith('~'):
                # NOT
                input_sig = expr[1:].strip()
                self.add_gate('not', [output_sig, input_sig])
            else:
                # Default to buffer for unknown expressions
                if ' ' not in expr and expr.isidentifier():
                    self.add_gate('buf', [output_sig, expr])
        
        print(f"Behavioral fallback extracted {self.gate_counter} gates")

    def reset_state(self):
        """Reset converter state for retry"""
        old_use_yosys = self.use_yosys
        old_trojan_detection = self.trojan_detection
        old_trojan_gates = self.trojan_gates.copy()
        
        self.__init__(use_yosys=old_use_yosys, trojan_detection=old_trojan_detection)
        self.trojan_gates = old_trojan_gates


def main():
    parser = argparse.ArgumentParser(description='Convert netlist to ICCAD contest format')
    parser.add_argument('input', help='Input Verilog file or directory')
    parser.add_argument('-o', '--output', help='Output file (default: input_converted.v)')
    parser.add_argument('--no-yosys', action='store_true', help='Disable Yosys synthesis')
    parser.add_argument('--detect-trojan', action='store_true', help='Detect trojan gates by comparing TjFree.v and TjIn.v')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    parser.add_argument('--convert-trojans', action='store_true', help='Convert all trojan*.v to primitive-only gate-level netlist')

    
    args = parser.parse_args()
    
    # Check if Yosys is available
    use_yosys = not args.no_yosys
    if use_yosys:
        try:
            subprocess.run(['yosys', '-V'], capture_output=True, check=True)
        except:
            print("Warning: Yosys not found. Please install Yosys for better RTL synthesis.")
            print("You can install it with: sudo apt-get install yosys")
            sys.exit(1)
    
        if args.convert_trojans:
            converter = NetlistConverter()
            converter.use_yosys = True

            input_dir = args.input
            if not os.path.isdir(input_dir):
                print("Error: --convert-trojans expects input to be a directory.")
                return

            for filename in os.listdir(input_dir):
                # FIXED: Only process original trojan files, skip already converted ones
                if (filename.startswith("trojan") and 
                    filename.endswith(".v") and 
                    not filename.endswith("_converted.v")):  # Skip already converted files
                    
                    src = os.path.join(input_dir, filename)
                    dst = os.path.join(input_dir, filename.replace(".v", "_converted.v"))
                    
                    print(f"[Trojan Convert] Processing {filename}...")
                    try:
                        converter.convert_file(src, dst)
                    except Exception as e:
                        print(f"[Trojan Convert Error] Failed to process {filename}: {e}")
            return



    # Check if input is a directory (for trojan detection mode)
    if os.path.isdir(args.input):
        if not args.detect_trojan:
            print("Error: Input is a directory. Use --detect-trojan flag to process TjFree.v and TjIn.v files.")
            sys.exit(1)
            
        # Find TjFree.v and TjIn.v in the directory
        tjfree_file = os.path.join(args.input, 'TjFree.v')
        tjin_file = os.path.join(args.input, 'TjIn.v')
        
        if not os.path.exists(tjfree_file):
            print(f"Error: {tjfree_file} not found")
            sys.exit(1)
        if not os.path.exists(tjin_file):
            print(f"Error: {tjin_file} not found")
            sys.exit(1)
            
        # First detect trojan gates
        converter = NetlistConverter(use_yosys=use_yosys, trojan_detection=True)
        trojan_gates = converter.detect_trojan_gates(tjfree_file, tjin_file)
        
        # Convert TjIn.v with trojan labeling
        output_file = args.output or os.path.join(args.input, 'TjIn_converted.v')
        converter.trojan_gates = trojan_gates
        converter.convert_file(tjin_file, output_file)
        
        # Also convert TjFree.v for comparison
        tjfree_output = os.path.join(args.input, 'TjFree_converted.v')
        converter_free = NetlistConverter(use_yosys=use_yosys, trojan_detection=False)
        converter_free.convert_file(tjfree_file, tjfree_output)
        
        print(f"\nTrojan detection complete!")
        print(f"TjFree converted to: {tjfree_output}")
        print(f"TjIn converted to: {output_file}")
        print(f"Trojan gates are labeled with 'tj_' prefix")
    
    elif args.convert_trojans:
        input_dir = args.input
        for filename in os.listdir(input_dir):
            if filename.startswith("trojan") and filename.endswith(".v"):
                src = os.path.join(input_dir, filename)
                dst = os.path.join(input_dir, filename.replace(".v", "_converted.v"))
                print(f"[Trojan Convert] Processing {filename}...")
                try:
                    converter.convert_file(src, dst)
                except Exception as e:
                    print(f"[Trojan Convert Error] Failed to process {filename}: {e}")

    else:
        # Single file conversion
        output_file = args.output or args.input.replace('.v', '_converted.v')
        
        converter = NetlistConverter(use_yosys=use_yosys, trojan_detection=False)
        converter.convert_file(args.input, output_file)


if __name__ == '__main__':
    main()


