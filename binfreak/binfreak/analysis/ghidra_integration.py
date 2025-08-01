"""
Ghidra Integration Module for Professional Binary Analysis
Provides integration with Ghidra headless analyzer for advanced analysis
"""

import os
import subprocess
import tempfile
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging


class GhidraAnalyzer:
    """Professional binary analysis using Ghidra headless analyzer"""
    
    def __init__(self, ghidra_path: Optional[str] = None):
        self.logger = logging.getLogger('GhidraAnalyzer')
        self.ghidra_path = ghidra_path or self._find_ghidra_installation()
        self.temp_dir = None
        self.analysis_cache = {}
        
    def _find_ghidra_installation(self) -> Optional[str]:
        """Find Ghidra installation on the system"""
        possible_paths = [
            '/opt/ghidra',
            '/usr/local/ghidra',
            '/Applications/ghidra',
            os.path.expanduser('~/ghidra'),
            os.path.expanduser('~/tools/ghidra'),
        ]
        
        # Check environment variable
        if 'GHIDRA_INSTALL_DIR' in os.environ:
            possible_paths.insert(0, os.environ['GHIDRA_INSTALL_DIR'])
        
        for path in possible_paths:
            if os.path.exists(os.path.join(path, 'support', 'analyzeHeadless')):
                self.logger.info(f"Found Ghidra installation at: {path}")
                return path
        
        self.logger.warning("Ghidra installation not found. Some features will be limited.")
        return None
    
    def is_available(self) -> bool:
        """Check if Ghidra is available for analysis"""
        return self.ghidra_path is not None and os.path.exists(
            os.path.join(self.ghidra_path, 'support', 'analyzeHeadless')
        )
    
    def analyze_binary(self, binary_path: str, analysis_options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Perform comprehensive binary analysis using Ghidra"""
        if not self.is_available():
            return {'error': 'Ghidra not available', 'available': False}
        
        analysis_options = analysis_options or {}
        
        try:
            # Create temporary directory for analysis
            with tempfile.TemporaryDirectory() as temp_dir:
                self.temp_dir = temp_dir
                project_dir = os.path.join(temp_dir, 'ghidra_project')
                os.makedirs(project_dir, exist_ok=True)
                
                # Run Ghidra headless analysis
                result = self._run_ghidra_analysis(binary_path, project_dir, analysis_options)
                
                if result['success']:
                    # Parse analysis results
                    analysis_data = self._parse_ghidra_output(project_dir, binary_path)
                    result.update(analysis_data)
                
                return result
        
        except Exception as e:
            self.logger.error(f"Ghidra analysis failed: {e}")
            return {'error': str(e), 'success': False}
    
    def _run_ghidra_analysis(self, binary_path: str, project_dir: str, 
                           options: Dict[str, Any]) -> Dict[str, Any]:
        """Run Ghidra headless analyzer"""
        try:
            analyze_script = os.path.join(self.ghidra_path, 'support', 'analyzeHeadless')
            project_name = 'binfreak_analysis'
            
            # Basic analysis command
            cmd = [
                analyze_script,
                project_dir,
                project_name,
                '-import', binary_path,
                '-deleteProject',  # Clean up after analysis
                '-overwrite',
            ]
            
            # Add analysis options
            if options.get('analyze_functions', True):
                cmd.extend(['-processor', 'x86:LE:64:default'])  # Default to x64
            
            if options.get('export_xml', True):
                xml_output = os.path.join(project_dir, 'analysis.xml')
                cmd.extend(['-postScript', 'ExportXML.java', xml_output])
            
            if options.get('export_functions', True):
                cmd.extend(['-postScript', 'ListFunctions.java'])
            
            # Add timeout and memory limits
            timeout = options.get('timeout', 300)  # 5 minutes default
            
            # Run analysis
            self.logger.info(f"Running Ghidra analysis: {' '.join(cmd)}")
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=project_dir
            )
            
            if process.returncode == 0:
                return {
                    'success': True,
                    'stdout': process.stdout,
                    'stderr': process.stderr,
                    'project_dir': project_dir
                }
            else:
                return {
                    'success': False,
                    'error': f"Ghidra analysis failed with code {process.returncode}",
                    'stdout': process.stdout,
                    'stderr': process.stderr
                }
        
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Ghidra analysis timed out'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _parse_ghidra_output(self, project_dir: str, binary_path: str) -> Dict[str, Any]:
        """Parse Ghidra analysis output"""
        analysis_data = {
            'functions': [],
            'symbols': [],
            'strings': [],
            'cross_references': [],
            'data_types': [],
            'memory_layout': {},
            'disassembly': [],
            'control_flow_graphs': []
        }
        
        try:
            # Parse XML output if available
            xml_file = os.path.join(project_dir, 'analysis.xml')
            if os.path.exists(xml_file):
                analysis_data.update(self._parse_xml_output(xml_file))
            
            # Parse function listing
            function_file = os.path.join(project_dir, 'functions.txt')
            if os.path.exists(function_file):
                analysis_data['functions'] = self._parse_function_list(function_file)
            
            # Parse other outputs
            analysis_data.update(self._parse_additional_outputs(project_dir))
            
        except Exception as e:
            self.logger.warning(f"Failed to parse some Ghidra outputs: {e}")
        
        return analysis_data
    
    def _parse_xml_output(self, xml_file: str) -> Dict[str, Any]:
        """Parse Ghidra XML export"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            data = {
                'functions': self._extract_functions_from_xml(root),
                'symbols': self._extract_symbols_from_xml(root),
                'memory_layout': self._extract_memory_layout_from_xml(root)
            }
            
            return data
        
        except Exception as e:
            self.logger.warning(f"Failed to parse XML output: {e}")
            return {}
    
    def _extract_functions_from_xml(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Extract function information from XML"""
        functions = []
        
        # Find function elements (varies by Ghidra version)
        function_elements = root.findall('.//FUNCTION') or root.findall('.//function')
        
        for func_elem in function_elements:
            function = {
                'name': func_elem.get('NAME', func_elem.get('name', 'unknown')),
                'address': func_elem.get('ADDRESS', func_elem.get('address', '0x0')),
                'size': func_elem.get('SIZE', func_elem.get('size', '0')),
                'entry_point': func_elem.get('ENTRY_POINT', func_elem.get('entry_point', '0x0')),
                'calling_convention': func_elem.get('CALLING_CONVENTION', 'unknown'),
                'signature': func_elem.get('SIGNATURE', ''),
                'parameters': [],
                'local_variables': []
            }
            
            # Extract parameters
            for param in func_elem.findall('.//PARAMETER') or func_elem.findall('.//parameter'):
                function['parameters'].append({
                    'name': param.get('NAME', param.get('name', '')),
                    'type': param.get('TYPE', param.get('type', '')),
                    'storage': param.get('STORAGE', param.get('storage', ''))
                })
            
            # Extract local variables
            for var in func_elem.findall('.//LOCAL_VAR') or func_elem.findall('.//local_var'):
                function['local_variables'].append({
                    'name': var.get('NAME', var.get('name', '')),
                    'type': var.get('TYPE', var.get('type', '')),
                    'offset': var.get('OFFSET', var.get('offset', '0'))
                })
            
            functions.append(function)
        
        return functions
    
    def _extract_symbols_from_xml(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Extract symbol information from XML"""
        symbols = []
        
        symbol_elements = root.findall('.//SYMBOL') or root.findall('.//symbol')
        
        for sym_elem in symbol_elements:
            symbol = {
                'name': sym_elem.get('NAME', sym_elem.get('name', '')),
                'address': sym_elem.get('ADDRESS', sym_elem.get('address', '0x0')),
                'type': sym_elem.get('TYPE', sym_elem.get('type', 'unknown')),
                'namespace': sym_elem.get('NAMESPACE', sym_elem.get('namespace', 'Global')),
                'source': sym_elem.get('SOURCE', sym_elem.get('source', 'unknown'))
            }
            symbols.append(symbol)
        
        return symbols
    
    def _extract_memory_layout_from_xml(self, root: ET.Element) -> Dict[str, Any]:
        """Extract memory layout information from XML"""
        memory_layout = {
            'segments': [],
            'sections': [],
            'base_address': '0x0',
            'entry_point': '0x0'
        }
        
        # Extract memory segments
        for segment in root.findall('.//MEMORY_SECTION') or root.findall('.//memory_section'):
            memory_layout['segments'].append({
                'name': segment.get('NAME', segment.get('name', '')),
                'start': segment.get('START', segment.get('start', '0x0')),
                'end': segment.get('END', segment.get('end', '0x0')),
                'permissions': segment.get('PERMISSIONS', segment.get('permissions', 'r--'))
            })
        
        return memory_layout
    
    def _parse_function_list(self, function_file: str) -> List[Dict[str, Any]]:
        """Parse function list output"""
        functions = []
        
        try:
            with open(function_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Parse function line (format varies)
                        parts = line.split()
                        if len(parts) >= 2:
                            functions.append({
                                'address': parts[0],
                                'name': parts[1] if len(parts) > 1 else 'unknown',
                                'size': parts[2] if len(parts) > 2 else 'unknown'
                            })
        
        except Exception as e:
            self.logger.warning(f"Failed to parse function list: {e}")
        
        return functions
    
    def _parse_additional_outputs(self, project_dir: str) -> Dict[str, Any]:
        """Parse additional Ghidra outputs"""
        data = {}
        
        # Look for additional output files
        output_files = [
            'strings.txt',
            'imports.txt', 
            'exports.txt',
            'cross_references.txt'
        ]
        
        for filename in output_files:
            filepath = os.path.join(project_dir, filename)
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r') as f:
                        content = f.read().strip()
                        key = filename.replace('.txt', '')
                        data[key] = content.split('\n') if content else []
                except Exception as e:
                    self.logger.warning(f"Failed to parse {filename}: {e}")
        
        return data
    
    def generate_control_flow_graph(self, binary_path: str, function_address: str) -> Dict[str, Any]:
        """Generate control flow graph for a specific function"""
        if not self.is_available():
            return {'error': 'Ghidra not available'}
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create Ghidra script for CFG generation
                script_content = self._create_cfg_script(function_address)
                script_path = os.path.join(temp_dir, 'generate_cfg.java')
                
                with open(script_path, 'w') as f:
                    f.write(script_content)
                
                # Run Ghidra with CFG script
                result = self._run_ghidra_with_script(binary_path, script_path, temp_dir)
                
                if result['success']:
                    # Parse CFG output
                    cfg_data = self._parse_cfg_output(temp_dir)
                    return {'success': True, 'cfg': cfg_data}
                else:
                    return result
        
        except Exception as e:
            return {'error': str(e), 'success': False}
    
    def _create_cfg_script(self, function_address: str) -> str:
        """Create Ghidra script for control flow graph generation"""
        script = f"""
// BinFreak Control Flow Graph Generator
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import java.io.*;

public class GenerateCFG extends GhidraScript {{
    
    @Override
    public void run() throws Exception {{
        Address funcAddr = getAddressFactory().getAddress("{function_address}");
        Function func = getFunctionAt(funcAddr);
        
        if (func == null) {{
            println("Function not found at address: {function_address}");
            return;
        }}
        
        // Generate basic blocks
        BasicBlockModel blockModel = new BasicBlockModel(currentProgram);
        CodeBlockIterator blocks = blockModel.getCodeBlocksContaining(func.getBody(), monitor);
        
        PrintWriter writer = new PrintWriter(new File("cfg_output.json"));
        writer.println("{{");
        writer.println("  \\"function\\": \\"" + func.getName() + "\\",");
        writer.println("  \\"address\\": \\"" + func.getEntryPoint() + "\\",");
        writer.println("  \\"blocks\\": [");
        
        boolean first = true;
        while (blocks.hasNext()) {{
            CodeBlock block = blocks.next();
            
            if (!first) writer.println(",");
            first = false;
            
            writer.println("    {{");
            writer.println("      \\"start\\": \\"" + block.getMinAddress() + "\\",");
            writer.println("      \\"end\\": \\"" + block.getMaxAddress() + "\\",");
            writer.println("      \\"size\\": " + block.getNumAddresses() + ",");
            
            // Get successors
            writer.println("      \\"successors\\": [");
            CodeBlockReferenceIterator refs = block.getDestinations(monitor);
            boolean firstRef = true;
            while (refs.hasNext()) {{
                CodeBlockReference ref = refs.next();
                if (!firstRef) writer.println(",");
                firstRef = false;
                writer.println("        \\"" + ref.getDestinationAddress() + "\\"");
            }}
            writer.println("      ]");
            writer.println("    }}");
        }}
        
        writer.println("  ]");
        writer.println("}}");
        writer.close();
        
        println("CFG generated successfully");
    }}
}}
"""
        return script
    
    def _run_ghidra_with_script(self, binary_path: str, script_path: str, 
                              temp_dir: str) -> Dict[str, Any]:
        """Run Ghidra with custom script"""
        try:
            analyze_script = os.path.join(self.ghidra_path, 'support', 'analyzeHeadless')
            project_dir = os.path.join(temp_dir, 'project')
            os.makedirs(project_dir, exist_ok=True)
            
            cmd = [
                analyze_script,
                project_dir,
                'cfg_project',
                '-import', binary_path,
                '-postScript', script_path,
                '-deleteProject'
            ]
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # 2 minutes for CFG generation
                cwd=temp_dir
            )
            
            return {
                'success': process.returncode == 0,
                'stdout': process.stdout,
                'stderr': process.stderr
            }
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _parse_cfg_output(self, temp_dir: str) -> Dict[str, Any]:
        """Parse control flow graph output"""
        cfg_file = os.path.join(temp_dir, 'cfg_output.json')
        
        if os.path.exists(cfg_file):
            try:
                with open(cfg_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.warning(f"Failed to parse CFG output: {e}")
        
        return {'error': 'CFG output not found'}
    
    def extract_strings_advanced(self, binary_path: str) -> List[Dict[str, Any]]:
        """Extract strings using Ghidra's advanced string detection"""
        if not self.is_available():
            return []
        
        try:
            analysis_result = self.analyze_binary(binary_path, {
                'extract_strings': True,
                'timeout': 60
            })
            
            if analysis_result.get('success'):
                strings_data = analysis_result.get('strings', [])
                
                # Parse string data
                parsed_strings = []
                for string_line in strings_data:
                    if string_line.strip():
                        parts = string_line.split('\t')
                        if len(parts) >= 2:
                            parsed_strings.append({
                                'address': parts[0],
                                'value': parts[1],
                                'encoding': parts[2] if len(parts) > 2 else 'ascii',
                                'length': len(parts[1]) if len(parts) > 1 else 0
                            })
                
                return parsed_strings
        
        except Exception as e:
            self.logger.warning(f"Advanced string extraction failed: {e}")
        
        return []


class GhidraFallback:
    """Fallback implementation when Ghidra is not available"""
    
    def __init__(self):
        self.logger = logging.getLogger('GhidraFallback')
    
    def is_available(self) -> bool:
        return False
    
    def analyze_binary(self, binary_path: str, analysis_options: Dict[str, Any] = None) -> Dict[str, Any]:
        return {
            'error': 'Ghidra not available - using fallback analysis',
            'available': False,
            'functions': [],
            'symbols': [],
            'strings': []
        }
    
    def generate_control_flow_graph(self, binary_path: str, function_address: str) -> Dict[str, Any]:
        return {'error': 'Ghidra not available for CFG generation'}
    
    def extract_strings_advanced(self, binary_path: str) -> List[Dict[str, Any]]:
        return []


# Factory function to get appropriate analyzer
def get_ghidra_analyzer(ghidra_path: Optional[str] = None) -> GhidraAnalyzer:
    """Get Ghidra analyzer instance (with fallback if not available)"""
    analyzer = GhidraAnalyzer(ghidra_path)
    
    if not analyzer.is_available():
        analyzer.logger.warning("Ghidra not available, some advanced features will be limited")
        # Return the same object but with limited functionality
        
    return analyzer