#!/usr/bin/env python3
"""
FuzzPro GUI - PyQt6 Interface for FuzzPro Fuzzing Tool
Professional Security Testing Interface
"""

import sys
import os
import subprocess
import threading
import time
import json
import tempfile
import base64
import shutil
import warnings

# Embedded binary placeholder
EMBEDDED_FUZZPRO_BINARY = None

# Suppress PyQt6 deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, module="PyQt6")
from PyQt6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, 
                            QWidget, QPushButton, QLabel, QLineEdit, QTextEdit, 
                            QProgressBar, QSpinBox, QFileDialog, QGroupBox, 
                            QGridLayout, QTabWidget, QTableWidget, QTableWidgetItem,
                            QSplitter, QFrame, QCheckBox, QComboBox)
from PyQt6.QtCore import QThread, pyqtSignal, QTimer, Qt
from PyQt6.QtGui import QFont, QPixmap, QPalette, QColor, QIcon

class FuzzingWorker(QThread):
    """Background thread for running fuzzing operations"""
    progress_updated = pyqtSignal(int, int, int)  # current, total, crashes
    output_updated = pyqtSignal(str)
    crash_updated = pyqtSignal(dict)  # real-time crash updates
    stats_updated = pyqtSignal(dict)  # real-time statistics updates
    finished = pyqtSignal(dict)  # results dictionary
    
    def __init__(self, target_binary, iterations, timeout=30, intensity="High", fuzzing_mode="Classic Fuzzing"):
        super().__init__()
        self.target_binary = target_binary
        self.iterations = iterations
        self.timeout = timeout
        self.intensity = intensity
        self.fuzzing_mode = fuzzing_mode
        self.coverage_guided = (fuzzing_mode == "Coverage-guided (ptrace)")
        self.is_running = True
        
    def extract_fuzzpro_binary(self):
        """Extract embedded FuzzPro binary to temp location"""
        if EMBEDDED_FUZZPRO_BINARY is None:
            # Fallback to local binary
            return "./fuzzpro"
            
        temp_dir = tempfile.mkdtemp()
        fuzzpro_path = os.path.join(temp_dir, "fuzzpro")
        
        with open(fuzzpro_path, 'wb') as f:
            f.write(EMBEDDED_FUZZPRO_BINARY)
        
        os.chmod(fuzzpro_path, 0o755)  # Make executable
        return fuzzpro_path
        
    def run(self):
        """Execute fuzzing campaign"""
        try:
            fuzzpro_path = self.extract_fuzzpro_binary()
            
            # Extract intensity number from selection (e.g. "7" from "7 (High)")
            intensity_value = self.intensity.split(" ")[0]
            if not intensity_value.isdigit():
                intensity_value = "7"  # Default if parsing fails
                
            cmd = [
                fuzzpro_path, 
                "-i", str(self.iterations),
                "-m", intensity_value
            ]
            
            # Add coverage-guided flag if enabled
            if self.coverage_guided:
                cmd.append("-c")
                self.output_updated.emit(f"[*] Coverage-guided fuzzing enabled (ptrace instrumentation)")
                self.output_updated.emit(f"[*] Mutation intensity: {intensity_value}/10")
            else:
                self.output_updated.emit(f"[*] Classic fuzzing mode enabled")
                self.output_updated.emit(f"[*] Mutation intensity: {intensity_value}/10")
            
            cmd.append(self.target_binary)
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                bufsize=0,  # Unbuffered for real-time output
                universal_newlines=False
            )
            
            output_lines = []
            current_iter = 0
            total_crashes = 0
            crash_details = []
            start_time = time.time()
            last_progress_time = start_time
            
            while True:
                # Read single byte to handle \r properly
                output_byte = process.stdout.read(1)
                if output_byte == b'' and process.poll() is not None:
                    break
                    
                if output_byte:
                    # Accumulate output until we get a complete line
                    if not hasattr(self, '_output_buffer'):
                        self._output_buffer = b''
                    
                    self._output_buffer += output_byte
                    
                    # Check for line endings or carriage return
                    if output_byte in [b'\n', b'\r']:
                        if self._output_buffer:
                            # Decode with error handling
                            try:
                                output = self._output_buffer.decode('utf-8', errors='replace').strip()
                            except:
                                output = str(self._output_buffer, errors='replace').strip()
                            
                            # Reset buffer
                            self._output_buffer = b''
                            
                            if output:  # Only process non-empty lines
                                output_lines.append(output)
                                
                                # Filter console output - only show basic fuzzing info
                                show_in_console = True
                                
                                # Hide all crash analysis sections
                                if "CRASH SUMMARY" in output or \
                                   "Found" in output and "unique crash locations:" in output or \
                                   "(__TEXT,__text) section" in output or \
                                   "Recommendation:" in output or \
                                   "Most frequent crash:" in output or \
                                   "] Address:" in output or \
                                   ("Signal:" in output and not "Crashes:" in output) or \
                                   ("Count:" in output and "occurrences" in output) or \
                                   ("Type:" in output and not "Crashes:" in output) or \
                                   ("Severity:" in output and not "Crashes:" in output) or \
                                   ("Description:" in output) or \
                                   ("Analysis:" in output) or \
                                   ("Exploitability:" in output) or \
                                   "Starting comprehensive crash analysis" in output or \
                                   (output.strip() == "./vulnerable_test:") or \
                                   (output.strip().endswith("./vulnerable_test:")) or \
                                   ("and 90 more" in output) or \
                                   (output.strip().startswith("./") and output.strip().endswith(":")):
                                    show_in_console = False
                                
                                # Hide assembly context lines
                                if "Assembly context:" in output or \
                                   "Showing first" in output and "lines of assembly" in output or \
                                   (output.strip().startswith("0") and len(output.strip()) > 10 and '\t' in output) or \
                                   (output.strip().startswith("_") and ":" in output and len(output.strip()) < 50):
                                    show_in_console = False
                                
                                # Hide coverage statistics
                                if "Coverage Statistics:" in output or \
                                   "Total basic blocks discovered:" in output or \
                                   "Total hits:" in output or \
                                   "New blocks in last run:" in output or \
                                   "Estimated coverage:" in output or \
                                   "Text section:" in output or \
                                   "Coverage Report at" in output:
                                    show_in_console = False
                                
                                # Hide live crash table
                                if "LIVE CRASH TABLE" in output or \
                                   "│" in output and ("Address" in output or "Signal" in output or "0x" in output) or \
                                   "├" in output or "└" in output or "┌" in output or "┐" in output or \
                                   "Showing last" in output and "total crashes" in output:
                                    show_in_console = False
                                
                                # Only emit to console if it should be shown
                                if show_in_console:
                                    self.output_updated.emit(output)
                                
                                # Parse progress from real-time output - IMPROVED PARSING
                                if "] " in output and "/" in output and "%" in output and "Crashes:" in output and "END SUMMARY" not in output:
                                    try:
                                        # Handle format: "] 50/1000 (5%) | Crashes: 2"
                                        progress_part = output.split("] ")[1]  # Get part after "] "
                                        
                                        # Extract current/total
                                        if "/" in progress_part:
                                            current_total = progress_part.split("(")[0].strip()  # Get "50/1000 "
                                            current_str, total_str = current_total.split("/")
                                            current_iter = int(current_str.strip())
                                            
                                            # Extract crashes count - FIXED PARSING
                                            if "Crashes:" in output:
                                                crash_part = output.split("Crashes:")[1].strip()
                                                # Only take the number part before any non-digit characters
                                                crash_number = ""
                                                for char in crash_part:
                                                    if char.isdigit():
                                                        crash_number += char
                                                    else:
                                                        break
                                                if crash_number:
                                                    parsed_crashes = int(crash_number)
                                                    # Update total_crashes with the maximum seen
                                                    total_crashes = max(total_crashes, parsed_crashes)
                                            
                                            # Calculate execution speed
                                            current_time = time.time()
                                            elapsed_time = current_time - start_time
                                            exec_per_sec = current_iter / elapsed_time if elapsed_time > 0 else 0
                                            
                                            # Emit progress and stats updates
                                            self.progress_updated.emit(current_iter, self.iterations, total_crashes)
                                            
                                            # Emit real-time statistics
                                            stats = {
                                                'total_executions': current_iter,
                                                'total_crashes': total_crashes,
                                                'crash_rate': (total_crashes / max(current_iter, 1)) * 100,
                                                'exec_per_sec': exec_per_sec
                                            }
                                            self.stats_updated.emit(stats)
                                            
                                            # Add small delay to allow UI to update
                                            QThread.msleep(5)
                                    except (ValueError, IndexError) as e:
                                        # Silently handle parsing errors
                                        pass
                                            
                                
                                # Parse crash details from CRASH SUMMARY section
                                if "] Address:" in output:
                                    # New crash entry: [965] Address: 0x100005860
                                    try:
                                        address_part = output.split("Address:")[1].strip()
                                        crash_info = {
                                            "address": address_part,
                                            "signal": "Unknown",
                                            "count": "1",
                                            "type": "Unknown",
                                            "severity": "Unknown",
                                            "assembly": [],
                                            "in_assembly_section": False
                                        }
                                        crash_details.append(crash_info)
                                        # Emit real-time crash update
                                        self.crash_updated.emit(crash_info)
                                    except (IndexError, ValueError):
                                        pass
                                elif "Signal:" in output and crash_details and not "] Address:" in output:
                                    # Signal: 6 (not part of a new address entry)
                                    try:
                                        signal_part = output.split("Signal:")[1].strip()
                                        crash_details[-1]["signal"] = signal_part
                                        
                                        # Map signal number to name and severity
                                        try:
                                            signal_num = int(signal_part)
                                            if signal_num == 5:
                                                crash_details[-1]["type"] = "SIGTRAP"
                                                crash_details[-1]["severity"] = "MEDIUM"
                                            elif signal_num == 6:
                                                crash_details[-1]["type"] = "SIGABRT"
                                                crash_details[-1]["severity"] = "HIGH"
                                            elif signal_num == 11:
                                                crash_details[-1]["type"] = "SIGSEGV"
                                                crash_details[-1]["severity"] = "CRITICAL"
                                            elif signal_num == 4:
                                                crash_details[-1]["type"] = "SIGILL"
                                                crash_details[-1]["severity"] = "CRITICAL"
                                            else:
                                                crash_details[-1]["type"] = f"Signal {signal_num}"
                                                crash_details[-1]["severity"] = "UNKNOWN"
                                            
                                            # Emit updated crash info
                                            self.crash_updated.emit(crash_details[-1])
                                        except ValueError:
                                            pass
                                    except (IndexError, ValueError):
                                        pass
                                elif "Count:" in output and "occurrences" in output and crash_details:
                                    # Count: 1 occurrences
                                    try:
                                        count_part = output.split("Count:")[1].split("occurrences")[0].strip()
                                        crash_details[-1]["count"] = count_part
                                    except (IndexError, ValueError):
                                        pass
                                elif "Type:" in output and crash_details:
                                    # Type: SIGABRT - Program abort
                                    try:
                                        type_part = output.split("Type:")[1].strip()
                                        crash_details[-1]["type"] = type_part
                                    except (IndexError, ValueError):
                                        pass
                                elif "Severity:" in output and crash_details:
                                    # Severity: MEDIUM - Program termination
                                    try:
                                        severity_part = output.split("Severity:")[1].strip()
                                        crash_details[-1]["severity"] = severity_part
                                    except (IndexError, ValueError):
                                        pass
                                elif "Assembly context:" in output and crash_details:
                                    # Mark that we're entering assembly section
                                    crash_details[-1]["in_assembly_section"] = True
                                elif "(Showing first" in output and "lines of assembly)" in output and crash_details and crash_details[-1].get("in_assembly_section"):
                                    # Skip the informational line
                                    pass
                                elif crash_details and crash_details[-1].get("in_assembly_section"):
                                    # We're in assembly section, collect lines
                                    stripped = output.strip()
                                    if (stripped.startswith("0") and len(stripped) > 10 and '\t' in stripped) or \
                                       (stripped.startswith("_") and ":" in stripped):  # Function names like _main:
                                        # Assembly line: 0000000100000460	sub	sp, sp, #0x30 or _main:
                                        if "assembly" not in crash_details[-1]:
                                            crash_details[-1]["assembly"] = []
                                        crash_details[-1]["assembly"].append(stripped)
                                        
                                        # Don't emit here, only emit when assembly section is complete
                                    elif stripped.startswith("[") and "] Address:" in stripped:
                                        # End of assembly section, new crash started
                                        crash_details[-1]["in_assembly_section"] = False
                                        # Emit final update with all assembly
                                        self.crash_updated.emit(crash_details[-1])
                                # Parse from live crash table format - DIRECTLY ADD TO CRASH TABLE
                                elif "│" in output and "0x" in output:
                                    # Format: │165 │ 0x1000016a0 │ 6 │ 1 │ SIGABRT │ HIGH │ 18:33:05 │
                                    try:
                                        parts = output.split("│")
                                        if len(parts) >= 7:  # Ensure we have enough parts
                                            # Extract crash information
                                            crash_num = parts[1].strip()
                                            address = parts[2].strip()
                                            signal_str = parts[3].strip()
                                            count = parts[4].strip()
                                            crash_type = parts[5].strip()
                                            severity = parts[6].strip()
                                            time_str = parts[7].strip() if len(parts) > 7 else "Unknown"
                                            
                                            # Create crash info object
                                            if address.startswith("0x") and signal_str.isdigit():
                                                crash_info = {
                                                    "address": address,
                                                    "signal": signal_str,
                                                    "count": count,
                                                    "type": crash_type,
                                                    "severity": severity,
                                                    "time": time_str,
                                                    "assembly": [],
                                                    "in_assembly_section": False
                                                }
                                                
                                                # Add to crash details and emit real-time update
                                                crash_details.append(crash_info)
                                                self.crash_updated.emit(crash_info)
                                    except (IndexError, ValueError):
                                        pass
                                elif "END SUMMARY" in output or "fuzzing session complete" in output.lower():
                                    # Final progress update when END SUMMARY is reached
                                    # Ensure we have the final crash count
                                    if len(crash_details) > total_crashes:
                                        total_crashes = len(crash_details)
                                    
                                    # Force progress to 100%
                                    self.progress_updated.emit(self.iterations, self.iterations, total_crashes)
                                    
                                    # Emit final statistics
                                    final_time = time.time()
                                    total_elapsed = final_time - start_time
                                    final_stats = {
                                        'total_executions': self.iterations,
                                        'total_crashes': total_crashes,
                                        'crash_rate': (total_crashes / self.iterations) * 100 if self.iterations > 0 else 0,
                                        'exec_per_sec': 0,  # Set to 0 when complete
                                        'elapsed_time': total_elapsed
                                    }
                                    self.stats_updated.emit(final_stats)
                                elif "Total executions:" in output:
                                    # Parse final execution count from summary
                                    try:
                                        exec_count = int(output.split("Total executions:")[1].strip())
                                        current_iter = exec_count
                                    except:
                                        pass
                                elif "Total crashes:" in output:
                                    # Parse final crash count from summary - use TOTAL crashes, not unique
                                    try:
                                        crash_count_str = output.split("Total crashes:")[1].strip()
                                        crash_count = int(crash_count_str)
                                        total_crashes = crash_count  # Use total crashes, not unique
                                    except:
                                        pass
            
            # Parse final results - ensure accurate crash count
            final_crash_count = max(total_crashes, len(crash_details))
            results = {
                'total_executions': self.iterations,
                'total_crashes': final_crash_count,
                'crash_rate': (final_crash_count / self.iterations) * 100 if self.iterations > 0 else 0,
                'crash_details': crash_details,
                'output': '\n'.join(output_lines)
            }
            
            self.finished.emit(results)
            
        except Exception as e:
            self.output_updated.emit(f"Error: {str(e)}")

class CrashAnalysisTab(QWidget):
    """Tab for crash analysis and results"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Results summary
        summary_group = QGroupBox("Fuzzing Results Summary")
        summary_layout = QGridLayout()
        
        self.total_exec_label = QLabel("Total Executions: -")
        self.total_crashes_label = QLabel("Total Crashes: -")
        self.crash_rate_label = QLabel("Crash Rate: -%")
        self.exec_speed_label = QLabel("Exec/sec: -")
        
        summary_layout.addWidget(self.total_exec_label, 0, 0)
        summary_layout.addWidget(self.total_crashes_label, 0, 1)
        summary_layout.addWidget(self.crash_rate_label, 1, 0)
        summary_layout.addWidget(self.exec_speed_label, 1, 1)
        
        summary_group.setLayout(summary_layout)
        layout.addWidget(summary_group)
        
        # Crash details table
        crash_group = QGroupBox("Crash Analysis Details")
        crash_layout = QVBoxLayout()
        
        self.crash_table = QTableWidget()
        self.crash_table.setColumnCount(6)
        self.crash_table.setHorizontalHeaderLabels([
            "Address", "Signal", "Count", "Type", "Severity", "Time"
        ])
        
        crash_layout.addWidget(self.crash_table)
        crash_group.setLayout(crash_layout)
        layout.addWidget(crash_group)
        
        # Assembly code viewer
        asm_group = QGroupBox("Assembly Code Context")
        asm_layout = QVBoxLayout()
        
        self.assembly_text = QTextEdit()
        self.assembly_text.setFont(QFont("Courier", 10))
        self.assembly_text.setReadOnly(True)
        
        asm_layout.addWidget(self.assembly_text)
        asm_group.setLayout(asm_layout)
        layout.addWidget(asm_group)
        
        self.setLayout(layout)
    
    def update_results(self, results):
        """Update UI with fuzzing results"""
        self.total_exec_label.setText(f"Total Executions: {results.get('total_executions', 0)}")
        self.total_crashes_label.setText(f"Total Crashes: {results.get('total_crashes', 0)}")
        self.crash_rate_label.setText(f"Crash Rate: {results.get('crash_rate', 0):.2f}%")
        
        # Update crash table with detailed information (only if not already populated)
        crash_details = results.get('crash_details', [])
        if self.crash_table.rowCount() == 0:  # Only populate if empty
            self.crash_table.setRowCount(len(crash_details))
            
            for i, crash in enumerate(crash_details):
                # Address
                address = crash.get('address', 'Unknown')
                self.crash_table.setItem(i, 0, QTableWidgetItem(address))
                
                # Signal
                signal = crash.get('signal', 'Unknown')
                self.crash_table.setItem(i, 1, QTableWidgetItem(signal))
                
                # Count
                count = crash.get('count', '1')
                self.crash_table.setItem(i, 2, QTableWidgetItem(count))
                
                # Type
                crash_type = crash.get('type', 'Unknown')
                self.crash_table.setItem(i, 3, QTableWidgetItem(crash_type))
                
                # Severity
                severity = crash.get('severity', 'Unknown')
                self.crash_table.setItem(i, 4, QTableWidgetItem(severity))
                
                # Time
                time_info = crash.get('time', 'Unknown')
                self.crash_table.setItem(i, 5, QTableWidgetItem(time_info))
        
        # Update assembly viewer with ONLY assembly code and addresses
        self.update_assembly_context(results)
        
    def update_assembly_context(self, results):
        """Update assembly context with only addresses and assembly code"""
        crash_details = results.get('crash_details', [])
        assembly_lines = []
        
        # Collect all assembly contexts from all crashes
        for crash in crash_details:
            if crash.get('assembly'):
                assembly_lines.extend(crash['assembly'])
        
        if assembly_lines:
            # Filter and format assembly lines to show only addresses and assembly code
            formatted_lines = []
            for line in assembly_lines:
                # Clean up the line to show only address and assembly instruction
                if '\t' in line and (line.strip().startswith('0') or line.strip().startswith('_')):
                    if line.strip().startswith('_') and ':' in line:
                        # Function name like _main:
                        formatted_lines.append(line.strip())
                    elif line.strip().startswith('0'):
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            address = parts[0].strip()
                            instruction = '\t'.join(parts[1:]).strip()
                            formatted_lines.append(f"{address}\t{instruction}")
                elif line.strip() and (line.strip().startswith('0x') or (line.strip().startswith('_') and ':' in line)):
                    formatted_lines.append(line.strip())
            
            if formatted_lines:
                assembly_text = "Assembly Code Context:\n" + "="*60 + "\n"
                assembly_text += "Address\t\t\tInstruction\n"
                assembly_text += "-"*60 + "\n"
                assembly_text += '\n'.join(formatted_lines)
                self.assembly_text.setText(assembly_text)
            else:
                self.assembly_text.setText("No assembly context available.")
        else:
            self.assembly_text.setText("No assembly context available.")
            
    def add_crash_entry(self, crash_info):
        """Add a single crash entry to the table in real-time"""
        row = self.crash_table.rowCount()
        self.crash_table.insertRow(row)
        
        # Address
        address = crash_info.get('address', 'Unknown')
        self.crash_table.setItem(row, 0, QTableWidgetItem(address))
        
        # Signal
        signal = crash_info.get('signal', 'Unknown')
        self.crash_table.setItem(row, 1, QTableWidgetItem(signal))
        
        # Count
        count = crash_info.get('count', '1')
        self.crash_table.setItem(row, 2, QTableWidgetItem(count))
        
        # Type
        crash_type = crash_info.get('type', 'Unknown')
        self.crash_table.setItem(row, 3, QTableWidgetItem(crash_type))
        
        # Severity
        severity = crash_info.get('severity', 'Unknown')
        self.crash_table.setItem(row, 4, QTableWidgetItem(severity))
        
        # Time
        time_info = crash_info.get('time', 'Unknown')
        self.crash_table.setItem(row, 5, QTableWidgetItem(time_info))
        
        # Update assembly context if this crash has assembly info (but only if not recursing)
        if crash_info.get('assembly') and len(crash_info.get('assembly', [])) > 0:
            # Add recursion protection
            if not hasattr(self, '_updating_assembly') or not self._updating_assembly:
                self._updating_assembly = True
                try:
                    self.update_assembly_with_single_crash(crash_info)
                finally:
                    self._updating_assembly = False
            
    def update_assembly_with_single_crash(self, crash_info):
        """Update assembly context with a single crash's assembly info"""
        # Add extra recursion protection
        if hasattr(self, '_recursion_depth'):
            self._recursion_depth += 1
            if self._recursion_depth > 5:
                return
        else:
            self._recursion_depth = 1
            
        try:
            assembly_lines = crash_info.get('assembly', [])
            
            if assembly_lines:
                # Get current content
                current_text = self.assembly_text.toPlainText()
                
                # Format new assembly lines
                formatted_lines = []
                for line in assembly_lines:
                    # Handle assembly lines in format: 0000000100000460	sub	sp, sp, #0x30
                    if '\t' in line:
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            address = parts[0].strip()
                            instruction = '\t'.join(parts[1:]).strip()
                            formatted_lines.append(f"{address}\t{instruction}")
                    elif line.strip() and (line.strip().startswith('0x') or line.strip()[0].isdigit()):
                        formatted_lines.append(line.strip())
                
                # Update assembly text with only new assembly info
                if formatted_lines:
                    if "No assembly context available." in current_text or not current_text.strip():
                        # First assembly context
                        new_text = "Assembly Code Context:\n" + "="*60 + "\n"
                        new_text += "Address\t\t\tInstruction\n"
                        new_text += "-"*60 + "\n"
                        new_text += '\n'.join(formatted_lines)
                    else:
                        # Append new assembly context
                        new_text = current_text + "\n\n" + f"Crash at {crash_info.get('address', 'Unknown')}:\n"
                        new_text += '\n'.join(formatted_lines)
                    
                    self.assembly_text.setText(new_text)
                    
                    # Auto-scroll to bottom
                    scrollbar = self.assembly_text.verticalScrollBar()
                    scrollbar.setValue(scrollbar.maximum())
        finally:
            self._recursion_depth -= 1

class FuzzProGUI(QMainWindow):
    """Main GUI window for FuzzPro"""
    
    def __init__(self):
        super().__init__()
        self.fuzzing_worker = None
        self.init_ui()
        self.setup_style()
        
    def init_ui(self):
        self.setWindowTitle("FuzzPro - Professional Security Fuzzing Tool")
        self.setGeometry(100, 100, 1200, 800)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QHBoxLayout()
        
        # Left panel - Controls
        left_panel = self.create_control_panel()
        
        # Right panel - Results
        right_panel = self.create_results_panel()
        
        # Splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        
        main_layout.addWidget(splitter)
        central_widget.setLayout(main_layout)
        
    def create_control_panel(self):
        """Create the left control panel"""
        panel = QFrame()
        panel.setFrameStyle(QFrame.Shape.StyledPanel)
        panel.setMinimumWidth(350)
        
        layout = QVBoxLayout()
        
        # Header
        header_label = QLabel("FuzzPro Control Panel")
        header_label.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        header_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header_label)
        
        # Target selection
        target_group = QGroupBox("Target Configuration")
        target_layout = QVBoxLayout()
        
        target_row = QHBoxLayout()
        self.target_path = QLineEdit("./vulnerable_test")
        self.target_path.setPlaceholderText("Path to target binary...")
        target_browse = QPushButton("Browse")
        target_browse.clicked.connect(self.browse_target)
        target_row.addWidget(QLabel("Target:"))
        target_row.addWidget(self.target_path)
        target_row.addWidget(target_browse)
        target_layout.addLayout(target_row)
        
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)
        
        # Fuzzing parameters
        params_group = QGroupBox("Fuzzing Parameters")
        params_layout = QGridLayout()
        
        params_layout.addWidget(QLabel("Iterations:"), 0, 0)
        self.iterations_spin = QSpinBox()
        self.iterations_spin.setRange(1, 100000)
        self.iterations_spin.setValue(50)
        params_layout.addWidget(self.iterations_spin, 0, 1)
        
        # Add timeout setting
        params_layout.addWidget(QLabel("Timeout (sec):"), 1, 0)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 3600)
        self.timeout_spin.setValue(30)
        params_layout.addWidget(self.timeout_spin, 1, 1)
        
        # Add mutation intensity
        params_layout.addWidget(QLabel("Mutation Intensity:"), 2, 0)
        self.intensity_combo = QComboBox()
        self.intensity_combo.addItems(["1 (Low)", "2", "3", "4", "5 (Medium)", "6", "7", "8", "9", "10 (Aggressive)"])
        self.intensity_combo.setCurrentIndex(6)  # Default to 7
        self.intensity_combo.setToolTip("Set mutation intensity - higher values introduce more complex mutations")
        params_layout.addWidget(self.intensity_combo, 2, 1)
        
        # Add fuzzing mode (dropdown instead of checkbox)
        params_layout.addWidget(QLabel("Fuzzing Mode:"), 3, 0)
        self.fuzzing_mode_combo = QComboBox()
        self.fuzzing_mode_combo.addItems(["Classic Fuzzing", "Coverage-guided (ptrace)"])
        self.fuzzing_mode_combo.setToolTip("Choose fuzzing strategy - Coverage-guided mode uses dynamic instrumentation")
        params_layout.addWidget(self.fuzzing_mode_combo, 3, 1)
        
        params_group.setLayout(params_layout)
        layout.addWidget(params_group)
        
        # Progress section
        progress_group = QGroupBox("Fuzzing Progress")
        progress_layout = QVBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_label = QLabel("Ready to start fuzzing...")
        self.crash_count_label = QLabel("Crashes Found: 0")
        
        progress_layout.addWidget(self.progress_label)
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.crash_count_label)
        
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton("Start Fuzzing")
        self.start_button.clicked.connect(self.start_fuzzing)
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_fuzzing)
        
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        layout.addLayout(button_layout)
        
        layout.addStretch()
        panel.setLayout(layout)
        return panel
        
    def create_results_panel(self):
        """Create the right results panel"""
        panel = QFrame()
        panel.setFrameStyle(QFrame.Shape.StyledPanel)
        
        layout = QVBoxLayout()
        
        # Header
        header_label = QLabel("Fuzzing Results & Analysis")
        header_label.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        header_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header_label)
        
        # Tab widget
        self.tabs = QTabWidget()
        
        # Console output tab
        console_tab = QWidget()
        console_layout = QVBoxLayout()
        
        self.console_output = QTextEdit()
        self.console_output.setFont(QFont("Courier", 10))
        self.console_output.setReadOnly(True)
        
        console_layout.addWidget(self.console_output)
        console_tab.setLayout(console_layout)
        self.tabs.addTab(console_tab, "Console Output")
        
        # Crash analysis tab
        self.crash_analysis_tab = CrashAnalysisTab()
        self.tabs.addTab(self.crash_analysis_tab, "Crash Analysis")
        
        layout.addWidget(self.tabs)
        panel.setLayout(layout)
        return panel
        
    def setup_style(self):
        """Setup Ghidra-like dark theme styling"""
        self.setStyleSheet("""
            /* Main window styling */
            QMainWindow {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            
            /* Group box styling */
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cc3333;
                border-radius: 5px;
                margin-top: 1ex;
                padding-top: 10px;
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #cc3333;
            }
            
            /* Tab widget styling */
            QTabWidget::pane {
                border: 2px solid #cc3333;
                background-color: #1e1e1e;
            }
            QTabBar::tab {
                background-color: #2b2b2b;
                color: #ffffff;
                padding: 8px 16px;
                margin-right: 2px;
                border: 1px solid #666666;
            }
            QTabBar::tab:selected {
                background-color: #cc3333;
                color: #ffffff;
                border-bottom: 2px solid #cc3333;
            }
            QTabBar::tab:hover {
                background-color: #aa2222;
            }
            
            /* Button styling */
            QPushButton {
                background-color: #cc3333;
                color: #ffffff;
                border: 1px solid #cc3333;
                padding: 8px 16px;
                font-weight: bold;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #aa2222;
            }
            QPushButton:pressed {
                background-color: #882222;
            }
            QPushButton:disabled {
                background-color: #555555;
                color: #888888;
                border: 1px solid #555555;
            }
            
            /* Input field styling */
            QLineEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #666666;
                padding: 5px;
                border-radius: 3px;
            }
            QLineEdit:focus {
                border: 2px solid #cc3333;
            }
            
            /* Spin box styling */
            QSpinBox {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #666666;
                padding: 5px;
                border-radius: 3px;
            }
            QSpinBox:focus {
                border: 2px solid #cc3333;
            }
            
            /* Progress bar styling */
            QProgressBar {
                border: 1px solid #666666;
                border-radius: 3px;
                text-align: center;
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QProgressBar::chunk {
                background-color: #cc3333;
                border-radius: 3px;
            }
            
            /* Text edit styling */
            QTextEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #666666;
                selection-background-color: #cc3333;
            }
            
            /* Table styling */
            QTableWidget {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #666666;
                gridline-color: #666666;
                selection-background-color: #cc3333;
            }
            QHeaderView::section {
                background-color: #2b2b2b;
                color: #ffffff;
                border: 1px solid #666666;
                padding: 5px;
                font-weight: bold;
            }
            
            /* Label styling */
            QLabel {
                color: #ffffff;
            }
            
            /* Frame styling */
            QFrame {
                background-color: #2b2b2b;
                border: 1px solid #666666;
            }
        """)
        
    def browse_target(self):
        """Browse for target binary"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Target Binary", "", "Executable Files (*)")
        if file_path:
            self.target_path.setText(file_path)
            
    def start_fuzzing(self):
        """Start fuzzing campaign"""
        target = self.target_path.text().strip()
        iterations = self.iterations_spin.value()
        timeout = self.timeout_spin.value()
        
        # Get mutation intensity value from combobox
        intensity_text = self.intensity_combo.currentText()
        intensity = intensity_text.split()[0]  # Get the numeric part (e.g. "7" from "7 (High)")
        
        # Get fuzzing mode from dropdown instead of checkbox
        fuzzing_mode = self.fuzzing_mode_combo.currentText()
        
        if not target:
            self.console_output.append("Error: Please specify target path")
            return
            
        if not os.path.exists(target):
            self.console_output.append(f"Error: Target binary not found: {target}")
            return
            
        # Clear previous results
        self.crash_analysis_tab.crash_table.setRowCount(0)
        self.crash_analysis_tab.assembly_text.clear()
        
        # Reset results summary
        self.crash_analysis_tab.total_exec_label.setText("Total Executions: 0")
        self.crash_analysis_tab.total_crashes_label.setText("Total Crashes: 0")
        self.crash_analysis_tab.crash_rate_label.setText("Crash Rate: 0.00%")
        self.crash_analysis_tab.exec_speed_label.setText("Exec/sec: 0")
            
        # Update UI state
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setRange(0, iterations)
        self.progress_bar.setValue(0)
        
        self.progress_label.setText(f"Starting {fuzzing_mode} with {iterations} iterations...")
        self.console_output.clear()
        
        # Start fuzzing worker with selected fuzzing mode
        self.fuzzing_worker = FuzzingWorker(target, iterations, timeout, intensity, fuzzing_mode)
        self.fuzzing_worker.progress_updated.connect(self.update_progress)
        self.fuzzing_worker.output_updated.connect(self.update_console)
        self.fuzzing_worker.crash_updated.connect(self.update_crash_table)
        self.fuzzing_worker.stats_updated.connect(self.update_stats)
        self.fuzzing_worker.finished.connect(self.fuzzing_completed)
        self.fuzzing_worker.start()
        
    def stop_fuzzing(self):
        """Stop fuzzing campaign"""
        if self.fuzzing_worker and self.fuzzing_worker.isRunning():
            self.fuzzing_worker.terminate()
            self.fuzzing_worker.wait()
            
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_label.setText("Fuzzing stopped by user")
        self.console_output.append("Fuzzing campaign stopped by user")
        
    def update_stats(self, stats):
        """Update real-time fuzzing statistics"""
        # Update the results summary in real-time
        self.crash_analysis_tab.total_exec_label.setText(f"Total Executions: {stats.get('total_executions', 0)}")
        self.crash_analysis_tab.total_crashes_label.setText(f"Total Crashes: {stats.get('total_crashes', 0)}")
        self.crash_analysis_tab.crash_rate_label.setText(f"Crash Rate: {stats.get('crash_rate', 0):.2f}%")
        
        # Update exec/sec - show "Executing" during fuzzing, 0 when complete
        exec_per_sec = stats.get('exec_per_sec', 0)
        if exec_per_sec > 0:
            self.crash_analysis_tab.exec_speed_label.setText(f"Exec/sec: {exec_per_sec:.1f} (Executing)")
        else:
            self.crash_analysis_tab.exec_speed_label.setText(f"Exec/sec: 0 (Complete)")
        
    def update_progress(self, current, total, crashes):
        """Update progress bar and labels"""
        # Calculate percentage safely to prevent division by zero
        percentage = (current/max(total, 1))*100 if total > 0 else 0
        
        # Update progress bar with correct range
        if self.progress_bar.maximum() != total:
            self.progress_bar.setRange(0, total)
        
        # Set value with bounds checking
        if current <= total:
            self.progress_bar.setValue(current)
        
        # Update labels with real-time information
        self.progress_label.setText(f"Progress: {current}/{total} iterations ({percentage:.1f}%)")
        self.crash_count_label.setText(f"Crashes Found: {crashes}")
        
    def update_console(self, line):
        """Update console output"""
        self.console_output.append(line)
        # Auto-scroll to bottom
        scrollbar = self.console_output.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
        
    def update_crash_table(self, crash_info):
        """Update crash table in real-time"""
        try:
            self.crash_analysis_tab.add_crash_entry(crash_info)
            # Force UI update to show the new crash immediately
            QApplication.processEvents()
        except RecursionError as e:
            # Handle recursion error gracefully
            print(f"Recursion error in crash table update: {e}")
            # Stop the worker to prevent further crashes
            if self.fuzzing_worker and self.fuzzing_worker.isRunning():
                self.fuzzing_worker.terminate()
        except Exception as e:
            print(f"Error updating crash table: {e}")
            pass
        
    def fuzzing_completed(self, results):
        """Handle fuzzing completion"""
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
        # Update final progress
        total_exec = results.get('total_executions', 0)
        total_crashes = results.get('total_crashes', 0)
        crash_rate = results.get('crash_rate', 0)
        
        # Show final console output - only the basic completion info
        self.console_output.append("==================== FUZZING COMPLETE ====================")
        self.console_output.append(f"Total executions: {total_exec}")
        self.console_output.append(f"Total crashes: {total_crashes}")
        self.console_output.append(f"Crash rate: {crash_rate:.2f}%")
        self.console_output.append("=" * 60)
        
        # Final progress update
        self.progress_label.setText(f"Fuzzing Complete! {total_crashes} crashes found ({crash_rate:.2f}% rate)")
        self.crash_count_label.setText(f"Final Crashes: {total_crashes}")
        
        # Update crash analysis tab
        self.crash_analysis_tab.update_results(results)
        
        # Switch to crash analysis tab if crashes were found
        if total_crashes > 0:
            self.tabs.setCurrentIndex(1)
            self.console_output.append(f"Found {total_crashes} crashes! Check the Crash Analysis tab for details.")
        else:
            self.console_output.append("No crashes found during fuzzing session.")

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("FuzzPro GUI")
    app.setApplicationVersion("1.0")
    
    # Set application icon if available
    try:
        app.setWindowIcon(QIcon("fuzzpro_icon.png"))
    except:
        pass
    
    window = FuzzProGUI()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
