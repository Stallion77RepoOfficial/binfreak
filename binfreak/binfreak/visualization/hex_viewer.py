"""
Professional hex viewer widget for binary analysis
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QScrollBar,
    QLabel, QLineEdit, QPushButton, QCheckBox, QSpinBox
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QTextCursor, QColor, QTextCharFormat
from typing import Optional


class HexViewer(QWidget):
    """Professional hex viewer with annotations and search"""
    
    address_changed = pyqtSignal(int)
    selection_changed = pyqtSignal(int, int)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.data = b''
        self.current_offset = 0
        self.bytes_per_line = 16
        self.annotations = {}  # offset -> annotation text
        self.highlighted_ranges = []  # [(start, end, color), ...]
        
        self.init_ui()
        self.setup_formatting()
    
    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout(self)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        # Offset input
        controls_layout.addWidget(QLabel("Offset:"))
        self.offset_input = QLineEdit()
        self.offset_input.setPlaceholderText("0x1000")
        self.offset_input.returnPressed.connect(self.goto_offset)
        controls_layout.addWidget(self.offset_input)
        
        # Go button
        goto_button = QPushButton("Go")
        goto_button.clicked.connect(self.goto_offset)
        controls_layout.addWidget(goto_button)
        
        # Bytes per line
        controls_layout.addWidget(QLabel("Bytes/line:"))
        self.bytes_per_line_spin = QSpinBox()
        self.bytes_per_line_spin.setRange(8, 32)
        self.bytes_per_line_spin.setValue(16)
        self.bytes_per_line_spin.valueChanged.connect(self.set_bytes_per_line)
        controls_layout.addWidget(self.bytes_per_line_spin)
        
        # Search
        controls_layout.addWidget(QLabel("Search:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("hex bytes or string")
        self.search_input.returnPressed.connect(self.search)
        controls_layout.addWidget(self.search_input)
        
        search_button = QPushButton("Search")
        search_button.clicked.connect(self.search)
        controls_layout.addWidget(search_button)
        
        # Show annotations checkbox
        self.show_annotations_cb = QCheckBox("Show Annotations")
        self.show_annotations_cb.setChecked(True)
        self.show_annotations_cb.toggled.connect(self.refresh_display)
        controls_layout.addWidget(self.show_annotations_cb)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        # Hex display area
        self.hex_display = QTextEdit()
        self.hex_display.setFont(QFont("Courier", 10))
        self.hex_display.setReadOnly(True)
        self.hex_display.cursorPositionChanged.connect(self.on_cursor_changed)
        layout.addWidget(self.hex_display)
        
        # Status bar
        status_layout = QHBoxLayout()
        self.status_label = QLabel("No data loaded")
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        self.selection_label = QLabel("")
        status_layout.addWidget(self.selection_label)
        layout.addLayout(status_layout)
    
    def setup_formatting(self):
        """Setup text formatting for different data types"""
        self.format_offset = QTextCharFormat()
        self.format_offset.setForeground(QColor(100, 100, 100))
        
        self.format_hex_normal = QTextCharFormat()
        self.format_hex_normal.setForeground(QColor(0, 0, 0))
        
        self.format_hex_string = QTextCharFormat()
        self.format_hex_string.setForeground(QColor(0, 100, 200))
        
        self.format_hex_code = QTextCharFormat()
        self.format_hex_code.setForeground(QColor(200, 0, 0))
        
        self.format_ascii = QTextCharFormat()
        self.format_ascii.setForeground(QColor(0, 150, 0))
        
        self.format_annotation = QTextCharFormat()
        self.format_annotation.setForeground(QColor(150, 0, 150))
    
    def set_data(self, data: bytes):
        """Set binary data to display"""
        self.data = data
        self.current_offset = 0
        self.refresh_display()
        self.status_label.setText(f"Data size: {len(data):,} bytes")
    
    def set_bytes_per_line(self, bytes_per_line: int):
        """Set number of bytes to display per line"""
        self.bytes_per_line = bytes_per_line
        self.refresh_display()
    
    def goto_offset(self):
        """Go to specific offset"""
        offset_text = self.offset_input.text().strip()
        if not offset_text:
            return
        
        try:
            if offset_text.startswith('0x'):
                offset = int(offset_text, 16)
            else:
                offset = int(offset_text)
            
            if 0 <= offset < len(self.data):
                self.current_offset = offset
                self.refresh_display()
                self.address_changed.emit(offset)
            else:
                self.status_label.setText(f"Offset {offset:x} out of range")
        
        except ValueError:
            self.status_label.setText("Invalid offset format")
    
    def search(self):
        """Search for pattern in data"""
        pattern_text = self.search_input.text().strip()
        if not pattern_text or not self.data:
            return
        
        # Try to parse as hex first
        try:
            if ' ' in pattern_text:
                # Space-separated hex bytes
                hex_bytes = pattern_text.split()
                pattern = bytes(int(b, 16) for b in hex_bytes)
            elif len(pattern_text) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in pattern_text):
                # Continuous hex string
                pattern = bytes.fromhex(pattern_text)
            else:
                # Treat as string
                pattern = pattern_text.encode('utf-8')
        except ValueError:
            # Fallback to string search
            pattern = pattern_text.encode('utf-8')
        
        # Search in data
        pos = self.data.find(pattern, self.current_offset + 1)
        if pos != -1:
            self.current_offset = pos
            self.refresh_display()
            self.highlight_range(pos, pos + len(pattern), QColor(255, 255, 0))
            self.status_label.setText(f"Found at offset 0x{pos:x}")
        else:
            self.status_label.setText("Pattern not found")
    
    def highlight_range(self, start: int, end: int, color: QColor):
        """Highlight a range of bytes"""
        self.highlighted_ranges.append((start, end, color))
        self.refresh_display()
    
    def add_annotation(self, offset: int, text: str):
        """Add annotation at specific offset"""
        self.annotations[offset] = text
        self.refresh_display()
    
    def clear_annotations(self):
        """Clear all annotations"""
        self.annotations.clear()
        self.refresh_display()
    
    def clear_highlights(self):
        """Clear all highlights"""
        self.highlighted_ranges.clear()
        self.refresh_display()
    
    def refresh_display(self):
        """Refresh the hex display"""
        if not self.data:
            self.hex_display.clear()
            return
        
        # Calculate display range
        start_offset = max(0, self.current_offset - 512)  # Show some context before
        end_offset = min(len(self.data), start_offset + 2048)  # Show 2KB
        
        # Align start to line boundary
        start_offset = (start_offset // self.bytes_per_line) * self.bytes_per_line
        
        display_text = []
        
        for offset in range(start_offset, end_offset, self.bytes_per_line):
            line_data = self.data[offset:offset + self.bytes_per_line]
            if not line_data:
                break
            
            # Format offset
            offset_str = f"{offset:08x}"
            
            # Format hex bytes
            hex_parts = []
            ascii_parts = []
            
            for i, byte in enumerate(line_data):
                current_offset = offset + i
                
                # Determine color based on content type
                hex_color = self.get_byte_color(current_offset, byte)
                
                hex_parts.append(f"{byte:02x}")
                
                # ASCII representation
                if 32 <= byte <= 126:
                    ascii_parts.append(chr(byte))
                else:
                    ascii_parts.append('.')
            
            # Pad hex part if line is not full
            while len(hex_parts) < self.bytes_per_line:
                hex_parts.append('  ')
                ascii_parts.append(' ')
            
            hex_str = ' '.join(hex_parts)
            ascii_str = ''.join(ascii_parts)
            
            line = f"{offset_str}  {hex_str}  |{ascii_str}|"
            
            # Add annotation if present
            if self.show_annotations_cb.isChecked() and offset in self.annotations:
                line += f"  ; {self.annotations[offset]}"
            
            display_text.append(line)
        
        self.hex_display.setPlainText('\\n'.join(display_text))
        
        # Highlight current offset line
        self.highlight_current_line()
    
    def get_byte_color(self, offset: int, byte: int) -> str:
        """Get color for byte based on context"""
        # Check if byte is in a highlighted range
        for start, end, color in self.highlighted_ranges:
            if start <= offset < end:
                return f"background-color: {color.name()};"
        
        # Default color based on byte value
        if 32 <= byte <= 126:  # Printable ASCII
            return "color: #006600;"
        elif byte == 0:  # Null bytes
            return "color: #cccccc;"
        else:  # Binary data
            return "color: #000000;"
    
    def highlight_current_line(self):
        """Highlight the line containing current offset"""
        cursor = self.hex_display.textCursor()
        
        # Find line containing current offset
        current_line_offset = (self.current_offset // self.bytes_per_line) * self.bytes_per_line
        text = self.hex_display.toPlainText()
        lines = text.split('\\n')
        
        for i, line in enumerate(lines):
            if line.startswith(f"{current_line_offset:08x}"):
                # Move cursor to this line
                cursor.movePosition(QTextCursor.MoveOperation.Start)
                for _ in range(i):
                    cursor.movePosition(QTextCursor.MoveOperation.Down)
                
                # Select the line
                cursor.select(QTextCursor.SelectionType.LineUnderCursor)
                self.hex_display.setTextCursor(cursor)
                break
    
    def on_cursor_changed(self):
        """Handle cursor position changes"""
        cursor = self.hex_display.textCursor()
        line_number = cursor.blockNumber()
        
        # Calculate offset based on line number
        text = self.hex_display.toPlainText()
        lines = text.split('\\n')
        
        if line_number < len(lines):
            line = lines[line_number]
            if len(line) >= 8:
                try:
                    line_offset = int(line[:8], 16)
                    
                    # Calculate byte position within line
                    column = cursor.columnNumber()
                    if 10 <= column <= 58:  # In hex area
                        byte_in_line = (column - 10) // 3
                        if byte_in_line < self.bytes_per_line:
                            offset = line_offset + byte_in_line
                            if offset < len(self.data):
                                byte_value = self.data[offset]
                                self.selection_label.setText(
                                    f"Offset: 0x{offset:x} ({offset}) "
                                    f"Byte: 0x{byte_value:02x} ({byte_value}) "
                                    f"ASCII: {chr(byte_value) if 32 <= byte_value <= 126 else '.'}"
                                )
                                return
                except ValueError:
                    pass
        
        self.selection_label.setText("")
    
    def export_selection(self, start: int, end: int) -> bytes:
        """Export selected range as bytes"""
        if 0 <= start < len(self.data) and 0 <= end <= len(self.data) and start < end:
            return self.data[start:end]
        return b''
    
    def get_current_offset(self) -> int:
        """Get current display offset"""
        return self.current_offset
    
    def get_data_size(self) -> int:
        """Get total data size"""
        return len(self.data)