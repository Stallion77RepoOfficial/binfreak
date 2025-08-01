"""
Advanced visualization components for binary analysis
"""

import math
from typing import Dict, Any, List, Tuple

try:
    from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, 
                                QLabel, QScrollArea, QSplitter)
    from PyQt6.QtCore import Qt, QTimer
    from PyQt6.QtGui import QPainter, QPen, QColor, QFont
except ImportError:
    print("PyQt6 required for GUI components")


class AdvancedVisualizationWidget(QWidget):
    """Advanced visualization widget for binary analysis"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.binary_data = None
        self.visualization_data = {}
        
    def init_ui(self):
        """Initialize the visualization UI"""
        layout = QVBoxLayout()
        
        # Create splitter for multiple views
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Entropy visualization
        self.entropy_widget = EntropyVisualizationWidget()
        splitter.addWidget(self.entropy_widget)
        
        # Function call graph
        self.call_graph_widget = CallGraphWidget()
        splitter.addWidget(self.call_graph_widget)
        
        # Memory layout
        self.memory_widget = MemoryLayoutWidget()
        splitter.addWidget(self.memory_widget)
        
        layout.addWidget(splitter)
        self.setLayout(layout)
    
    def update_visualization(self, analysis_data: Dict[str, Any]):
        """Update all visualization components"""
        self.entropy_widget.update_data(analysis_data.get('entropy', []))
        self.call_graph_widget.update_data(analysis_data.get('functions', []))
        self.memory_widget.update_data(analysis_data.get('sections', []))


class EntropyVisualizationWidget(QWidget):
    """Widget for displaying entropy visualization"""
    
    def __init__(self):
        super().__init__()
        self.entropy_data = []
        self.setMinimumSize(300, 200)
        
    def update_data(self, entropy_data: List[float]):
        """Update entropy data"""
        # If no real entropy data, generate from binary analysis
        if not entropy_data and hasattr(self, 'binary_data'):
            from ..analysis.entropy_calculator import EntropyCalculator
            calculator = EntropyCalculator()
            entropy_data = calculator.calculate_entropy_blocks(self.binary_data)
        
        self.entropy_data = entropy_data[:1000] if entropy_data else []
        self.update()
    
    def set_binary_data(self, data: bytes):
        """Set binary data for entropy calculation"""
        self.binary_data = data
        if data:
            from ..analysis.entropy_calculator import EntropyCalculator
            calculator = EntropyCalculator()
            entropy_data = calculator.calculate_entropy_blocks(data)
            self.update_data(entropy_data)
    
    def paintEvent(self, event):
        """Paint the entropy visualization"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        if not self.entropy_data:
            # Show placeholder with instructions
            painter.setPen(QPen(QColor(255, 255, 255)))
            painter.setFont(QFont("Arial", 14))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, 
                           "Load a binary file to see entropy analysis")
            return
        
        width = self.width()
        height = self.height()
        
        # Draw background
        painter.fillRect(self.rect(), QColor(30, 30, 30))
        
        # Draw entropy graph
        if len(self.entropy_data) > 1:
            pen = QPen(QColor(0, 255, 0), 2)
            painter.setPen(pen)
            
            x_step = width / len(self.entropy_data)
            max_entropy = max(self.entropy_data) if self.entropy_data else 1
            
            for i in range(len(self.entropy_data) - 1):
                x1 = i * x_step
                y1 = height - (self.entropy_data[i] / max_entropy * height)
                x2 = (i + 1) * x_step
                y2 = height - (self.entropy_data[i + 1] / max_entropy * height)
                
                painter.drawLine(int(x1), int(y1), int(x2), int(y2))
        
        # Draw title
        painter.setPen(QPen(QColor(255, 255, 255)))
        painter.setFont(QFont("Arial", 12))
        painter.drawText(10, 20, "Entropy Analysis")


class CallGraphWidget(QWidget):
    """Widget for displaying function call graph"""
    
    def __init__(self):
        super().__init__()
        self.functions = []
        self.setMinimumSize(300, 200)
        
    def update_data(self, functions: List[Dict[str, Any]]):
        """Update function data"""
        self.functions = functions[:50]  # Limit for performance
        self.update()
    
    def paintEvent(self, event):
        """Paint the call graph"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Draw background
        painter.fillRect(self.rect(), QColor(20, 20, 20))
        
        if not self.functions:
            painter.setPen(QPen(QColor(255, 255, 255)))
            painter.setFont(QFont("Arial", 14))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, 
                           "Load a binary file to see function call graph")
            return
        
        # Draw function nodes
        painter.setPen(QPen(QColor(100, 150, 255), 2))
        painter.setBrush(QColor(50, 75, 150))
        
        width = self.width()
        height = self.height()
        
        # Simple grid layout for functions
        cols = int(math.sqrt(len(self.functions))) + 1
        rows = (len(self.functions) + cols - 1) // cols
        
        cell_width = width // cols
        cell_height = height // rows
        
        for i, func in enumerate(self.functions):
            row = i // cols
            col = i % cols
            
            x = col * cell_width + 10
            y = row * cell_height + 10
            
            # Draw function box
            painter.drawRect(x, y, min(cell_width - 20, 80), min(cell_height - 20, 30))
            
            # Draw function name
            painter.setPen(QPen(QColor(255, 255, 255)))
            painter.setFont(QFont("Arial", 8))
            func_name = func.get('name', f"func_{i}")[:10]
            painter.drawText(x + 5, y + 20, func_name)
            
            painter.setPen(QPen(QColor(100, 150, 255), 2))
        
        # Draw title
        painter.setPen(QPen(QColor(255, 255, 255)))
        painter.setFont(QFont("Arial", 12))
        painter.drawText(10, 20, "Call Graph")


class MemoryLayoutWidget(QWidget):
    """Widget for displaying memory layout"""
    
    def __init__(self):
        super().__init__()
        self.sections = []
        self.setMinimumSize(300, 200)
        
    def update_data(self, sections: List[Dict[str, Any]]):
        """Update section data"""
        self.sections = sections
        self.update()
    
    def paintEvent(self, event):
        """Paint the memory layout"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Draw background
        painter.fillRect(self.rect(), QColor(25, 25, 25))
        
        if not self.sections:
            painter.setPen(QPen(QColor(255, 255, 255)))
            painter.setFont(QFont("Arial", 14)) 
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                           "Load a binary file to see memory layout")
            return
        
        width = self.width()
        height = self.height()
        
        # Calculate total size for scaling
        total_size = sum(section.get('size', 0) for section in self.sections)
        if total_size == 0:
            return
        
        # Draw memory sections
        y_offset = 30
        available_height = height - 50
        
        colors = [
            QColor(255, 100, 100),  # Red
            QColor(100, 255, 100),  # Green
            QColor(100, 100, 255),  # Blue
            QColor(255, 255, 100),  # Yellow
            QColor(255, 100, 255),  # Magenta
            QColor(100, 255, 255),  # Cyan
        ]
        
        for i, section in enumerate(self.sections):
            section_size = section.get('size', 0)
            section_height = int((section_size / total_size) * available_height)
            
            color = colors[i % len(colors)]
            painter.setBrush(color)
            painter.setPen(QPen(QColor(255, 255, 255), 1))
            
            # Draw section rectangle
            painter.drawRect(50, y_offset, width - 100, section_height)
            
            # Draw section label
            painter.setPen(QPen(QColor(0, 0, 0)))
            painter.setFont(QFont("Arial", 10, QFont.Weight.Bold))
            section_name = section.get('name', f"Section {i}")
            painter.drawText(55, y_offset + section_height // 2, section_name)
            
            y_offset += section_height
        
        # Draw title
        painter.setPen(QPen(QColor(255, 255, 255)))
        painter.setFont(QFont("Arial", 12))
        painter.drawText(10, 20, "Memory Layout")


class VisualizationManager:
    """Manager for all visualization components"""
    
    def __init__(self):
        self.widgets = {}
        
    def create_visualization_widget(self) -> AdvancedVisualizationWidget:
        """Create and return a new visualization widget"""
        widget = AdvancedVisualizationWidget()
        widget_id = id(widget)
        self.widgets[widget_id] = widget
        return widget
    
    def update_all_visualizations(self, analysis_data: Dict[str, Any]):
        """Update all visualization widgets"""
        for widget in self.widgets.values():
            widget.update_visualization(analysis_data)
    
    def remove_widget(self, widget: AdvancedVisualizationWidget):
        """Remove widget from manager"""
        widget_id = id(widget)
        if widget_id in self.widgets:
            del self.widgets[widget_id]
