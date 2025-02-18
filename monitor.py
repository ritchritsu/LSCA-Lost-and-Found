import psutil
import time
from datetime import datetime
import threading
import csv
from pathlib import Path
import os
import statistics
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter

class SystemMonitor:
    def __init__(self, interval=1):
        self.interval = interval
        self.monitoring = False
        self.metrics = []
        self.start_time = None
        self.peak_metrics = {
            'cpu': 0,
            'memory': 0,
            'disk_io': 0
        }
        
    def collect_metrics(self):
        """Collect system metrics"""
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.Process().memory_info()
        disk_io = psutil.disk_io_counters()
        
        metrics = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'cpu_percent': cpu_percent,
            'memory_rss': memory.rss / 1024 / 1024,  # MB
            'memory_vms': memory.vms / 1024 / 1024,  # MB
            'disk_read_mb': disk_io.read_bytes / 1024 / 1024,  # MB
            'disk_write_mb': disk_io.write_bytes / 1024 / 1024,  # MB
            'disk_read_count': disk_io.read_count,
            'disk_write_count': disk_io.write_count
        }
        
        # Update peak metrics
        self.peak_metrics['cpu'] = max(self.peak_metrics['cpu'], cpu_percent)
        self.peak_metrics['memory'] = max(self.peak_metrics['memory'], metrics['memory_rss'])
        self.peak_metrics['disk_io'] = max(
            self.peak_metrics['disk_io'], 
            metrics['disk_read_mb'] + metrics['disk_write_mb']
        )
        
        return metrics
    
    def monitor(self):
        """Monitor system continuously"""
        while self.monitoring:
            metrics = self.collect_metrics()
            self.metrics.append(metrics)
            time.sleep(self.interval)
    
    def start(self):
        """Start monitoring"""
        self.monitoring = True
        self.start_time = datetime.now()
        self.monitor_thread = threading.Thread(target=self.monitor)
        self.monitor_thread.start()
        print("Monitoring started...")
    
    def stop(self):
        """Stop monitoring and save results"""
        self.monitoring = False
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join()
        
        # Create results directory if it doesn't exist
        results_dir = Path('monitoring_results')
        results_dir.mkdir(exist_ok=True)
        
        # Save metrics to CSV
        filename = results_dir / f'metrics_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.metrics[0].keys())
            writer.writeheader()
            writer.writerows(self.metrics)
        
        print(f"Monitoring stopped. Results saved to {filename}")
        self.analyze_results()
    
    def analyze_results(self):
        """Analyze collected metrics"""
        if not self.metrics:
            print("No metrics collected")
            return
        
        # Calculate statistics
        cpu_values = [m['cpu_percent'] for m in self.metrics]
        memory_values = [m['memory_rss'] for m in self.metrics]
        disk_read = [m['disk_read_mb'] for m in self.metrics]
        disk_write = [m['disk_write_mb'] for m in self.metrics]
        
        analysis = {
            'duration': f"{(datetime.now() - self.start_time).total_seconds():.2f} seconds",
            'cpu_avg': f"{sum(cpu_values)/len(cpu_values):.2f}%",
            'cpu_max': f"{max(cpu_values):.2f}%",
            'memory_avg': f"{sum(memory_values)/len(memory_values):.2f} MB",
            'memory_max': f"{max(memory_values)::.2f} MB",
            'disk_read_total': f"{max(disk_read):.2f} MB",
            'disk_write_total': f"{max(disk_write):.2f} MB"
        }
        
        print("\nPerformance Analysis:")
        print("-" * 50)
        for key, value in analysis.items():
            print(f"{key.replace('_', ' ').title()}: {value}")

    def analyze_performance(self):
        """Analyze collected metrics and generate insights"""
        if not self.metrics:
            return "No metrics collected"

        cpu_values = [m['cpu_percent'] for m in self.metrics]
        memory_values = [m['memory_rss'] for m in self.metrics]
        disk_read = [m['disk_read_mb'] for m in self.metrics]
        disk_write = [m['disk_write_mb'] for m in self.metrics]

        analysis = {
            'General': {
                'Monitoring Duration': f"{(datetime.now() - self.start_time).total_seconds():.2f} seconds",
                'Total Samples': len(self.metrics)
            },
            'CPU Analysis': {
                'Average CPU Usage': f"{statistics.mean(cpu_values):.2f}%",
                'Peak CPU Usage': f"{max(cpu_values):.2f}%",
                'CPU Usage Variance': f"{statistics.variance(cpu_values):.2f}"
            },
            'Memory Analysis': {
                'Average Memory Usage': f"{statistics.mean(memory_values):.2f} MB",
                'Peak Memory Usage': f"{max(memory_values):.2f} MB",
                'Memory Growth Rate': f"{(memory_values[-1] - memory_values[0]) / len(memory_values):.2f} MB/sample"
            },
            'Disk I/O Analysis': {
                'Total Read': f"{max(disk_read):.2f} MB",
                'Total Write': f"{max(disk_write):.2f} MB",
                'I/O Operations': f"{sum([m['disk_read_count'] + m['disk_write_count'] for m in self.metrics])}"
            },
            'Optimization Suggestions': [
                "Consider implementing caching for frequently accessed data" if statistics.mean(cpu_values) > 70 else "",
                "Memory usage shows potential leak, investigate memory management" if (memory_values[-1] - memory_values[0]) > 100 else "",
                "High disk I/O detected, consider batch processing" if max(disk_write) > 100 else "",
                "System performs within normal parameters" if statistics.mean(cpu_values) < 70 and max(memory_values) < 500 else ""
            ]
        }
        
        return analysis

    def export_to_excel(self, wb):
        """Export monitoring data and analysis to Excel"""
        # Raw Metrics Sheet
        metrics_ws = wb.create_sheet(title="System Metrics")
        headers = list(self.metrics[0].keys())
        
        # Add headers
        for col, header in enumerate(headers, 1):
            cell = metrics_ws.cell(row=1, column=col, value=header.upper())
            cell.font = Font(bold=True)
            cell.fill = PatternFill(start_color="CCCCCC", end_color="CCCCCC", fill_type="solid")
        
        # Add metrics data
        for row, metric in enumerate(self.metrics, 2):
            for col, header in enumerate(headers, 1):
                metrics_ws.cell(row=row, column=col, value=metric[header])

        # Analysis Sheet
        analysis_ws = wb.create_sheet(title="Performance Analysis")
        analysis = self.analyze_performance()
        current_row = 1

        for section, data in analysis.items():
            # Section header
            cell = analysis_ws.cell(row=current_row, column=1, value=section)
            cell.font = Font(bold=True)
            cell.fill = PatternFill(start_color="86C232", end_color="86C232", fill_type="solid")
            current_row += 1

            if isinstance(data, dict):
                for key, value in data.items():
                    analysis_ws.cell(row=current_row, column=1, value=key)
                    analysis_ws.cell(row=current_row, column=2, value=value)
                    current_row += 1
            elif isinstance(data, list):
                for item in data:
                    if item:  # Only add non-empty suggestions
                        analysis_ws.cell(row=current_row, column=1, value=item)
                        current_row += 1
            current_row += 1  # Add space between sections

        # Auto-adjust column widths
        for ws in [metrics_ws, analysis_ws]:
            for column_cells in ws.columns:
                length = max(len(str(cell.value) if cell.value else "") for cell in column_cells)
                ws.column_dimensions[get_column_letter(column_cells[0].column)].width = length + 2

        return wb