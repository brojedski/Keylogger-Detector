import ctypes
import hashlib
import os
import platform
import psutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import winreg
from datetime import datetime
from tkinter import *
from tkinter import ttk, messagebox, scrolledtext

# Constants for Windows API
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

class SystemMonitor:
    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.psapi = ctypes.windll.psapi
        self.user32 = ctypes.windll.user32
        self.running = False
        self.suspicious_activities = []
        self.known_threats = self._load_threat_database()
        self.create_ui()
        
    def _load_threat_database(self):
        """Load threat signatures from a secure source (in a real implementation)"""
        return {
            # Example hashes (replace with actual threat intelligence)
            "a94a8fe5ccb19ba61c4c0873d391e987": "Example Keylogger",
            "d41d8cd98f00b204e9800998ecf8427e": "Empty File Marker"
        }
    
    def create_ui(self):
        """Create the user interface"""
        self.root = Tk()
        self.root.title("Advanced System Sentinel")
        self.root.geometry("1200x800")
        
        # Configure styles
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f5f5f5')
        self.style.configure('TLabel', background='#f5f5f5', font=('Segoe UI', 10))
        self.style.configure('Title.TLabel', font=('Segoe UI', 16, 'bold'))
        self.style.configure('Red.TLabel', foreground='red')
        self.style.configure('Green.TLabel', foreground='green')
        
        # Create frames
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=X, pady=(0, 10))
        
        ttk.Label(header_frame, text="Advanced System Sentinel", style='Title.TLabel').pack(side=LEFT)
        
        # Control buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=X, pady=(0, 10))
        
        self.start_btn = ttk.Button(btn_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_btn.pack(side=LEFT, padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="Stop Monitoring", command=self.stop_monitoring, state=DISABLED)
        self.stop_btn.pack(side=LEFT, padx=5)
        
        ttk.Button(btn_frame, text="Scan System", command=self.run_full_scan).pack(side=LEFT, padx=5)
        ttk.Button(btn_frame, text="View Logs", command=self.view_logs).pack(side=LEFT, padx=5)
        
        # Monitoring dashboard
        dashboard_frame = ttk.LabelFrame(main_frame, text="Monitoring Dashboard", padding=10)
        dashboard_frame.pack(fill=BOTH, expand=True)
        
        # Process tree
        self.process_tree = ttk.Treeview(dashboard_frame, columns=('pid', 'name', 'status', 'risk'), selectmode='browse')
        self.process_tree.heading('#0', text='Process Tree')
        self.process_tree.column('#0', width=250)
        self.process_tree.heading('pid', text='PID')
        self.process_tree.column('pid', width=80)
        self.process_tree.heading('name', text='Name')
        self.process_tree.column('name', width=200)
        self.process_tree.heading('status', text='Status')
        self.process_tree.column('status', width=100)
        self.process_tree.heading('risk', text='Risk')
        self.process_tree.column('risk', width=80)
        
        yscroll = ttk.Scrollbar(dashboard_frame, orient=VERTICAL, command=self.process_tree.yview)
        xscroll = ttk.Scrollbar(dashboard_frame, orient=HORIZONTAL, command=self.process_tree.xview)
        self.process_tree.configure(yscroll=yscroll.set, xscroll=xscroll.set)
        
        self.process_tree.grid(row=0, column=0, sticky=NSEW)
        yscroll.grid(row=0, column=1, sticky=NS)
        xscroll.grid(row=1, column=0, sticky=EW)
        
        # Details panel
        details_frame = ttk.Frame(dashboard_frame)
        details_frame.grid(row=2, column=0, columnspan=2, sticky=EW, pady=(10, 0))
        
        ttk.Label(details_frame, text="Process Details:").pack(side=LEFT)
        self.details_text = scrolledtext.ScrolledText(details_frame, height=8, wrap=WORD)
        self.details_text.pack(fill=BOTH, expand=True)
        
        # Configure grid weights
        dashboard_frame.grid_columnconfigure(0, weight=1)
        dashboard_frame.grid_rowconfigure(0, weight=1)
        
        # Status bar
        self.status_var = StringVar(value="Ready")
        status_bar = ttk.Frame(main_frame)
        status_bar.pack(fill=X, pady=(10, 0))
        
        ttk.Label(status_bar, textvariable=self.status_var, relief=SUNKEN, anchor=W).pack(fill=X)
        
        # Bind events
        self.process_tree.bind('<<TreeviewSelect>>', self.show_process_details)
        
    def start_monitoring(self):
        """Start the monitoring thread"""
        if not self.running:
            self.running = True
            self.start_btn.config(state=DISABLED)
            self.stop_btn.config(state=NORMAL)
            self.status_var.set("Monitoring started")
            
            # Start monitoring thread
            self.monitor_thread = threading.Thread(target=self.monitor_system, daemon=True)
            self.monitor_thread.start()
            
    def stop_monitoring(self):
        """Stop the monitoring thread"""
        if self.running:
            self.running = False
            self.start_btn.config(state=NORMAL)
            self.stop_btn.config(state=DISABLED)
            self.status_var.set("Monitoring stopped")
            
    def monitor_system(self):
        """Main monitoring loop"""
        while self.running:
            try:
                self.update_process_tree()
                self.check_for_suspicious_activity()
                time.sleep(2)  # Update every 2 seconds
            except Exception as e:
                self.log_error(f"Monitoring error: {str(e)}")
                time.sleep(5)
                
    def update_process_tree(self):
        """Update the process tree view"""
        current_processes = {p.pid: p for p in psutil.process_iter(['pid', 'name', 'status'])}
        
        # Get existing items in tree
        existing_items = set()
        for item in self.process_tree.get_children():
            pid = int(self.process_tree.item(item, 'values')[0])
            existing_items.add(pid)
            
        # Add new processes
        for pid, proc in current_processes.items():
            if pid not in existing_items:
                risk = self.assess_process_risk(proc)
                self.process_tree.insert(
                    '', 'end', 
                    values=(proc.pid, proc.name(), proc.status(), risk),
                    tags=(risk.lower(),)
                )
        
        # Remove dead processes
        current_pids = set(current_processes.keys())
        for item in self.process_tree.get_children():
            pid = int(self.process_tree.item(item, 'values')[0])
            if pid not in current_pids:
                self.process_tree.delete(item)
                
        # Configure tag colors
        self.process_tree.tag_configure('high', background='#ffcccc')
        self.process_tree.tag_configure('medium', background='#fff3cd')
        self.process_tree.tag_configure('low', background='#ffffff')
        
    def assess_process_risk(self, process):
        """Assess risk level of a process"""
        try:
            # Check process name
            proc_name = process.name().lower()
            suspicious_keywords = [
                'keylog', 'spy', 'monitor', 'logger', 
                'track', 'record', 'capture', 'stealer'
            ]
            
            if any(kw in proc_name for kw in suspicious_keywords):
                return "High"
                
            # Check process path
            exe_path = process.exe()
            if exe_path:
                # Check if in suspicious locations
                suspicious_locations = [
                    os.getenv('TEMP'),
                    os.getenv('APPDATA'),
                    os.path.join(os.getenv('SYSTEMROOT'), 'Temp')
                ]
                
                if any(loc in exe_path for loc in suspicious_locations if loc):
                    return "Medium"
                    
                # Check file hash
                file_hash = self.get_file_hash(exe_path)
                if file_hash in self.known_threats:
                    return "High"
                    
            return "Low"
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "Unknown"
            
    def get_file_hash(self, file_path):
        """Calculate MD5 hash of a file"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except:
            return None
            
    def check_for_suspicious_activity(self):
        """Check for various suspicious activities"""
        self.check_hidden_processes()
        self.check_keyboard_hooks()
        self.check_unsigned_drivers()
        self.check_network_connections()
        
    def check_hidden_processes(self):
        """Detect processes hidden from normal enumeration"""
        try:
            # Get processes through Windows API
            process_ids = (ctypes.c_ulong * 1024)()
            bytes_returned = ctypes.c_ulong()
            
            if self.psapi.EnumProcesses(ctypes.byref(process_ids), ctypes.sizeof(process_ids), ctypes.byref(bytes_returned)):
                api_pids = set(pid for pid in process_ids if pid != 0)
                psutil_pids = set(p.pid for p in psutil.process_iter())
                
                # Find PIDs visible to API but not to psutil
                hidden_pids = api_pids - psutil_pids
                if hidden_pids:
                    self.log_alert(f"Potential hidden processes detected: {hidden_pids}")
                    
        except Exception as e:
            self.log_error(f"Error checking hidden processes: {str(e)}")
            
    def check_keyboard_hooks(self):
        """Check for keyboard hooks"""
        try:
            # This is a simplified check - real implementation would be more thorough
            wh_keyboard_ll = 13
            hook_count = self.user32.GetWindowHookCount(wh_keyboard_ll)
            
            if hook_count > 1:  # Normally only system hooks should be present
                self.log_alert(f"Multiple keyboard hooks detected ({hook_count})")
                
        except Exception as e:
            self.log_error(f"Error checking keyboard hooks: {str(e)}")
            
    def check_unsigned_drivers(self):
        """Check for unsigned drivers"""
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(
                    ['powershell', 'Get-WindowsDriver -Online -All | Where-Object {$_.IsSigned -eq $False}'],
                    capture_output=True, text=True
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    self.log_alert("Unsigned drivers detected:\n" + result.stdout)
                    
        except Exception as e:
            self.log_error(f"Error checking unsigned drivers: {str(e)}")
            
    def check_network_connections(self):
        """Check for suspicious network connections"""
        try:
            for conn in psutil.net_connections():
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    # Check for connections to known suspicious ports
                    suspicious_ports = [4444, 31337, 6667]  # Example ports
                    if conn.raddr.port in suspicious_ports:
                        self.log_alert(f"Suspicious connection to {conn.raddr.ip}:{conn.raddr.port}")
                        
        except Exception as e:
            self.log_error(f"Error checking network connections: {str(e)}")
            
    def run_full_scan(self):
        """Run a comprehensive system scan"""
        self.status_var.set("Starting full system scan...")
        
        scan_thread = threading.Thread(target=self._perform_scan, daemon=True)
        scan_thread.start()
        
    def _perform_scan(self):
        """Perform the actual scanning"""
        try:
            self.log_action("Starting full system scan")
            
            # Scan running processes
            self.log_action("Scanning running processes")
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                risk = self.assess_process_risk(proc)
                if risk in ("High", "Medium"):
                    self.log_alert(f"Suspicious process: {proc.name()} (PID: {proc.pid}, Risk: {risk})")
            
            # Scan startup programs
            self.log_action("Scanning startup programs")
            self.scan_startup_programs()
            
            # Scan system files
            self.log_action("Scanning system files")
            self.scan_system_files()
            
            self.log_action("Full system scan completed")
            self.status_var.set("Scan completed - check logs for details")
            
        except Exception as e:
            self.log_error(f"Scan error: {str(e)}")
            self.status_var.set(f"Scan error: {str(e)}")
            
    def scan_startup_programs(self):
        """Scan startup programs in registry"""
        startup_locations = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        
        for root_key, subkey in startup_locations:
            try:
                with winreg.OpenKey(root_key, subkey) as key:
                    for i in range(0, winreg.QueryInfoKey(key)[1]):
                        name, value, _ = winreg.EnumValue(key, i)
                        
                        # Check for suspicious keywords
                        suspicious = any(
                            kw in name.lower() or kw in value.lower() 
                            for kw in ['keylog', 'spy', 'monitor', 'logger']
                        )
                        
                        if suspicious:
                            self.log_alert(f"Suspicious startup entry: {name} = {value}")
                            
                        # Check if file exists and scan it
                        if os.path.exists(value):
                            file_hash = self.get_file_hash(value)
                            if file_hash in self.known_threats:
                                self.log_alert(f"Known threat in startup: {name} = {value} ({self.known_threats[file_hash]})")
                                
            except Exception as e:
                self.log_error(f"Error scanning startup: {str(e)}")
                
    def scan_system_files(self):
        """Scan system files for known threats"""
        scan_locations = [
            os.path.join(os.getenv('SYSTEMROOT'), 'System32'),
            os.path.join(os.getenv('SYSTEMROOT'), 'Temp'),
            os.getenv('APPDATA'),
            os.getenv('TEMP')
        ]
        
        for location in scan_locations:
            try:
                for root, _, files in os.walk(location):
                    for file in files:
                        file_path = os.path.join(root, file)
                        
                        # Only check executable files
                        if file_path.lower().endswith(('.exe', '.dll', '.sys')):
                            file_hash = self.get_file_hash(file_path)
                            if file_hash in self.known_threats:
                                self.log_alert(f"Known threat found: {file_path} ({self.known_threats[file_hash]})")
                                
            except Exception as e:
                self.log_error(f"Error scanning {location}: {str(e)}")
                
    def show_process_details(self, event):
        """Show details for selected process"""
        selected = self.process_tree.selection()
        if selected:
            item = self.process_tree.item(selected[0])
            pid = int(item['values'][0])
            
            try:
                proc = psutil.Process(pid)
                details = f"Process: {proc.name()}\n"
                details += f"PID: {proc.pid}\n"
                details += f"Status: {proc.status()}\n"
                details += f"CPU %: {proc.cpu_percent()}\n"
                details += f"Memory: {proc.memory_info().rss/1024/1024:.2f} MB\n"
                
                try:
                    details += f"Path: {proc.exe()}\n"
                except:
                    details += "Path: [Access denied]\n"
                    
                details += "\nCommand line:\n"
                try:
                    details += ' '.join(proc.cmdline()) + "\n"
                except:
                    details += "[Access denied]\n"
                    
                self.details_text.delete(1.0, END)
                self.details_text.insert(END, details)
                
            except psutil.NoSuchProcess:
                self.details_text.delete(1.0, END)
                self.details_text.insert(END, "Process no longer exists")
                
    def view_logs(self):
        """Show the log viewer"""
        log_window = Toplevel(self.root)
        log_window.title("Activity Logs")
        log_window.geometry("800x600")
        
        log_text = scrolledtext.ScrolledText(log_window, wrap=WORD)
        log_text.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # Load logs (in a real app, this would read from a log file)
        log_text.insert(END, "=== Activity Log ===\n")
        for entry in self.suspicious_activities:
            log_text.insert(END, entry + "\n")
            
        log_text.config(state=DISABLED)
        
    def log_alert(self, message):
        """Log a security alert"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[ALERT] {timestamp} - {message}"
        self.suspicious_activities.append(log_entry)
        
    def log_action(self, message):
        """Log a normal action"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[INFO] {timestamp} - {message}"
        self.suspicious_activities.append(log_entry)
        
    def log_error(self, message):
        """Log an error"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[ERROR] {timestamp} - {message}"
        self.suspicious_activities.append(log_entry)
        
    def run(self):
        """Run the application"""
        self.root.mainloop()

if __name__ == "__main__":
    if platform.system() != 'Windows':
        print("This tool is designed for Windows systems")
        sys.exit(1)
        
    if os.geteuid() == 0 or ctypes.windll.shell32.IsUserAnAdmin():
        monitor = SystemMonitor()
        monitor.run()
    else:
        print("Please run as administrator")
        sys.exit(1)