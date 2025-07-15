import os
import psutil
import winreg
import hashlib
import platform
import socket
import threading
from tkinter import *
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
import requests
from io import BytesIO

class AdvancedKeyloggerDetector:
    def __init__(self, root):
        self.root = root
        self.root.title("Guardian Sentinel - Advanced Keylogger Detection")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # Style configuration
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Segoe UI', 10))
        self.style.configure('Title.TLabel', font=('Segoe UI', 16, 'bold'))
        self.style.configure('TButton', font=('Segoe UI', 10))
        self.style.configure('Red.TButton', foreground='red')
        self.style.configure('Green.TButton', foreground='green')
        self.style.map('TButton', 
                      foreground=[('pressed', 'black'), ('active', 'blue')],
                      background=[('pressed', '!disabled', '#f0f0f0'), ('active', '#e1e1e1')])
        
        # Load known signatures (in a real app, this would be from a secure server)
        self.known_threats = self.load_threat_signatures()
        self.suspicious_keywords = ["keylog", "spy", "monitor", "logger", "track", "record", "capture", "stealer"]
        
        # Create UI
        self.create_header()
        self.create_scan_section()
        self.create_results_section()
        self.create_footer()
        
        # Initialize scan thread
        self.scan_thread = None
        self.stop_scan = False
        
    def create_header(self):
        # Header frame
        header_frame = ttk.Frame(self.root, style='TFrame')
        header_frame.pack(fill=X, padx=10, pady=10)
        
        # Logo (placeholder - would be replaced with actual logo)
        try:
            response = requests.get("https://via.placeholder.com/64")
            img_data = response.content
            self.logo_img = ImageTk.PhotoImage(Image.open(BytesIO(img_data)).resize((64, 64)))
            logo_label = ttk.Label(header_frame, image=self.logo_img)
            logo_label.grid(row=0, column=0, rowspan=2, padx=(0, 15))
        except:
            pass
        
        # Title and subtitle
        title_label = ttk.Label(header_frame, text="Guardian Sentinel", style='Title.TLabel')
        title_label.grid(row=0, column=1, sticky=W)
        
        subtitle_label = ttk.Label(header_frame, 
                                 text="Advanced Keylogger & Spyware Detection System",
                                 style='TLabel')
        subtitle_label.grid(row=1, column=1, sticky=W)
        
        # System info
        sys_info = f"OS: {platform.system()} {platform.release()} | CPU: {os.cpu_count()} cores | Host: {socket.gethostname()}"
        sys_label = ttk.Label(header_frame, text=sys_info, style='TLabel')
        sys_label.grid(row=0, column=2, rowspan=2, sticky=E)
        
    def create_scan_section(self):
        # Scan options frame
        scan_frame = ttk.LabelFrame(self.root, text="Scan Options", padding=(15, 10))
        scan_frame.pack(fill=X, padx=10, pady=(0, 10))
        
        # Scan types
        ttk.Label(scan_frame, text="Scan Type:").grid(row=0, column=0, sticky=W)
        self.scan_type = StringVar(value="quick")
        ttk.Radiobutton(scan_frame, text="Quick Scan", variable=self.scan_type, value="quick").grid(row=0, column=1, sticky=W)
        ttk.Radiobutton(scan_frame, text="Full Scan", variable=self.scan_type, value="full").grid(row=0, column=2, sticky=W)
        ttk.Radiobutton(scan_frame, text="Custom Scan", variable=self.scan_type, value="custom").grid(row=0, column=3, sticky=W)
        
        # Custom scan path
        self.custom_path = StringVar()
        path_frame = ttk.Frame(scan_frame)
        path_frame.grid(row=1, column=0, columnspan=4, sticky=EW, pady=(10, 0))
        ttk.Label(path_frame, text="Custom Path:").pack(side=LEFT)
        ttk.Entry(path_frame, textvariable=self.custom_path, width=50).pack(side=LEFT, padx=5)
        ttk.Button(path_frame, text="Browse...", command=self.browse_path).pack(side=LEFT)
        
        # Action buttons
        button_frame = ttk.Frame(scan_frame)
        button_frame.grid(row=2, column=0, columnspan=4, pady=(15, 5))
        ttk.Button(button_frame, text="Start Scan", command=self.start_scan, 
                  style='Green.TButton').pack(side=LEFT, padx=5)
        ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan_func, 
                  style='Red.TButton').pack(side=LEFT, padx=5)
        ttk.Button(button_frame, text="Quarantine Threats", command=self.quarantine_threats).pack(side=LEFT, padx=5)
        
    def create_results_section(self):
        # Results frame
        results_frame = ttk.LabelFrame(self.root, text="Scan Results", padding=(15, 10))
        results_frame.pack(fill=BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Treeview for results
        self.results_tree = ttk.Treeview(results_frame, columns=('type', 'location', 'risk', 'details'), 
                                       selectmode='extended')
        self.results_tree.heading('#0', text='Item')
        self.results_tree.column('#0', width=150, stretch=NO)
        self.results_tree.heading('type', text='Type')
        self.results_tree.column('type', width=100, stretch=NO)
        self.results_tree.heading('location', text='Location')
        self.results_tree.column('location', width=250)
        self.results_tree.heading('risk', text='Risk Level')
        self.results_tree.column('risk', width=80, stretch=NO)
        self.results_tree.heading('details', text='Details')
        self.results_tree.column('details', width=300)
        
        # Scrollbars
        yscroll = ttk.Scrollbar(results_frame, orient=VERTICAL, command=self.results_tree.yview)
        xscroll = ttk.Scrollbar(results_frame, orient=HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        
        # Grid layout
        self.results_tree.grid(row=0, column=0, sticky=NSEW)
        yscroll.grid(row=0, column=1, sticky=NS)
        xscroll.grid(row=1, column=0, sticky=EW)
        
        # Configure grid weights
        results_frame.grid_columnconfigure(0, weight=1)
        results_frame.grid_rowconfigure(0, weight=1)
        
        # Details frame
        details_frame = ttk.Frame(results_frame)
        details_frame.grid(row=2, column=0, columnspan=2, sticky=EW, pady=(10, 0))
        ttk.Label(details_frame, text="Threat Details:").pack(side=LEFT)
        self.details_text = Text(details_frame, height=4, wrap=WORD)
        self.details_text.pack(side=LEFT, fill=X, expand=True)
        
        # Bind treeview selection
        self.results_tree.bind('<<TreeviewSelect>>', self.show_details)
        
    def create_footer(self):
        # Footer frame
        footer_frame = ttk.Frame(self.root, style='TFrame')
        footer_frame.pack(fill=X, padx=10, pady=(0, 10))
        
        # Progress bar
        self.progress = ttk.Progressbar(footer_frame, orient=HORIZONTAL, mode='determinate')
        self.progress.pack(side=LEFT, fill=X, expand=True, padx=(0, 10))
        
        # Status label
        self.status_var = StringVar(value="Ready to scan")
        ttk.Label(footer_frame, textvariable=self.status_var, style='TLabel').pack(side=LEFT)
        
    def browse_path(self):
        path = filedialog.askdirectory()
        if path:
            self.custom_path.set(path)
            self.scan_type.set('custom')
            
    def load_threat_signatures(self):
        # In a real application, this would fetch from a secure server
        return {
            # Sample MD5 hashes of known malicious files
            "d41d8cd98f00b204e9800998ecf8427e": "Sample Keylogger A",
            "098f6bcd4621d373cade4e832627b4f6": "Sample Keylogger B",
            # Add more signatures as needed
        }
    
    def start_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showwarning("Scan in Progress", "A scan is already running!")
            return
            
        self.stop_scan = False
        self.results_tree.delete(*self.results_tree.get_children())
        self.status_var.set("Scanning...")
        self.progress['value'] = 0
        
        scan_type = self.scan_type.get()
        scan_path = self.custom_path.get() if scan_type == 'custom' else None
        
        self.scan_thread = threading.Thread(
            target=self.run_scan,
            args=(scan_type, scan_path),
            daemon=True
        )
        self.scan_thread.start()
        
    def stop_scan_func(self):
        self.stop_scan = True
        self.status_var.set("Scan stopped by user")
        
    def run_scan(self, scan_type, custom_path=None):
        try:
            # Update UI from thread requires special handling
            self.root.after(0, lambda: self.status_var.set("Checking running processes..."))
            self.check_running_processes()
            if self.stop_scan: return
            
            self.root.after(0, lambda: self.status_var.set("Checking startup programs..."))
            self.check_startup_programs()
            if self.stop_scan: return
            
            self.root.after(0, lambda: self.status_var.set("Checking system hooks..."))
            self.check_system_hooks()
            if self.stop_scan: return
            
            if scan_type == 'full' or scan_type == 'custom':
                self.root.after(0, lambda: self.status_var.set("Scanning files..."))
                scan_path = custom_path if scan_type == 'custom' else "C:\\"
                self.check_suspicious_files(scan_path)
                if self.stop_scan: return
            
            self.root.after(0, lambda: self.status_var.set("Scan complete!"))
            self.progress['value'] = 100
            self.show_scan_summary()
            
        except Exception as e:
            self.root.after(0, lambda: self.status_var.set(f"Scan error: {str(e)}"))
            self.root.after(0, lambda: messagebox.showerror("Scan Error", str(e)))
    
    def check_running_processes(self):
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            if self.stop_scan: return
            
            # Check process name
            proc_name = proc.info['name'].lower()
            for keyword in self.suspicious_keywords:
                if keyword in proc_name:
                    self.add_threat(
                        item=proc_name,
                        type='Process',
                        location=proc.info['exe'] or 'Unknown',
                        risk='High',
                        details=f"Process name contains suspicious keyword: {keyword}"
                    )
            
            # Check command line
            if proc.info['cmdline']:
                cmd_line = ' '.join(proc.info['cmdline']).lower()
                for keyword in self.suspicious_keywords:
                    if keyword in cmd_line:
                        self.add_threat(
                            item=proc_name,
                            type='Process',
                            location=proc.info['exe'] or 'Unknown',
                            risk='High',
                            details=f"Process command line contains suspicious keyword: {keyword}"
                        )
            
            # Update progress
            self.root.after(0, lambda: self.progress.step(0.5))
    
    def check_startup_programs(self):
        startup_locations = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        
        for root_key, subkey in startup_locations:
            if self.stop_scan: return
            
            try:
                with winreg.OpenKey(root_key, subkey) as key:
                    for i in range(0, winreg.QueryInfoKey(key)[1]):
                        name, value, _ = winreg.EnumValue(key, i)
                        value_lower = value.lower()
                        
                        for keyword in self.suspicious_keywords:
                            if keyword in name.lower() or keyword in value_lower:
                                self.add_threat(
                                    item=name,
                                    type='Startup Entry',
                                    location=f"Registry: {subkey}",
                                    risk='Medium',
                                    details=f"Startup entry contains suspicious keyword: {keyword}"
                                )
                                
                        # Check if path exists and scan the file
                        if os.path.exists(value):
                            file_hash = self.get_file_hash(value)
                            if file_hash in self.known_threats:
                                self.add_threat(
                                    item=name,
                                    type='Startup Entry',
                                    location=f"Registry: {subkey}",
                                    risk='High',
                                    details=f"Known threat: {self.known_threats[file_hash]}"
                                )
            
            except Exception as e:
                continue
            
            self.root.after(0, lambda: self.progress.step(1))
    
    def check_system_hooks(self):
        # Check for keyboard hooks (simplified example)
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                               r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows") as key:
                appinit_dlls = winreg.QueryValueEx(key, "AppInit_DLLs")[0]
                if appinit_dlls:
                    for dll in appinit_dlls.split(','):
                        dll = dll.strip()
                        if any(kw in dll.lower() for kw in self.suspicious_keywords):
                            self.add_threat(
                                item=dll,
                                type='System Hook',
                                location='AppInit_DLLs',
                                risk='High',
                                details="Suspicious DLL loaded via AppInit_DLLs"
                            )
        except:
            pass
        
        self.root.after(0, lambda: self.progress.step(1))
    
    def check_suspicious_files(self, scan_path):
        # In a real application, this would be more sophisticated
        # Here we just check file names and hashes
        total_files = 0
        scanned_files = 0
        
        # Count files first (for progress)
        if not self.stop_scan:
            for root, _, files in os.walk(scan_path):
                total_files += len(files)
        
        if not self.stop_scan:
            for root, _, files in os.walk(scan_path):
                for file in files:
                    if self.stop_scan: return
                    
                    file_path = os.path.join(root, file)
                    file_lower = file.lower()
                    
                    # Check file name
                    for keyword in self.suspicious_keywords:
                        if keyword in file_lower:
                            self.add_threat(
                                item=file,
                                type='File',
                                location=file_path,
                                risk='Medium',
                                details=f"Filename contains suspicious keyword: {keyword}"
                            )
                    
                    # Check file hash if it's an executable
                    if file_path.endswith(('.exe', '.dll', '.sys')):
                        try:
                            file_hash = self.get_file_hash(file_path)
                            if file_hash in self.known_threats:
                                self.add_threat(
                                    item=file,
                                    type='File',
                                    location=file_path,
                                    risk='High',
                                    details=f"Known threat: {self.known_threats[file_hash]}"
                                )
                        except:
                            pass
                    
                    scanned_files += 1
                    progress = (scanned_files / total_files) * 50 + 50  # First 50% was other checks
                    self.root.after(0, lambda: self.progress['value'] = min(progress, 99))
    
    def get_file_hash(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except:
            return None
    
    def add_threat(self, item, type, location, risk, details):
        self.root.after(0, lambda: self.results_tree.insert(
            '', 'end', 
            text=item,
            values=(type, location, risk, details)
        ))
        
        # Color code based on risk
        if risk == 'High':
            self.root.after(0, lambda: self.results_tree.item(
                self.results_tree.get_children()[-1], 
                tags=('high',)
            ))
        elif risk == 'Medium':
            self.root.after(0, lambda: self.results_tree.item(
                self.results_tree.get_children()[-1], 
                tags=('medium',)
            ))
        
        # Configure tag colors
        self.root.after(0, lambda: self.results_tree.tag_configure(
            'high', background='#ffcccc'
        ))
        self.root.after(0, lambda: self.results_tree.tag_configure(
            'medium', background='#fff3cd'
        ))
    
    def show_details(self, event):
        selected = self.results_tree.selection()
        if selected:
            item = self.results_tree.item(selected[0])
            details = "\n".join(f"{k}: {v}" for k, v in zip(
                ['Type', 'Location', 'Risk', 'Details'],
                item['values']
            ))
            self.details_text.delete(1.0, END)
            self.details_text.insert(END, details)
    
    def show_scan_summary(self):
        total = len(self.results_tree.get_children())
        high = len(self.results_tree.tag_has('high'))
        medium = len(self.results_tree.tag_has('medium'))
        
        summary = f"Scan complete!\n\nTotal items scanned\nThreats found: {total}\nHigh risk: {high}\nMedium risk: {medium}"
        messagebox.showinfo("Scan Summary", summary)
    
    def quarantine_threats(self):
        selected = self.results_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select threats to quarantine")
            return
            
        confirmed = messagebox.askyesno(
            "Confirm Quarantine",
            f"Are you sure you want to quarantine {len(selected)} selected items?"
        )
        if not confirmed:
            return
            
        # In a real application, this would actually quarantine the files
        # Here we just simulate it
        for item_id in selected:
            item = self.results_tree.item(item_id)
            location = item['values'][1]
            
            # Skip registry entries (would need different handling)
            if location.startswith('Registry:'):
                continue
                
            # Skip if path doesn't exist
            if not os.path.exists(location):
                continue
                
            # In a real app, we would move to quarantine instead of deleting
            try:
                os.remove(location)
                self.results_tree.item(item_id, tags=('quarantined',))
            except Exception as e:
                self.results_tree.item(item_id, tags=('error',))
        
        # Update tag colors
        self.results_tree.tag_configure('quarantined', background='#ccffcc')
        self.results_tree.tag_configure('error', background='#ff9999')
        
        messagebox.showinfo(
            "Quarantine Complete",
            f"Attempted to quarantine {len(selected)} items\n"
            "Note: This demo only simulates quarantine"
        )

if __name__ == "__main__":
    root = Tk()
    app = AdvancedKeyloggerDetector(root)
    root.mainloop()