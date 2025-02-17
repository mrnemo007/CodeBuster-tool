import socket
import threading
import nmap
import customtkinter as ctk
from utils import log_message
import time
from datetime import datetime
from risk_analyzer import RiskAnalyzer

class PortScanner:
    def __init__(self, app):
        self.app = app
        self.scanning = False

    def create_scanner_frame(self):
        """Maak het hoofdframe voor de scanner"""
        scanner_frame = ctk.CTkFrame(self.app.main_frame)
        scanner_frame.grid(row=1, column=0, columnspan=3, padx=20, pady=10, sticky="ew")
        return scanner_frame

    def create_target_input(self, parent_frame):
        """Maak de target input sectie"""
        target_label = ctk.CTkLabel(parent_frame, text="Doel IP:")
        target_label.grid(row=0, column=0, padx=5, pady=5)

        self.target_entry = ctk.CTkEntry(parent_frame, width=200)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5)
        self.target_entry.insert(0, "Enter target IP address...")  # Duidelijkere placeholder

    def create_scan_type_selector(self, parent_frame):
        """Maak de scan type selector"""
        scan_type_label = ctk.CTkLabel(parent_frame, text="Scan Type:")
        scan_type_label.grid(row=0, column=2, padx=5, pady=5)

        self.scan_type = ctk.CTkOptionMenu(
            parent_frame,
            values=["Quick Scan (Common Ports)", 
                   "Full Scan (1-1024)", 
                   "Deep Scan (All Ports)",
                   "Stealth Scan"],
            width=200
        )
        self.scan_type.grid(row=0, column=3, padx=5, pady=5)

    def create_options_frame(self, parent_frame):
        """Maak het frame voor scan opties"""
        options_frame = ctk.CTkFrame(parent_frame)
        options_frame.grid(row=1, column=0, columnspan=4, padx=5, pady=5, sticky="ew")

        self.service_detection = ctk.CTkCheckBox(
            options_frame, 
            text="Service Detection",
            variable=ctk.BooleanVar(value=True)
        )
        self.service_detection.grid(row=0, column=0, padx=5, pady=5)

        self.vuln_detection = ctk.CTkCheckBox(
            options_frame, 
            text="Vulnerability Detection",
            variable=ctk.BooleanVar(value=True)
        )
        self.vuln_detection.grid(row=0, column=1, padx=5, pady=5)

        self.risk_analysis = ctk.CTkCheckBox(
            options_frame, 
            text="Risk Analysis",
            variable=ctk.BooleanVar(value=True)
        )
        self.risk_analysis.grid(row=0, column=2, padx=5, pady=5)

    def create_buttons_frame(self, parent_frame):
        """Maak het frame voor de knoppen"""
        buttons_frame = ctk.CTkFrame(parent_frame)
        buttons_frame.grid(row=2, column=0, columnspan=4, padx=5, pady=5, sticky="ew")

        self.scan_button = ctk.CTkButton(
            buttons_frame, 
            text="Start Scan", 
            command=self.start_scan,
            fg_color="#1f538d"
        )
        self.scan_button.grid(row=0, column=0, padx=5, pady=5)

        self.security_button = ctk.CTkButton(
            buttons_frame, 
            text="Security Test", 
            command=self.start_security_test,
            fg_color="#8d1f1f"
        )
        self.security_button.grid(row=0, column=1, padx=5, pady=5)

    def create_progress_frame(self):
        """Maak het progress frame"""
        self.progress_frame = ctk.CTkFrame(self.app.main_frame)
        self.progress_frame.grid(row=2, column=0, columnspan=3, padx=20, pady=10, sticky="ew")
        self.progress_frame.grid_columnconfigure(0, weight=1)

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(
            self.progress_frame,
            width=300,
            height=20,
            border_width=2,
            progress_color="#00ff00",
            fg_color="#000000"
        )
        self.progress_bar.grid(row=0, column=0, padx=10, pady=5, sticky="ew")
        self.progress_bar.set(0)

        # Status labels
        self.percentage_label = ctk.CTkLabel(
            self.progress_frame,
            text="0%",
            font=("Terminal", 12),
            text_color="#00ff00"
        )
        self.percentage_label.grid(row=1, column=0, pady=2)

        self.status_label = ctk.CTkLabel(
            self.progress_frame,
            text="",
            font=("Terminal", 10),
            text_color="#00ff00"
        )
        self.status_label.grid(row=2, column=0, pady=2)
        
        # Verberg progress frame bij start
        self.progress_frame.grid_remove()

    def create_warning_frame(self):
        """Maak het waarschuwingsframe met sluit-knop"""
        self.warning_frame = ctk.CTkFrame(self.app.main_frame)
        self.warning_frame.grid(row=0, column=0, columnspan=3, padx=20, pady=(10, 5), sticky="ew")
        
        # Header frame met waarschuwing en sluit-knop
        header_frame = ctk.CTkFrame(self.warning_frame, fg_color="transparent")
        header_frame.pack(fill="x", pady=5, padx=10)
        
        # Waarschuwing header met icoon (links)
        warning_header = ctk.CTkFrame(header_frame, fg_color="transparent")
        warning_header.pack(side="left")
        
        warning_icon = ctk.CTkLabel(
            warning_header,
            text="⚠️",
            font=("Arial", 24),
            text_color="#FFB302"
        )
        warning_icon.pack(side="left", padx=(0, 10))
        
        warning_title = ctk.CTkLabel(
            warning_header,
            text="WETTELIJKE WAARSCHUWING",
            font=("Arial", 16, "bold"),
            text_color="#FFB302"
        )
        warning_title.pack(side="left")
        
        # Sluit-knop (rechts)
        close_button = ctk.CTkButton(
            header_frame,
            text="✕",
            width=30,
            height=30,
            fg_color="transparent",
            hover_color="#FF6B6B",
            command=self.hide_warning
        )
        close_button.pack(side="right", padx=5)
        
        # Waarschuwing tekst
        warning_text = ctk.CTkLabel(
            self.warning_frame,
            text="Het is illegaal om port scans uit te voeren op systemen zonder expliciete toestemming.\n"
                 "Gebruik deze tool alleen op systemen waarvoor u toestemming heeft.",
            font=("Arial", 12),
            text_color="#FF6B6B"
        )
        warning_text.pack(pady=(0, 10), padx=20)

    def hide_warning(self):
        """Verberg het waarschuwingsframe"""
        self.warning_frame.grid_remove()
        # Verschuif andere frames omhoog
        self.scanner_frame.grid(row=0, column=0, columnspan=3, padx=20, pady=10, sticky="ew")
        if hasattr(self, 'progress_frame'):
            self.progress_frame.grid(row=1, column=0, columnspan=3, padx=20, pady=10, sticky="ew")

    def setup_ui(self):
        """Setup de UI voor de Port Scanner"""
        for widget in self.app.main_frame.winfo_children():
            if widget != self.app.output_text:
                widget.destroy()

        # Waarschuwing frame
        self.create_warning_frame()

        # Scanner frame
        self.scanner_frame = self.create_scanner_frame()
        self.create_target_input(self.scanner_frame)
        self.create_scan_type_selector(self.scanner_frame)
        self.create_options_frame(self.scanner_frame)
        self.create_buttons_frame(self.scanner_frame)
        
        # Progress frame
        self.create_progress_frame()

    def get_ports_for_scan_type(self, scan_type):
        """Bepaal de te scannen poorten op basis van scan type"""
        if scan_type == "Quick Scan (Common Ports)":
            return [21,22,23,25,53,80,110,139,443,445,3306,3389,5432,8080]
        elif scan_type == "Full Scan (1-1024)":
            return range(1, 1025)
        else:
            return range(1, 65536)

    def scan_single_port(self, target, port):
        """Scan een enkele poort"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.1)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = "unknown"
                try:
                    service = socket.getservbyport(port)
                except:
                    pass
                return port, service
        return None, None

    def scan_ports(self, target):
        """Voer de port scan uit"""
        try:
            ports = self.get_ports_for_scan_type(self.scan_type.get())
            total_ports = len(ports) if isinstance(ports, list) else ports.stop - ports.start
            ports_scanned = 0
            open_ports = []

            for port in ports:
                if not self.scanning:
                    break

                port_num, service = self.scan_single_port(target, port)
                if port_num:
                    open_ports.append(port_num)
                    log_message(self.app.output_text, f"Port {port} ({service}) is open", "success")

                ports_scanned += 1
                progress = ports_scanned / total_ports
                self.update_progress(progress, f"SCANNING PORT {port}")

            self.log_scan_results(open_ports)

        except Exception as e:
            log_message(self.app.output_text, f"Scan error: {str(e)}", "error")
        finally:
            self.scan_completed()

    def log_scan_results(self, open_ports):
        """Log de resultaten van de scan"""
        scan_duration = datetime.now() - self.scan_start_time
        log_message(self.app.output_text, f"\nScan completed in {scan_duration}", "info")
        log_message(self.app.output_text, f"Found {len(open_ports)} open ports", "info")

    def update_progress(self, progress_value, status_text):
        """Update de voortgangsbalk en status"""
        self.progress_bar.set(progress_value)
        percentage = int(progress_value * 100)
        self.percentage_label.configure(text=f"{percentage}%")
        self.status_label.configure(text=status_text)

    def start_scan(self):
        """Start een basis port scan"""
        target = self.target_entry.get()
        self.scanning = True
        self.scan_start_time = datetime.now()
        
        # Reset en toon progress frame
        self.progress_bar.set(0)
        self.percentage_label.configure(text="0%")
        self.status_label.configure(text="Starting scan...")
        self.progress_frame.grid()
        
        self.scan_button.configure(text="Stop Scan", command=self.stop_scan)
        self.security_button.configure(state="disabled")  # Disable security knop tijdens scan

        thread = threading.Thread(target=self.scan_ports, args=(target,))
        thread.start()

    def scan_completed(self):
        """Reset UI na scan"""
        self.scanning = False
        self.scan_button.configure(text="Start Scan", command=self.start_scan, state="normal")
        self.security_button.configure(text="Security Test", command=self.start_security_test, state="normal")
        self.progress_frame.grid_remove()
        self.update_progress(0, "")

    def stop_scan(self):
        """Stop de huidige scan"""
        self.scanning = False
        self.scan_button.configure(state="disabled")
        self.status_label.configure(text="STOPPING SCAN...")
        log_message(self.app.output_text, "\nStopping scan...", "warning")

    def start_security_test(self):
        """Start een security test met voortgangsweergave"""
        target = self.target_entry.get()
        self.scanning = True
        self.scan_start_time = datetime.now()
        
        # Reset en toon output
        self.app.output_text.delete("1.0", "end")
        log_message(self.app.output_text, "Starting Security Test...", "header")
        log_message(self.app.output_text, f"Target: {target}\n", "info")
        
        # Reset en toon progress frame
        self.progress_bar.set(0)
        self.percentage_label.configure(text="0%")
        self.status_label.configure(text="Initializing security test...")
        self.progress_frame.grid()
        
        # Update UI knoppen
        self.security_button.configure(text="Stop Test", command=self.stop_security_test)
        self.scan_button.configure(state="disabled")
        
        thread = threading.Thread(target=self._run_security_test, args=(target,))
        thread.start()

    def _run_security_test(self, target):
        """Voer de security test uit"""
        try:
            # Fase 1: Port Scan (0-30%)
            log_message(self.app.output_text, "[Phase 1] Basic Port Scan", "header")
            log_message(self.app.output_text, "-"*40 + "\n", "header")
            
            open_ports = []
            common_ports = [20,21,22,23,25,53,80,110,139,443,445,1433,3306,3389,5432,8080]
            
            for i, port in enumerate(common_ports):
                if not self.scanning:
                    break
                    
                port_num, service = self.scan_single_port(target, port)
                if port_num:
                    open_ports.append(port_num)
                    log_message(self.app.output_text, 
                              f"Found open port {port} ({service})", "warning")
                
                progress = (i + 1) / len(common_ports) * 0.3
                self.update_progress(progress, "SCANNING VULNERABLE PORTS...")
            
            if not self.scanning:
                return

            # Fase 2: Service Detection (30-70%)
            log_message(self.app.output_text, "\n[Phase 2] Service Detection", "header")
            log_message(self.app.output_text, "-"*40 + "\n", "header")
            
            services = []
            if open_ports:
                for i, port in enumerate(open_ports):
                    if not self.scanning:
                        break

                    # Probeer service informatie te krijgen
                    try:
                        service_name = socket.getservbyport(port)
                    except:
                        service_name = "unknown"

                    # Probeer banner grabbing voor meer informatie
                    product = ""
                    version = ""
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                            sock.settimeout(2)
                            sock.connect((target, port))
                            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                            if banner:
                                product = banner.split()[0]
                                if len(banner.split()) > 1:
                                    version = banner.split()[1]
                    except:
                        pass

                    service_str = f"Port {port}: {service_name}"
                    if product or version:
                        service_str += f" ({product} {version})"
                    
                    log_message(self.app.output_text, service_str, "info")
                    services.append({
                        'port': port,
                        'name': service_name,
                        'product': product,
                        'version': version
                    })

                    progress = 0.3 + ((i + 1) / len(open_ports)) * 0.4
                    self.update_progress(progress, f"ANALYZING PORT {port}...")
                    time.sleep(0.1)  # Kleine pauze tussen scans

            if not self.scanning:
                return

            # Fase 3: Risk Analysis (70-100%)
            if self.risk_analysis.get():
                log_message(self.app.output_text, "\n[Phase 3] Risk Analysis", "header")
                log_message(self.app.output_text, "-"*40 + "\n", "header")
                
                self.update_progress(0.7, "PERFORMING RISK ANALYSIS...")
                
                # Gebruik risk analyzer
                analyzer = RiskAnalyzer(self.app)
                security_report = analyzer.analyze_security(target, open_ports, services)
                
                # Toon resultaten
                self.update_progress(0.9, "GENERATING SECURITY REPORT...")
                
                log_message(self.app.output_text, "\n" + "="*50, "header")
                log_message(self.app.output_text, " SECURITY ASSESSMENT ", "header")
                log_message(self.app.output_text, "="*50 + "\n", "header")
                
                # Risk Score
                risk_color = "success" if security_report['risk_score'] < 30 else "warning" if security_report['risk_score'] < 70 else "error"
                log_message(self.app.output_text, f"Overall Risk Score: {security_report['risk_score']}/100", risk_color)
                log_message(self.app.output_text, f"Risk Level: {security_report['risk_level']}", risk_color)
                
                # Vulnerabilities
                if security_report['vulnerabilities']:
                    log_message(self.app.output_text, "\n[!] Critical Vulnerabilities:", "header")
                    for vuln in security_report['vulnerabilities']:
                        log_message(self.app.output_text, f"\n▶ {vuln['service'].upper()} (Port {vuln['port']})", "warning")
                        log_message(self.app.output_text, f"  Risk Level: {vuln['risk']}", "warning")
                        log_message(self.app.output_text, f"  Issue: {vuln['message']}", "info")
                        log_message(self.app.output_text, f"  Impact: {vuln['impact']}", "error")
                
                # Security Issues
                if security_report['security_issues']:
                    log_message(self.app.output_text, "\n[!] Security Issues:", "header")
                    for issue in security_report['security_issues']:
                        log_message(self.app.output_text, f"\n▶ {issue['type']}", "warning")
                        log_message(self.app.output_text, f"  Risk Level: {issue['risk']}", "warning")
                        log_message(self.app.output_text, f"  Issue: {issue['message']}", "info")
                        log_message(self.app.output_text, f"  Impact: {issue['impact']}", "error")
                
                # Recommendations
                if security_report['recommendations']:
                    log_message(self.app.output_text, "\n[+] Security Recommendations:", "header")
                    for rec in security_report['recommendations']:
                        log_message(self.app.output_text, f"\n▶ {rec['title']} (Priority: {rec['priority']})", "success")
                        for step in rec['steps']:
                            log_message(self.app.output_text, f"  • {step}", "info")

                self.update_progress(1.0, "SECURITY ASSESSMENT COMPLETE")

            else:
                log_message(self.app.output_text, "\nRisk analysis skipped (not enabled)", "warning")
                self.update_progress(1.0, "SCAN COMPLETE")

        except Exception as e:
            log_message(self.app.output_text, f"Security test error: {str(e)}", "error")
        finally:
            if self.scanning:
                self.scan_completed()
            else:
                log_message(self.app.output_text, "\nSecurity test manually stopped.", "warning")
            self.security_button.configure(text="Security Test", command=self.start_security_test, state="normal")
            self.scan_button.configure(state="normal")
            self.progress_frame.grid_remove()

    def stop_security_test(self):
        """Stop de security test"""
        self.scanning = False
        self.security_button.configure(state="disabled")
        self.status_label.configure(text="STOPPING TEST...")
        log_message(self.app.output_text, "\nStopping security test...", "warning")
