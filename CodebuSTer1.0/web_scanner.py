import customtkinter as ctk
import threading
import requests
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
import re
from utils import log_message
import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import time

# Onderdruk SSL waarschuwingen
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class WebScanner:
    def __init__(self, app):
        self.app = app
        self.scanning = False
        self.session = requests.Session()
        self.session.verify = True

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
            text="Het is illegaal om website scans uit te voeren op systemen zonder expliciete toestemming.\n"
                 "Gebruik deze tool alleen op websites waarvoor u toestemming heeft.",
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
        
        self.progress_frame.grid_remove()

    def setup_ui(self):
        """Setup de UI voor de Web Scanner"""
        for widget in self.app.main_frame.winfo_children():
            if widget != self.app.output_text:
                widget.destroy()

        # Waarschuwing frame
        self.create_warning_frame()

        # Scanner frame
        self.scanner_frame = ctk.CTkFrame(self.app.main_frame)
        self.scanner_frame.grid(row=1, column=0, columnspan=3, padx=20, pady=10, sticky="ew")

        # Website URL input
        url_label = ctk.CTkLabel(self.scanner_frame, text="Website URL:")
        url_label.grid(row=0, column=0, padx=5, pady=5)

        self.url_entry = ctk.CTkEntry(self.scanner_frame, width=400)
        self.url_entry.grid(row=0, column=1, padx=5, pady=5)
        self.url_entry.insert(0, "Enter website URL...")

        # Scan opties
        options_frame = ctk.CTkFrame(self.scanner_frame)
        options_frame.grid(row=1, column=0, columnspan=4, padx=5, pady=5, sticky="ew")

        self.ssl_check = ctk.CTkCheckBox(
            options_frame,
            text="SSL/TLS Check",
            variable=ctk.BooleanVar(value=True)
        )
        self.ssl_check.grid(row=0, column=0, padx=5, pady=5)

        self.headers_check = ctk.CTkCheckBox(
            options_frame,
            text="Security Headers",
            variable=ctk.BooleanVar(value=True)
        )
        self.headers_check.grid(row=0, column=1, padx=5, pady=5)

        self.content_check = ctk.CTkCheckBox(
            options_frame,
            text="Content Security",
            variable=ctk.BooleanVar(value=True)
        )
        self.content_check.grid(row=0, column=2, padx=5, pady=5)

        # Start scan button
        self.scan_button = ctk.CTkButton(
            self.scanner_frame,
            text="Start Scan",
            command=self.start_scan,
            fg_color="#1f538d"
        )
        self.scan_button.grid(row=2, column=0, columnspan=4, padx=5, pady=10)

        # Progress frame
        self.setup_progress_frame()

    def start_scan(self):
        """Start website scan"""
        try:
            # Haal URL op en valideer
            raw_url = self.url_entry.get()
            url = self._prepare_url(raw_url)
            
            self.scanning = True
            
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
            self.progress_frame.grid(row=1)
            
            # Update button
            self.scan_button.configure(text="Stop Scan", command=self.stop_scan)
            
            # Start scan thread
            thread = threading.Thread(target=self._run_web_scan, args=(url,))
            thread.daemon = True
            thread.start()
            
        except ValueError as e:
            log_message(self.app.output_text, f"\nError: {str(e)}", "error")
            self.scan_completed()
        except Exception as e:
            log_message(self.app.output_text, f"\nUnexpected error: {str(e)}", "error")
            self.scan_completed()

    def stop_scan(self):
        """Stop de website scan"""
        self.scanning = False
        self.scan_button.configure(state="disabled")
        self.status_label.configure(text="STOPPING SCAN...")
        log_message(self.app.output_text, "\nStopping website scan...", "warning")

    def scan_completed(self):
        """Reset UI na scan"""
        if not hasattr(self, 'scan_button') or not self.scan_button.winfo_exists():
            return
            
        try:
            self.scanning = False
            self.scan_button.configure(text="Start Scan", command=self.start_scan, state="normal")
            if hasattr(self, 'progress_frame') and self.progress_frame.winfo_exists():
                self.progress_frame.grid_remove()
            self.update_progress(0, "")
        except Exception as e:
            print(f"Error in scan completion: {str(e)}")

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

    def _run_web_scan(self, url):
        """Voer website security scan uit"""
        try:
            self.update_progress(0.1, "Gathering target information...")
            target_info = self._gather_target_info(url)
            
            security_issues = []
            
            # Basic HTTP headers check
            if self.headers_check.get():
                self.update_progress(0.3, "Checking security headers...")
                headers = self._check_security_headers(url)
                security_issues.extend(headers)
            
            # SSL/TLS check
            if self.ssl_check.get():
                self.update_progress(0.5, "Analyzing SSL/TLS security...")
                ssl_issues = self._check_ssl_security(url)
                security_issues.extend(ssl_issues)
            
            # Content security check
            if self.content_check.get():
                self.update_progress(0.7, "Scanning content security...")
                content_issues = self._check_content_security(url)
                security_issues.extend(content_issues)
            
            # Generate reports
            self.update_progress(0.8, "Generating target information report...")
            self._generate_info_report(target_info)
            
            self.update_progress(0.9, "Generating security report...")
            self._generate_web_security_report(url, security_issues)
            
            self.update_progress(1.0, "Scan complete")
            
        except Exception as e:
            log_message(self.app.output_text, f"Error scanning website: {str(e)}", "error")
        finally:
            self.scan_completed()

    def _check_security_headers(self, url):
        """Check security headers"""
        issues = []
        try:
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
                    
        except Exception as e:
            issues.append({
                'type': 'connection',
                'severity': 'high',
                'description': f'Verbindingsfout: {str(e)}',
                'recommendation': 'Controleer website bereikbaarheid'
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
                    
        except Exception as e:
            issues.append({
                'type': 'ssl',
                'severity': 'high',
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
                    
        except Exception as e:
            issues.append({
                'type': 'content',
                'severity': 'medium',
                'description': f'Content analyse fout: {str(e)}',
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

    def _gather_target_info(self, url):
        """Verzamel uitgebreide informatie over het target"""
        info = {
            'url': url,
            'ip': None,
            'server': None,
            'technologies': [],
            'dns_records': {},
            'whois_info': {},
            'headers': {},
            'cookies': [],
            'forms': [],
            'links': [],
            'emails': [],
            'social_media': [],
            'security_headers': {},
            'response_time': None,
            'ssl_info': {},
            'ports': []
        }
        
        try:
            # Meet response tijd
            start_time = time.time()
            response = self.session.get(url, timeout=10, verify=False)
            info['response_time'] = f"{(time.time() - start_time):.2f} seconds"
            
            # Basis informatie
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            
            # IP en poort scanning
            try:
                info['ip'] = socket.gethostbyname(hostname)
                common_ports = [80, 443, 8080, 8443]
                for port in common_ports:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((info['ip'], port))
                        if result == 0:
                            info['ports'].append(port)
                        sock.close()
                    except:
                        pass
            except:
                pass

            # Headers analyse
            info['headers'] = dict(response.headers)
            info['server'] = response.headers.get('Server', 'Unknown')
            
            # Security headers check
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Frame-Options': 'X-Frame',
                'X-Content-Type-Options': 'X-Content-Type',
                'X-XSS-Protection': 'XSS Protection',
                'Referrer-Policy': 'Referrer Policy'
            }
            
            for header, desc in security_headers.items():
                info['security_headers'][desc] = header in response.headers

            # SSL/TLS informatie
            if url.startswith('https'):
                try:
                    ssl_context = ssl.create_default_context()
                    with socket.create_connection((hostname, 443)) as sock:
                        with ssl_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            info['ssl_info'] = {
                                'version': ssock.version(),
                                'cipher': ssock.cipher(),
                                'cert': ssock.getpeercert()
                            }
                except:
                    pass

            # DNS informatie
            try:
                import dns.resolver
                for record_type in ['A', 'MX', 'NS', 'TXT', 'CNAME']:
                    try:
                        answers = dns.resolver.resolve(hostname, record_type)
                        info['dns_records'][record_type] = [str(answer) for answer in answers]
                    except:
                        pass
            except:
                pass

            # WHOIS informatie
            try:
                info['whois_info'] = self._gather_whois_info(hostname)
            except:
                pass

            # Cookies analyse
            info['cookies'] = [
                {
                    'name': cookie.name,
                    'value': cookie.value,
                    'secure': cookie.secure,
                    'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                    'samesite': cookie.has_nonstandard_attr('SameSite')
                } for cookie in response.cookies
            ]
            
            # HTML content analyse
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Forms detectie
            forms = soup.find_all('form')
            for form in forms:
                form_info = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get'),
                    'inputs': [
                        {
                            'type': input.get('type', ''),
                            'name': input.get('name', ''),
                            'id': input.get('id', '')
                        } for input in form.find_all('input')
                    ]
                }
                info['forms'].append(form_info)
            
            # Links verzameling
            links = soup.find_all('a')
            info['links'] = [link.get('href') for link in links if link.get('href')]
            
            # Email adressen zoeken
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            info['emails'] = list(set(re.findall(email_pattern, response.text)))
            
            # Social media links detectie
            social_patterns = {
                'facebook': r'facebook\.com/[a-zA-Z0-9.]+',
                'twitter': r'twitter\.com/[a-zA-Z0-9_]+',
                'linkedin': r'linkedin\.com/[a-zA-Z0-9/-]+',
                'instagram': r'instagram\.com/[a-zA-Z0-9_.]+',
                'youtube': r'youtube\.com/[a-zA-Z0-9/-]+'
            }
            
            for platform, pattern in social_patterns.items():
                matches = re.findall(pattern, response.text)
                if matches:
                    info['social_media'].extend(matches)
            
            # Technologie detectie
            self._detect_technologies(response.text, response.headers, info['technologies'])
            
        except Exception as e:
            log_message(self.app.output_text, f"Error gathering target info: {str(e)}", "error")
            
        return info

    def _gather_whois_info(self, hostname):
        """Verzamel uitgebreide WHOIS informatie via meerdere bronnen"""
        whois_info = {
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'name_servers': [],
            'status': None,
            'emails': [],
            'contacts': {},
            'organization': None,
            'abuse_contact': None
        }
        
        try:
            # 1. Probeer eerst via requests direct WHOIS info te krijgen
            try:
                response = requests.get(f'https://rdap.sidn.nl/domain/{hostname}')
                if response.status_code == 200:
                    data = response.json()
                    
                    # Basis informatie
                    if 'entities' in data:
                        for entity in data['entities']:
                            if 'roles' in entity:
                                role = entity['roles'][0].lower()
                                if 'vcardArray' in entity:
                                    vcard = entity['vcardArray'][1]
                                    contact_info = {}
                                    
                                    for item in vcard:
                                        if item[0] == 'fn':
                                            contact_info['name'] = item[3]
                                        elif item[0] == 'email':
                                            contact_info['email'] = item[3]
                                        elif item[0] == 'tel':
                                            contact_info['phone'] = item[3]
                                        elif item[0] == 'adr':
                                            contact_info['address'] = ' '.join(item[3])
                                            
                                    whois_info['contacts'][role] = contact_info
                    
                    # Events (creation, expiration, etc.)
                    if 'events' in data:
                        for event in data['events']:
                            if event['eventAction'] == 'registration':
                                whois_info['creation_date'] = event['eventDate']
                            elif event['eventAction'] == 'expiration':
                                whois_info['expiration_date'] = event['eventDate']
                    
                    # Nameservers
                    if 'nameservers' in data:
                        whois_info['name_servers'] = [ns['ldhName'] for ns in data['nameservers']]
            except:
                pass

            # 2. Probeer via socket directe WHOIS query
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(('whois.sidn.nl', 43))
                s.send(f'{hostname}\r\n'.encode())
                response = b''
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data
                s.close()
                
                whois_text = response.decode('utf-8', errors='ignore')
                
                # Parse de response
                for line in whois_text.split('\n'):
                    line = line.strip()
                    if ':' in line:
                        key, value = [x.strip() for x in line.split(':', 1)]
                        key = key.lower()
                        
                        if 'registrar' in key:
                            whois_info['registrar'] = value
                        elif 'abuse' in key:
                            whois_info['abuse_contact'] = value
                        elif 'organisation' in key or 'organization' in key:
                            whois_info['organization'] = value
                        elif 'e-mail' in key or 'email' in key:
                            if value and '@' in value:
                                whois_info['emails'].append(value)
                        elif 'status' in key:
                            whois_info['status'] = value
                        elif 'created' in key:
                            if not whois_info['creation_date']:
                                whois_info['creation_date'] = value
            except:
                pass

            # 3. Gebruik python-whois als backup
            try:
                import whois
                whois_data = whois.whois(hostname)
                
                # Update ontbrekende informatie
                if not whois_info['registrar'] and getattr(whois_data, 'registrar', None):
                    whois_info['registrar'] = whois_data.registrar
                if not whois_info['creation_date'] and getattr(whois_data, 'creation_date', None):
                    whois_info['creation_date'] = whois_data.creation_date
                if not whois_info['expiration_date'] and getattr(whois_data, 'expiration_date', None):
                    whois_info['expiration_date'] = whois_data.expiration_date
                if not whois_info['name_servers'] and getattr(whois_data, 'name_servers', None):
                    whois_info['name_servers'] = whois_data.name_servers
                if not whois_info['status'] and getattr(whois_data, 'status', None):
                    whois_info['status'] = whois_data.status
                
                # Verzamel extra emails
                for field in ['emails', 'email', 'admin_email', 'tech_email', 'registrant_email']:
                    if hasattr(whois_data, field):
                        value = getattr(whois_data, field)
                        if value:
                            if isinstance(value, list):
                                whois_info['emails'].extend([e for e in value if '@' in str(e)])
                            elif '@' in str(value):
                                whois_info['emails'].append(value)
            except:
                pass

        except Exception as e:
            print(f"WHOIS error: {str(e)}")
            
        # Verwijder duplicaten uit emails
        whois_info['emails'] = list(set(whois_info['emails']))
        
        return whois_info

    def _detect_technologies(self, html, headers, technologies):
        """Detecteer gebruikte web technologieën"""
        # Headers analyse
        if 'X-Powered-By' in headers:
            technologies.append(headers['X-Powered-By'])
        
        # Common frameworks/libraries
        tech_signatures = {
            'WordPress': ['wp-content', 'wp-includes'],
            'Joomla': ['joomla!', 'com_content'],
            'Drupal': ['drupal.js', 'drupal.min.js'],
            'Bootstrap': ['bootstrap.css', 'bootstrap.js'],
            'jQuery': ['jquery.js', 'jquery.min.js'],
            'React': ['react.js', 'react.development.js'],
            'Vue.js': ['vue.js', 'vue.min.js'],
            'Angular': ['angular.js', 'ng-app'],
            'Laravel': ['laravel', 'csrf-token'],
            'Django': ['csrfmiddlewaretoken', 'django'],
            'ASP.NET': ['.aspx', 'asp.net'],
            'PHP': ['php', '.php'],
            'nginx': ['nginx'],
            'Apache': ['apache'],
            'IIS': ['IIS', 'X-Powered-By: ASP.NET']
        }
        
        for tech, signatures in tech_signatures.items():
            if any(sig.lower() in html.lower() for sig in signatures):
                technologies.append(tech)

    def _generate_info_report(self, info):
        """Genereer rapport van verzamelde informatie"""
        log_message(self.app.output_text, "\nTarget Information Report\n", "header")
        log_message(self.app.output_text, "="*50 + "\n", "header")
        
        # Basis informatie
        log_message(self.app.output_text, "Basic Information:", "header")
        log_message(self.app.output_text, f"URL: {info['url']}", "info")
        log_message(self.app.output_text, f"IP Address: {info['ip']}", "info")
        log_message(self.app.output_text, f"Server: {info['server']}", "info")
        log_message(self.app.output_text, f"Response Time: {info['response_time']}", "info")
        
        # Open poorten
        if info['ports']:
            log_message(self.app.output_text, "\nOpen Ports:", "header")
            for port in info['ports']:
                log_message(self.app.output_text, f"  • Port {port}", "info")
        
        # Security Headers
        log_message(self.app.output_text, "\nSecurity Headers:", "header")
        for desc, present in info['security_headers'].items():
            status = "success" if present else "error"
            log_message(self.app.output_text, f"  • {desc}: {'✓' if present else '✗'}", status)
        
        # SSL/TLS Informatie
        if info['ssl_info']:
            log_message(self.app.output_text, "\nSSL/TLS Information:", "header")
            ssl_info = info['ssl_info']
            log_message(self.app.output_text, f"Version: {ssl_info['version']}", "info")
            log_message(self.app.output_text, f"Cipher Suite: {ssl_info['cipher'][0]}", "info")
            
            if 'cert' in ssl_info:
                cert = ssl_info['cert']
                if 'notAfter' in cert:
                    expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (expiry - datetime.now()).days
                    status = "success" if days_left > 30 else "warning" if days_left > 0 else "error"
                    log_message(self.app.output_text, f"Certificate Expires: {cert['notAfter']} ({days_left} days left)", status)

        # DNS Records
        if info['dns_records']:
            log_message(self.app.output_text, "\nDNS Records:", "header")
            for record_type, records in info['dns_records'].items():
                log_message(self.app.output_text, f"{record_type} Records:", "info")
                for record in records:
                    log_message(self.app.output_text, f"  • {record}", "info")
        
        # WHOIS Informatie
        if info['whois_info']:
            log_message(self.app.output_text, "\nWHOIS Information:", "header")
            
            # Registratie informatie
            if info['whois_info'].get('registrar'):
                log_message(self.app.output_text, f"Registrar: {info['whois_info']['registrar']}", "info")
            if info['whois_info'].get('organization'):
                log_message(self.app.output_text, f"Organization: {info['whois_info']['organization']}", "info")
            if info['whois_info'].get('creation_date'):
                log_message(self.app.output_text, f"Created: {info['whois_info']['creation_date']}", "info")
            if info['whois_info'].get('expiration_date'):
                log_message(self.app.output_text, f"Expires: {info['whois_info']['expiration_date']}", "info")
            if info['whois_info'].get('status'):
                log_message(self.app.output_text, f"Status: {info['whois_info']['status']}", "info")
            
            # Contact informatie
            if info['whois_info'].get('contacts'):
                log_message(self.app.output_text, "\nContact Information:", "header")
                for role, details in info['whois_info']['contacts'].items():
                    log_message(self.app.output_text, f"\n{role.title()} Contact:", "info")
                    for key, value in details.items():
                        log_message(self.app.output_text, f"  {key.title()}: {value}", "info")
            
            # Abuse contact
            if info['whois_info'].get('abuse_contact'):
                log_message(self.app.output_text, f"\nAbuse Contact: {info['whois_info']['abuse_contact']}", "warning")
            
            # Email adressen
            if info['whois_info'].get('emails'):
                log_message(self.app.output_text, "\nAssociated Email Addresses:", "info")
                for email in info['whois_info']['emails']:
                    log_message(self.app.output_text, f"  • {email}", "info")
            
            # Nameservers
            if info['whois_info'].get('name_servers'):
                log_message(self.app.output_text, "\nNameservers:", "info")
                for ns in info['whois_info']['name_servers']:
                    if ns and len(ns) > 1:
                        log_message(self.app.output_text, f"  • {ns}", "info")
        
        # Technologieën
        if info['technologies']:
            log_message(self.app.output_text, "\nDetected Technologies:", "header")
            for tech in info['technologies']:
                log_message(self.app.output_text, f"  • {tech}", "info")
        
        # Forms
        if info['forms']:
            log_message(self.app.output_text, "\nDetected Forms:", "header")
            for i, form in enumerate(info['forms'], 1):
                log_message(self.app.output_text, f"\nForm {i}:", "warning")
                log_message(self.app.output_text, f"Action: {form['action']}", "info")
                log_message(self.app.output_text, f"Method: {form['method']}", "info")
                if form['inputs']:
                    log_message(self.app.output_text, "Inputs:", "info")
                    for input in form['inputs']:
                        log_message(self.app.output_text, f"  • {input['type']} - {input['name']}", "info")
        
        # Cookies
        if info['cookies']:
            log_message(self.app.output_text, "\nCookies:", "header")
            for cookie in info['cookies']:
                security_issues = []
                if not cookie['secure']:
                    security_issues.append("Not Secure")
                if not cookie['httponly']:
                    security_issues.append("No HttpOnly")
                if not cookie['samesite']:
                    security_issues.append("No SameSite")
                    
                status = "error" if security_issues else "success"
                log_message(self.app.output_text, f"  • {cookie['name']}", status)
                if security_issues:
                    log_message(self.app.output_text, f"    Issues: {', '.join(security_issues)}", "warning")
        
        # Email Addresses
        if info['emails']:
            log_message(self.app.output_text, "\nDetected Email Addresses:", "header")
            for email in info['emails']:
                log_message(self.app.output_text, f"  • {email}", "info")
        
        # Social Media
        if info['social_media']:
            log_message(self.app.output_text, "\nSocial Media Links:", "header")
            for link in info['social_media']:
                log_message(self.app.output_text, f"  • {link}", "info")

    def _prepare_url(self, url):
        """Bereid de URL voor voor scanning"""
        if not url or url == "Enter website URL...":
            raise ValueError("Please enter a valid URL")
            
        # Verwijder whitespace
        url = url.strip()
        
        # Voeg http:// toe als er geen protocol is
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        try:
            # Valideer URL formaat
            parsed = urlparse(url)
            if not all([parsed.scheme, parsed.netloc]):
                raise ValueError("Invalid URL format")
                
            # Test of de website bereikbaar is
            response = requests.head(url, timeout=5, verify=False)
            response.raise_for_status()
            
            return url
            
        except requests.exceptions.RequestException as e:
            raise ValueError(f"Could not connect to website: {str(e)}")
        except Exception as e:
            raise ValueError(f"Invalid URL: {str(e)}")

    def _query_sidn_whois(self, domain):
        """Direct WHOIS query naar SIDN voor .nl domeinen"""
        whois_data = {}
        try:
            # Connect naar SIDN WHOIS server met socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect(('whois.domain-registry.nl', 43))
            
            # Stuur query
            query = f"{domain}\r\n"
            s.send(query.encode())
            
            # Ontvang response
            response = b''
            while True:
                try:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data
                except socket.timeout:
                    break
                    
            s.close()
            
            # Decodeer en parse response
            whois_text = response.decode('utf-8', errors='ignore')
            
            # Parse de response
            for line in whois_text.split('\n'):
                line = line.strip()
                
                if not line or line.startswith('%') or line.startswith('#'):
                    continue
                    
                if ':' in line:
                    key, value = [x.strip() for x in line.split(':', 1)]
                    key = key.lower()
                    
                    if 'registrant' in key:
                        whois_data['registrant'] = value
                    elif 'admin-c' in key:
                        whois_data['admin'] = value
                    elif 'tech-c' in key:
                        whois_data['tech'] = value
                    elif 'registrar' in key:
                        whois_data['registrar'] = value
                    elif 'status' in key:
                        whois_data['status'] = value
                    elif 'domain' in key:
                        whois_data['domain'] = value
                    elif 'abuse-c' in key:
                        whois_data['abuse'] = value
                    elif 'created' in key or 'creation' in key:
                        whois_data['creation_date'] = value
                    elif 'updated' in key:
                        whois_data['updated_date'] = value
                    elif 'dns:' in key or 'nserver' in key:
                        if 'nameservers' not in whois_data:
                            whois_data['nameservers'] = []
                        whois_data['nameservers'].append(value)
                    elif 'e-mail' in key or 'email' in key:
                        if 'emails' not in whois_data:
                            whois_data['emails'] = []
                        if '@' in value:
                            whois_data['emails'].append(value)
                    elif 'phone' in key:
                        whois_data['phone'] = value
                    elif 'organisation' in key or 'organization' in key:
                        whois_data['organization'] = value
                        
            return whois_data
            
        except Exception as e:
            print(f"SIDN WHOIS Error: {str(e)}")
            return None 