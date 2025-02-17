import socket
import ssl
import requests
from datetime import datetime
import re
from utils import log_message

class RiskAnalyzer:
    def __init__(self, app):
        self.app = app
        self.vulnerabilities = []
        self.security_issues = []
        self.risk_score = 0
        
    def analyze_security(self, target, open_ports, services):
        """Voer uitgebreide security analyse uit"""
        self.vulnerabilities = []
        self.security_issues = []
        
        # Basis service checks
        self._check_vulnerable_services(services)
        
        # SSL/TLS checks voor HTTPS
        if 443 in open_ports:
            self._check_ssl_security(target)
            
        # HTTP security headers check
        if 80 in open_ports or 443 in open_ports:
            self._check_http_security(target)
            
        # Database port checks
        self._check_database_security(open_ports)
        
        # Remote access checks
        self._check_remote_access(open_ports, services)
        
        # Default port checks
        self._check_default_ports(open_ports)
        
        # Calculate final risk score
        self._calculate_risk_score(open_ports)
        
        return self._generate_security_report()

    def _check_vulnerable_services(self, services):
        """Check voor bekende kwetsbare services"""
        vulnerable_services = {
            'telnet': {
                'risk': 'HIGH',
                'message': 'Telnet verstuurt data onversleuteld - vervang door SSH',
                'impact': 'Credentials kunnen onderschept worden'
            },
            'ftp': {
                'risk': 'MEDIUM',
                'message': 'FTP is onveilig voor bestandsoverdracht - gebruik SFTP/FTPS',
                'impact': 'Bestanden en inloggegevens kunnen onderschept worden'
            },
            'http': {
                'risk': 'MEDIUM',
                'message': 'Onversleutelde HTTP gevonden - forceer HTTPS',
                'impact': 'Verkeer kan onderschept en gemanipuleerd worden'
            },
            'mysql': {
                'risk': 'HIGH',
                'message': 'MySQL direct toegankelijk van buitenaf',
                'impact': 'Database kan doelwit zijn van brute-force aanvallen'
            },
            'microsoft-ds': {
                'risk': 'HIGH',
                'message': 'SMB service gevonden - mogelijk kwetsbaar voor exploits',
                'impact': 'Systeem kan kwetsbaar zijn voor ransomware en remote code execution'
            }
        }

        for service in services:
            service_name = service['name'].lower()
            if service_name in vulnerable_services:
                vuln = vulnerable_services[service_name]
                self.vulnerabilities.append({
                    'service': service_name,
                    'port': service['port'],
                    'risk': vuln['risk'],
                    'message': vuln['message'],
                    'impact': vuln['impact']
                })

    def _check_ssl_security(self, target):
        """Controleer SSL/TLS configuratie"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    if cert and 'notAfter' in cert:
                        expiry = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                        if expiry < datetime.now():
                            self.security_issues.append({
                                'type': 'SSL',
                                'risk': 'HIGH',
                                'message': 'SSL certificaat is verlopen',
                                'impact': 'Bezoekers krijgen waarschuwingen en verkeer is mogelijk onveilig'
                            })
                    
                    # Check protocol version
                    version = ssock.version()
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        self.security_issues.append({
                            'type': 'SSL',
                            'risk': 'MEDIUM',
                            'message': f'Verouderd SSL/TLS protocol gevonden: {version}',
                            'impact': 'Verkeer kan mogelijk gedecrypt worden door bekende kwetsbaarheden'
                        })
        except:
            pass

    def _check_http_security(self, target):
        """Controleer HTTP security headers"""
        try:
            response = requests.get(f'http://{target}', timeout=5)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'Bescherming tegen clickjacking ontbreekt',
                'X-Content-Type-Options': 'MIME-type sniffing protectie ontbreekt',
                'X-XSS-Protection': 'XSS bescherming is niet geconfigureerd',
                'Content-Security-Policy': 'Content Security Policy ontbreekt',
                'Strict-Transport-Security': 'HSTS is niet geconfigureerd'
            }
            
            for header, message in security_headers.items():
                if header not in headers:
                    self.security_issues.append({
                        'type': 'HTTP',
                        'risk': 'MEDIUM',
                        'message': message,
                        'impact': 'Website is mogelijk kwetsbaar voor verschillende aanvallen'
                    })
        except:
            pass

    def _check_database_security(self, open_ports):
        """Controleer database security"""
        database_ports = {
            3306: 'MySQL',
            5432: 'PostgreSQL',
            1433: 'MSSQL',
            27017: 'MongoDB',
            6379: 'Redis'
        }
        
        for port, db in database_ports.items():
            if port in open_ports:
                self.security_issues.append({
                    'type': 'DATABASE',
                    'risk': 'HIGH',
                    'message': f'{db} database direct toegankelijk van buitenaf op port {port}',
                    'impact': 'Database kan doelwit zijn van aanvallen en data diefstal'
                })

    def _check_remote_access(self, open_ports, services):
        """Controleer remote access services"""
        remote_ports = {
            22: 'SSH',
            23: 'Telnet',
            3389: 'RDP',
            5900: 'VNC'
        }
        
        for port, service in remote_ports.items():
            if port in open_ports:
                risk_level = 'MEDIUM' if service == 'SSH' else 'HIGH'
                self.security_issues.append({
                    'type': 'REMOTE',
                    'risk': risk_level,
                    'message': f'{service} remote access service gevonden op port {port}',
                    'impact': 'Systeem kan doelwit zijn van brute-force aanvallen'
                })

    def _check_default_ports(self, open_ports):
        """Controleer gebruik van standaard poorten"""
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            443: 'HTTPS'
        }
        
        for port, service in common_ports.items():
            if port in open_ports:
                self.security_issues.append({
                    'type': 'DEFAULT',
                    'risk': 'LOW',
                    'message': f'{service} gebruikt standaard port {port}',
                    'impact': 'Maakt service makkelijker vindbaar voor aanvallers'
                })

    def _calculate_risk_score(self, open_ports):
        """Bereken totale risico score"""
        score = 0
        
        # Base score from open ports
        score += len(open_ports) * 5
        
        # Add points for vulnerabilities
        risk_weights = {'HIGH': 20, 'MEDIUM': 10, 'LOW': 5}
        
        for vuln in self.vulnerabilities:
            score += risk_weights[vuln['risk']]
            
        for issue in self.security_issues:
            score += risk_weights[issue['risk']]
            
        self.risk_score = min(100, score)

    def _generate_security_report(self):
        """Genereer security rapport"""
        risk_level = "LOW" if self.risk_score < 30 else "MEDIUM" if self.risk_score < 70 else "HIGH"
        
        report = {
            'risk_score': self.risk_score,
            'risk_level': risk_level,
            'vulnerabilities': self.vulnerabilities,
            'security_issues': self.security_issues,
            'recommendations': self._generate_recommendations()
        }
        
        return report

    def _generate_recommendations(self):
        """Genereer specifieke aanbevelingen"""
        recommendations = []
        
        if self.vulnerabilities or self.security_issues:
            recommendations.append({
                'priority': 'HIGH',
                'title': 'Kritieke Services Beschermen',
                'steps': [
                    'Implementeer firewall regels om toegang te beperken',
                    'Update alle services naar de laatste versie',
                    'Gebruik sterke authenticatie voor alle services',
                    'Monitor verdachte activiteiten'
                ]
            })
            
            if any(v['service'] == 'http' for v in self.vulnerabilities):
                recommendations.append({
                    'priority': 'MEDIUM',
                    'title': 'Web Security Verbeteren',
                    'steps': [
                        'Forceer HTTPS voor alle verkeer',
                        'Implementeer security headers',
                        'Gebruik moderne TLS versies',
                        'Configureer HSTS'
                    ]
                })
                
            if any(i['type'] == 'DATABASE' for i in self.security_issues):
                recommendations.append({
                    'priority': 'HIGH',
                    'title': 'Database Beveiliging',
                    'steps': [
                        'Beperk database toegang tot interne netwerk',
                        'Gebruik sterke wachtwoorden',
                        'Implementeer IP whitelisting',
                        'Versleutel gevoelige data'
                    ]
                })
        
        return recommendations 