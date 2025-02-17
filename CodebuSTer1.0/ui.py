import customtkinter as ctk
from scanner import PortScanner
from hash_generator import HashGenerator
from network_scanner import NetworkScanner
from utils import log_message
from theme import COLORS, STYLES
from PIL import Image
import os
from web_scanner import WebScanner
from metadata_extractor import MetadataExtractor
import random

class CyberToolkit(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Window setup
        self.title("CodeBuster 1.0")
        self.geometry("1200x800")
        
        # Configure appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        
        # Hide window initially (will be shown after splash screen)
        self.withdraw()
        
        # Load images
        self.load_images()
        
        # Configure grid weights
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Create background
        self.create_background()
        
        # Create sidebar
        self.create_sidebar()
        
        # Create main content area
        self.create_main_area()
        
        # Initialize tools
        self.scanner = PortScanner(self)
        self.hash_generator = HashGenerator(self)
        self.network_scanner = NetworkScanner(self)
        self.web_scanner = WebScanner(self)
        self.metadata_extractor = MetadataExtractor(self)

        # Start with port scanner
        self.show_port_scanner()
        
        # Center window on screen
        self.center_window()

    def load_images(self):
        """Load application images"""
        try:
            # Controleer of assets map bestaat, zo niet maak deze aan
            if not os.path.exists("assets"):
                os.makedirs("assets")
            
            # Controleer of logo bestaat, zo niet maak een placeholder
            logo_path = os.path.join("assets", "logo.png")
            if not os.path.exists(logo_path):
                self.create_placeholder_logo(logo_path)
            
            # Laad logo met grotere afmetingen
            self.logo_image = ctk.CTkImage(
                light_image=Image.open(logo_path),
                dark_image=Image.open(logo_path),
                size=(180, 180)  # Vergroot van 100x100 naar 180x180
            )
            
            # Controleer of achtergrond bestaat, zo niet maak een placeholder
            bg_path = os.path.join("assets", "sdsd.png")
            if not os.path.exists(bg_path):
                self.create_placeholder_background(bg_path)
            
            # Laad achtergrond
            self.bg_image = ctk.CTkImage(
                light_image=Image.open(bg_path),
                dark_image=Image.open(bg_path),
                size=(1200, 800)
            )
        except Exception as e:
            print(f"Error loading images: {str(e)}")
            # Maak placeholder images als er iets misgaat
            self.logo_image = None
            self.bg_image = None

    def create_placeholder_logo(self, path):
        """Maak een placeholder logo als de echte niet bestaat"""
        img = Image.new('RGB', (200, 200), color='#1a1a1a')
        # Teken een simpele octopus-achtige vorm
        from PIL import ImageDraw
        draw = ImageDraw.Draw(img)
        
        # Hoofdcirkel
        draw.ellipse([50, 50, 150, 150], fill='#00E5FF')
        # Tentakels
        for i in range(8):
            angle = i * 45
            import math
            x = 100 + 60 * math.cos(math.radians(angle))
            y = 100 + 60 * math.sin(math.radians(angle))
            draw.line([100, 100, x, y], fill='#00E5FF', width=10)
        img.save(path)

    def create_placeholder_background(self, path):
        """Maak een placeholder achtergrond als de echte niet bestaat"""
        img = Image.new('RGB', (1200, 800), color='#1a1a1a')
        from PIL import ImageDraw
        draw = ImageDraw.Draw(img)
        
        # Maak een cyaan gradient
        for i in range(0, 1200, 2):
            # Bereken kleur intensiteit gebaseerd op positie
            intensity = int(40 + (i / 1200) * 20)  # Varieert van 40 tot 60
            cyan = int((i / 1200) * 229)  # Varieert van 0 tot 229 (E5 in hex)
            color = f"#{intensity:02x}{intensity+cyan:02x}{intensity+cyan:02x}"
            draw.line([(i, 0), (i, 800)], fill=color, width=2)
            
        # Voeg wat matrix-achtige elementen toe
        from random import randint
        for _ in range(100):
            x = randint(0, 1200)
            y = randint(0, 800)
            size = randint(2, 5)
            opacity = randint(40, 255)
            draw.rectangle([x, y, x+size, y+size], 
                         fill=f'#{0:02x}{opacity:02x}{opacity:02x}')
        
        img.save(path)

    def create_background(self):
        """Create animated cyberpunk background"""
        self.bg_frame = ctk.CTkFrame(self, corner_radius=0)
        self.bg_frame.grid(row=0, column=0, columnspan=2, rowspan=4, sticky="nsew")
        
        # Laad de cyberpunk achtergrond
        bg_image = Image.open("assets/background.png")  # Je cyberpunk circuit achtergrond
        bg_photo = ctk.CTkImage(bg_image, size=(self.winfo_screenwidth(), self.winfo_screenheight()))
        
        self.bg_label = ctk.CTkLabel(
            self.bg_frame,
            image=bg_photo,
            text=""
        )
        self.bg_label.grid(row=0, column=0, sticky="nsew")

    def create_sidebar(self):
        """Create the cyberpunk-styled sidebar"""
        # Sidebar container met donkere achtergrond
        self.sidebar_frame = ctk.CTkFrame(
            self,
            width=300,
            corner_radius=15,
            fg_color="#0c0f16",  # Donkere achtergrond zonder transparantie
            border_width=2,
            border_color="#00ffff"
        )
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew", padx=20, pady=20)
        self.sidebar_frame.grid_rowconfigure(8, weight=1)

        # Voeg een subtiele glow toe
        glow_frame = ctk.CTkFrame(
            self.sidebar_frame,
            fg_color="#0c0f16",
            corner_radius=15,
            border_width=1,
            border_color="#00ffff"
        )
        glow_frame.place(relx=0, rely=0, relwidth=1, relheight=1)

        # Logo area met cyber effect
        logo_frame = ctk.CTkFrame(
            self.sidebar_frame,
            fg_color="transparent",
            corner_radius=10
        )
        logo_frame.grid(row=0, column=0, padx=35, pady=(30, 15), sticky="ew")

        if self.logo_image:
            logo_image_label = ctk.CTkLabel(
                logo_frame,
                image=self.logo_image,
                text=""
            )
            logo_image_label.pack(pady=10)

        # Cyber-styled app name
        logo_label = ctk.CTkLabel(
            logo_frame,
            text="CODEBUSTER",
            font=("Orbitron", 28, "bold"),  # Cyber-style font
            text_color="#00ffff"  # Cyan kleur
        )
        logo_label.pack(pady=5)

        version_label = ctk.CTkLabel(
            logo_frame,
            text="v1.0 // SECURITY SUITE",
            font=("Share Tech Mono", 12),  # Tech-style font
            text_color="#0088ff"
        )
        version_label.pack()

        # Categorie headers met cyber-styling
        self.create_category_label("// NETWORK TOOLS", 1)
        self.port_scan_button = self.create_nav_button("⚡ PORT SCANNER", self.show_port_scanner, 2)
        self.network_button = self.create_nav_button("🌐 NETWORK RECON", self.show_network_scanner, 3)
        self.web_button = self.create_nav_button("🔒 WEB SECURITY", self.show_web_scanner, 4)

        self.create_category_label("// ANALYSIS TOOLS", 5)
        self.hash_button = self.create_nav_button("🔑 HASH ENGINE", self.show_hash_generator, 6)
        self.metadata_button = self.create_nav_button("📄 META EXTRACT", self.show_metadata_extractor, 7)

        # Stats frame met cyber-effect
        stats_frame = ctk.CTkFrame(
            self.sidebar_frame,
            fg_color="#0d1117",
            corner_radius=10,
            border_width=2,
            border_color="#00ffff"
        )
        stats_frame.grid(row=8, column=0, padx=20, pady=20, sticky="ew")

        session_label = ctk.CTkLabel(
            stats_frame,
            text="ACTIVE SESSION",
            font=("Share Tech Mono", 14, "bold"),
            text_color="#00ffff"
        )
        session_label.pack(pady=5)

        from datetime import datetime
        start_time = datetime.now().strftime("%H:%M:%S")
        time_label = ctk.CTkLabel(
            stats_frame,
            text=f"UPTIME: {start_time}",
            font=("Share Tech Mono", 12),
            text_color="#0088ff"
        )
        time_label.pack()

        # Footer met cyber-styling en klikbare link
        footer_frame = ctk.CTkFrame(
            self.sidebar_frame,
            fg_color="transparent"
        )
        footer_frame.grid(row=9, column=0, padx=20, pady=20, sticky="ew")

        footer_label = ctk.CTkButton(  # Verander van Label naar Button
            footer_frame,
            text="// RDM DEVELOPMENT",
            font=("Share Tech Mono", 12),
            text_color="#0088ff",
            fg_color="transparent",
            hover_color="#002222",
            command=self.show_developer_info  # Voeg command toe
        )
        footer_label.pack()

    def create_category_label(self, text, row):
        """Create a cyber-styled category label"""
        label = ctk.CTkLabel(
            self.sidebar_frame,
            text=text,
            font=("Share Tech Mono", 14, "bold"),
            text_color="#00ffff"
        )
        label.grid(row=row, column=0, padx=25, pady=(20, 5), sticky="w")

    def create_nav_button(self, text, command, row):
        """Create a cyber-styled navigation button"""
        button = ctk.CTkButton(
            self.sidebar_frame,
            text=text,
            command=command,
            fg_color="transparent",
            font=("Share Tech Mono", 12),
            anchor="w",
            height=40,
            corner_radius=8,
            hover_color="#002222",  # Donkere cyan kleur ipv rgba
            border_width=1,
            border_color="#00ffff",
            text_color="#ffffff"
        )
        button.grid(row=row, column=0, padx=20, pady=2, sticky="ew")
        return button

    def create_main_area(self):
        """Create the main content area"""
        self.main_frame = ctk.CTkFrame(
            self,
            fg_color="#0c0f16",  # Donkere achtergrond
            corner_radius=15,
            border_width=2,
            border_color="#00ffff"
        )
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(2, weight=1)

        # Terminal-style output met cyber look
        self.output_text = ctk.CTkTextbox(
            self.main_frame,
            width=800,
            height=400,
            font=("Share Tech Mono", 12),  # Cyber font
            fg_color="#000000",  # Zwarte achtergrond
            text_color="#00ffff",  # Cyan text
            border_width=1,
            border_color="#00ffff",
            corner_radius=10
        )
        self.output_text.grid(row=2, column=0, columnspan=3, padx=20, pady=20, sticky="nsew")

        # Configure colored output tags met cyber kleuren
        self.output_text.tag_config("info", foreground="#00ffff")  # Cyan
        self.output_text.tag_config("warning", foreground="#ffff00")  # Geel
        self.output_text.tag_config("error", foreground="#ff0000")  # Rood
        self.output_text.tag_config("success", foreground="#00ff00")  # Groen
        self.output_text.tag_config("header", foreground="#ff00ff")  # Magenta

    def show_port_scanner(self):
        self.scanner.setup_ui()
        self._update_nav_buttons(self.port_scan_button)

    def show_hash_generator(self):
        self.hash_generator.setup_ui()
        self._update_nav_buttons(self.hash_button)

    def show_network_scanner(self):
        self.network_scanner.setup_ui()
        self._update_nav_buttons(self.network_button)

    def show_web_scanner(self):
        """Toon de web scanner"""
        self.web_scanner.setup_ui()
        self._update_nav_buttons(self.web_button)

    def show_metadata_extractor(self):
        """Toon de Metadata Extractor interface"""
        self.metadata_extractor.setup_ui()
        self._update_nav_buttons(self.metadata_button)

    def _update_nav_buttons(self, active_button):
        """Update navigation button states"""
        buttons = [
            self.port_scan_button, 
            self.hash_button, 
            self.network_button,
            self.web_button,
            self.metadata_button
        ]
        for button in buttons:
            if button == active_button:
                button.configure(fg_color=COLORS["accent_hover"])
            else:
                button.configure(fg_color="transparent")

    def center_window(self):
        """Center the window on the screen"""
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        window_width = 1200
        window_height = 800
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.geometry(f"{window_width}x{window_height}+{x}+{y}")

    def show_developer_info(self):
        """Toon developer en project informatie in een scrollbare popup"""
        popup = ctk.CTkToplevel(self)
        popup.title("Project Information")
        
        # Bereken optimale grootte (80% van scherm)
        screen_width = popup.winfo_screenwidth()
        screen_height = popup.winfo_screenheight()
        width = min(int(screen_width * 0.8), 800)
        height = min(int(screen_height * 0.8), 800)
        popup.geometry(f"{width}x{height}")
        
        popup.configure(fg_color="#0c0f16")
        
        # Scrollbare container
        scroll_frame = ctk.CTkScrollableFrame(
            popup,
            fg_color="#0d1117",
            corner_radius=10,
            border_width=1,
            border_color="#00ffff",
            scrollbar_button_color="#1f538d",
            scrollbar_button_hover_color="#002222"
        )
        scroll_frame.pack(padx=20, pady=20, fill="both", expand=True)
        
        # Header sectie
        header_label = ctk.CTkLabel(
            scroll_frame,
            text="CodeBuster Security Suite",
            font=("Share Tech Mono", 24, "bold"),
            text_color="#00ffff"
        )
        header_label.pack(pady=(10, 5))
        
        version_label = ctk.CTkLabel(
            scroll_frame,
            text="Beta Version 1.0",
            font=("Share Tech Mono", 14),
            text_color="#ff0000"
        )
        version_label.pack(pady=(0, 20))
        
        # Project beschrijving
        desc_frame = ctk.CTkFrame(
            scroll_frame,
            fg_color="#000000",
            corner_radius=8,
            border_width=1,
            border_color="#00ffff"
        )
        desc_frame.pack(padx=10, pady=(0, 20), fill="x")
        
        desc_label = ctk.CTkLabel(
            desc_frame,
            text="An advanced security testing and analysis toolkit\n"
                 "developed for security professionals and researchers.",
            font=("Share Tech Mono", 12),
            text_color="#00ffff",
            wraplength=width-100  # Dynamische text wrap
        )
        desc_label.pack(pady=10)
        
        # Secties met info
        sections = {
            "Current Features": [
                "Port Scanning & Service Detection",
                "Network Reconnaissance",
                "Web Security Analysis",
                "Hash Generation & Verification",
                "Metadata Extraction & Analysis"
            ],
            "Upcoming Features": [
                "Advanced Vulnerability Scanning",
                "Custom Exploit Development",
                "Wireless Network Analysis",
                "Password Strength Testing",
                "Traffic Analysis & Packet Inspection",
                "API Security Testing"
            ],
            "Technologies": [
                "Python 3.11+",
                "CustomTkinter (Modern UI)",
                "Nmap (Network Scanning)",
                "Requests (Web Testing)",
                "Socket (Low-level Networking)",
                "PyPDF2 & python-docx (File Analysis)",
                "SQLite (Local Database)"
            ]
        }
        
        for title, items in sections.items():
            self._create_section(scroll_frame, title, items)
        
        # Developer info
        dev_frame = ctk.CTkFrame(
            scroll_frame,
            fg_color="transparent"
        )
        dev_frame.pack(pady=20, padx=10, fill="x")
        
        dev_label = ctk.CTkLabel(
            dev_frame,
            text="Developed by RDM Development",
            font=("Share Tech Mono", 12, "bold"),
            text_color="#0088ff"
        )
        dev_label.pack()
        
        # Contact links
        links_frame = ctk.CTkFrame(
            scroll_frame,
            fg_color="transparent"
        )
        links_frame.pack(pady=(0, 20), fill="x")
        
        github_btn = ctk.CTkButton(
            links_frame,
            text="GitHub Repository",
            font=("Share Tech Mono", 12),
            fg_color="#1f538d",
            hover_color="#002222",
            command=lambda: self.open_link("github.com/mrnemo007")
        )
        github_btn.pack(side="left", padx=20, expand=True)
        
        email_btn = ctk.CTkButton(
            links_frame,
            text="Contact Developer",
            font=("Share Tech Mono", 12),
            fg_color="#1f538d",
            hover_color="#002222",
            command=lambda: self.open_link("codebusternemo@hotmail.com")
        )
        email_btn.pack(side="right", padx=20, expand=True)
        
        # Close button
        close_btn = ctk.CTkButton(
            scroll_frame,
            text="Close",
            font=("Share Tech Mono", 12),
            fg_color="#1f538d",
            hover_color="#002222",
            command=popup.destroy
        )
        close_btn.pack(pady=(0, 10))
        
        # Center popup
        popup.update_idletasks()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        popup.geometry(f'+{x}+{y}')
        
        popup.transient(self)
        popup.grab_set()

    def _create_section(self, parent, title, items):
        """Helper functie om secties te maken met lijsten"""
        frame = ctk.CTkFrame(
            parent,
            fg_color="transparent"
        )
        frame.pack(pady=10, padx=20, fill="x")
        
        title_label = ctk.CTkLabel(
            frame,
            text=title,
            font=("Share Tech Mono", 14, "bold"),
            text_color="#00ffff"
        )
        title_label.pack(anchor="w")
        
        for item in items:
            item_frame = ctk.CTkFrame(
                frame,
                fg_color="transparent"
            )
            item_frame.pack(fill="x", pady=2)
            
            bullet = ctk.CTkLabel(
                item_frame,
                text="•",
                font=("Share Tech Mono", 12),
                text_color="#0088ff"
            )
            bullet.pack(side="left", padx=(20, 5))
            
            item_label = ctk.CTkLabel(
                item_frame,
                text=item,
                font=("Share Tech Mono", 12),
                text_color="#ffffff"
            )
            item_label.pack(side="left")

    def open_link(self, url):
        """Open een URL in de standaard browser"""
        import webbrowser
        if url.startswith("github"):
            webbrowser.open(f"https://{url}")
        elif "@" in url:  # Email adres
            webbrowser.open(f"mailto:{url}")
