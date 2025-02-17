import customtkinter as ctk
import time
import random
from PIL import Image, ImageDraw
import os
from theme import COLORS

class SplashScreen(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        
        # Store parent and callback
        self.parent = parent
        self.completion_callback = None
        self.parent.withdraw()  # Hide main window
        
        # Window setup
        self.title("")
        self.geometry("800x600")
        self.overrideredirect(True)
        self.configure(fg_color="#1a1a1a")
        
        # Center window
        self.center_window()
        
        # Make window modal
        self.transient(parent)
        self.grab_set()
        
        # Initialize state
        self.matrix_running = False
        self.loading_complete = False
        
        # Setup UI
        self.setup_ui()
        
        # Start loading sequence
        self.after(100, self.start_loading_sequence)
        
    def setup_ui(self):
        """Setup all UI elements"""
        # Load background image
        try:
            bg_path = os.path.join("assets", "sdsd.png")
            if os.path.exists(bg_path):
                bg_image = ctk.CTkImage(
                    light_image=Image.open(bg_path),
                    dark_image=Image.open(bg_path),
                    size=(800, 600)  # Splash screen size
                )
                # Background label
                bg_label = ctk.CTkLabel(
                    self,
                    image=bg_image,
                    text=""
                )
                bg_label.place(relx=0, rely=0, relwidth=1, relheight=1)
        except Exception as e:
            print(f"Error loading splash background: {str(e)}")

        # Main container (met transparante achtergrond)
        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.pack(expand=True, fill="both", padx=20, pady=20)
        
        # Matrix canvas setup
        self.setup_matrix_canvas()
        
        # Logo and labels setup
        self.setup_logo_and_labels()
        
        # Progress elements setup
        self.setup_progress_elements()
        
        # Add decorative elements
        self.add_decorative_elements()

    def center_window(self):
        """Center the window on the screen"""
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        window_width = 800
        window_height = 600
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.geometry(f"{window_width}x{window_height}+{x}+{y}")

    def setup_matrix_canvas(self):
        """Setup the Matrix effect canvas"""
        self.matrix_canvas = ctk.CTkCanvas(
            self.container,
            width=800,
            height=600,
            bg="#1a1a1a",
            highlightthickness=0
        )
        self.matrix_canvas.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.matrix_chars = []
        self.start_matrix_effect()

    def setup_logo_and_labels(self):
        """Setup the logo and labels"""
        # Logo frame
        logo_frame = ctk.CTkFrame(self.container, fg_color="transparent")
        logo_frame.pack(pady=(50, 20))
        
        # Load and display logo
        try:
            logo_path = os.path.join("assets", "logo.png")
            if os.path.exists(logo_path):
                logo_image = ctk.CTkImage(
                    light_image=Image.open(logo_path),
                    dark_image=Image.open(logo_path),
                    size=(200, 200)
                )
                logo_label = ctk.CTkLabel(
                    logo_frame,
                    image=logo_image,
                    text=""
                )
                logo_label.pack()
        except Exception as e:
            print(f"Error loading logo: {str(e)}")
        
        # App name with cyber font style
        self.logo_label = ctk.CTkLabel(
            self.container,
            text="CodeBuster 1.0",
            font=("Terminal", 40, "bold"),
            text_color=COLORS["accent"]
        )
        self.logo_label.pack(pady=(20, 10))
        
        # Hacker tools icons
        tools_frame = ctk.CTkFrame(self.container, fg_color="transparent")
        tools_frame.pack(pady=10)
        
        tool_icons = ["🔒", "⚡", "🔍", "⚔️", "🛡️"]
        for icon in tool_icons:
            label = ctk.CTkLabel(
                tools_frame,
                text=icon,
                font=("Arial", 24),
                text_color=COLORS["accent"]
            )
            label.pack(side="left", padx=10)
        
        # Company name with glow effect
        self.company_label = ctk.CTkLabel(
            self.container,
            text="RDM Development",
            font=("Arial", 20),
            text_color="#ffffff"
        )
        self.company_label.pack(pady=10)

    def setup_progress_elements(self):
        """Setup the progress elements"""
        # Cyber-style progress bar
        self.progress_frame = ctk.CTkFrame(
            self.container,
            fg_color="transparent"
        )
        self.progress_frame.pack(pady=(30, 10))
        
        self.progress_bar = ctk.CTkProgressBar(
            self.progress_frame,
            width=400,
            height=15,
            border_width=0,
            progress_color=COLORS["accent"],
            fg_color="#333333"
        )
        self.progress_bar.pack()
        self.progress_bar.set(0)
        
        # Status text with typing effect
        self.status_label = ctk.CTkLabel(
            self.container,
            text="",
            font=("Terminal", 12),
            text_color="#888888"
        )
        self.status_label.pack(pady=5)

    def add_decorative_elements(self):
        """Voeg decoratieve cyber-elementen toe"""
        # Hoek decoraties
        corners = [(0, 0), (800, 0), (0, 600), (800, 600)]
        for x, y in corners:
            self.matrix_canvas.create_line(
                x, y, x + (20 if x == 0 else -20), y,
                fill=COLORS["accent"], width=2
            )
            self.matrix_canvas.create_line(
                x, y, x, y + (20 if y == 0 else -20),
                fill=COLORS["accent"], width=2
            )

    def start_matrix_effect(self):
        """Start the Matrix-style background effect"""
        self.matrix_chars = []
        for _ in range(50):  # Aantal kolommen
            x = random.randint(0, 800)
            self.matrix_chars.append({
                'x': x,
                'y': random.randint(-500, 0),
                'speed': random.randint(2, 5),
                'char': random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
            })
        self.update_matrix()

    def start_loading_sequence(self):
        """Start the loading sequence"""
        self.matrix_running = True
        self.update_matrix()
        self.run_loading_animation()

    def update_matrix(self):
        """Single update of matrix animation"""
        if not self.matrix_running:
            return
            
        try:
            self.matrix_canvas.delete("all")
            self.add_decorative_elements()  # Redraw decorative elements
            
            for char in self.matrix_chars:
                self.matrix_canvas.create_text(
                    char['x'], char['y'],
                    text=char['char'],
                    fill="#00E5FF",
                    font=("Courier", 14)
                )
                char['y'] += char['speed']
                if char['y'] > 600:
                    char['y'] = random.randint(-50, 0)
                    char['x'] = random.randint(0, 800)
                    char['char'] = random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
            
            if self.winfo_exists() and self.matrix_running:
                self.after(50, self.update_matrix)
                
        except Exception as e:
            print(f"Matrix update error: {str(e)}")

    def run_loading_animation(self):
        """Run the loading animation sequence"""
        messages = [
            "Initializing system...",
            "Loading security modules...",
            "Configuring network scanners...",
            "Preparing cyber tools...",
            "Starting CodeBuster..."
        ]
        
        def animate_text(i=0, j=0):
            if not self.winfo_exists() or self.loading_complete:
                return
                
            if i < len(messages):
                msg = messages[i]
                if j <= len(msg):
                    self.status_label.configure(text=msg[:j] + "█")
                    progress = (i * len(msg) + j) / (len(messages) * len(msg))
                    self.progress_bar.set(progress)
                    
                    if j < len(msg):
                        self.after(30, lambda: animate_text(i, j + 1))
                    else:
                        self.after(500, lambda: animate_text(i + 1, 0))
            else:
                self.finish_loading()
        
        animate_text()

    def set_completion_callback(self, callback):
        """Set the callback for when splash screen completes"""
        self.completion_callback = callback

    def finish_loading(self):
        """Complete the loading sequence"""
        if self.winfo_exists():
            self.status_label.configure(text="System Ready!")
            self.progress_bar.set(1)
            self.after(500, self.close)

    def close(self):
        """Clean closure of splash screen"""
        try:
            self.matrix_running = False
            self.loading_complete = True
            self.grab_release()
            
            # Call completion callback before destroying
            if self.completion_callback:
                self.completion_callback()
                
            self.destroy()
            
        except Exception as e:
            print(f"Error closing splash screen: {str(e)}")

    def on_close(self):
        """Handle window close event"""
        self.close() 