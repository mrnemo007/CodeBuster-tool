import hashlib
import customtkinter as ctk
from utils import log_message
import base64
import secrets
import string

class HashGenerator:
    def __init__(self, app):
        self.app = app

    def setup_ui(self):
        """Setup de UI voor de Hash Generator"""
        # Clear bestaande widgets behalve main output
        for widget in self.app.main_frame.winfo_children():
            if widget != self.app.output_text:
                widget.destroy()

        # Main container
        container = ctk.CTkFrame(self.app.main_frame)
        container.grid(row=0, column=0, columnspan=3, padx=20, pady=10, sticky="ew")
        container.grid_columnconfigure(0, weight=1)

        # Input sectie
        input_frame = ctk.CTkFrame(container)
        input_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        input_frame.grid_columnconfigure(1, weight=1)

        # Text input
        input_label = ctk.CTkLabel(input_frame, text="Input Text:")
        input_label.grid(row=0, column=0, padx=5, pady=5)

        self.input_text = ctk.CTkTextbox(
            input_frame, 
            height=100,
            font=("Arial", 12)
        )
        self.input_text.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        # Hash algoritme selectie
        algo_frame = ctk.CTkFrame(container)
        algo_frame.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
        
        algo_label = ctk.CTkLabel(algo_frame, text="Hash Algorithm:")
        algo_label.pack(side="left", padx=5)

        algorithms = ["MD5", "SHA1", "SHA256", "SHA512", "SHA3-256", "Blake2b"]
        self.selected_algo = ctk.StringVar(value="SHA256")
        
        for algo in algorithms:
            radio = ctk.CTkRadioButton(
                algo_frame,
                text=algo,
                variable=self.selected_algo,
                value=algo,
                font=("Arial", 12)
            )
            radio.pack(side="left", padx=10)

        # Extra opties frame
        options_frame = ctk.CTkFrame(container)
        options_frame.grid(row=2, column=0, padx=10, pady=10, sticky="ew")

        # Salt optie
        self.use_salt = ctk.BooleanVar(value=False)
        salt_check = ctk.CTkCheckBox(
            options_frame,
            text="Add Salt",
            variable=self.use_salt,
            command=self.toggle_salt_input
        )
        salt_check.pack(side="left", padx=10)

        # Salt input
        self.salt_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        self.salt_frame.pack(side="left", padx=10, fill="x", expand=True)
        
        self.salt_entry = ctk.CTkEntry(
            self.salt_frame,
            placeholder_text="Enter salt or generate random",
            width=200
        )
        self.salt_entry.pack(side="left", padx=5)
        self.salt_entry.configure(state="disabled")

        self.generate_salt_btn = ctk.CTkButton(
            self.salt_frame,
            text="Generate Salt",
            command=self.generate_random_salt,
            width=100
        )
        self.generate_salt_btn.pack(side="left", padx=5)
        self.generate_salt_btn.configure(state="disabled")

        # Action buttons
        button_frame = ctk.CTkFrame(container)
        button_frame.grid(row=3, column=0, padx=10, pady=10, sticky="ew")
        button_frame.grid_columnconfigure((0,1,2), weight=1)

        # Hash button
        hash_btn = ctk.CTkButton(
            button_frame,
            text="Generate Hash",
            command=self.generate_hash,
            font=("Arial", 12, "bold"),
            height=40
        )
        hash_btn.grid(row=0, column=1, padx=5, pady=5)

        # Clear button
        clear_btn = ctk.CTkButton(
            button_frame,
            text="Clear",
            command=self.clear_input,
            font=("Arial", 12),
            fg_color="#555555",
            height=40
        )
        clear_btn.grid(row=0, column=2, padx=5, pady=5)

        # Hash output frame
        output_frame = ctk.CTkFrame(container)
        output_frame.grid(row=4, column=0, padx=10, pady=10, sticky="ew")
        output_frame.grid_columnconfigure(1, weight=1)

        # Hash output
        output_label = ctk.CTkLabel(output_frame, text="Hash Output:")
        output_label.grid(row=0, column=0, padx=5, pady=5)

        self.output_text = ctk.CTkTextbox(
            output_frame,
            height=100,
            font=("Courier", 12)
        )
        self.output_text.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        # Copy button
        copy_btn = ctk.CTkButton(
            output_frame,
            text="Copy",
            command=self.copy_to_clipboard,
            width=60
        )
        copy_btn.grid(row=0, column=2, padx=5, pady=5)

        # Ensure main output is visible
        self.app.output_text.grid(row=2, column=0, columnspan=3, padx=20, pady=20, sticky="nsew")

    def toggle_salt_input(self):
        """Toggle salt input velden"""
        state = "normal" if self.use_salt.get() else "disabled"
        self.salt_entry.configure(state=state)
        self.generate_salt_btn.configure(state=state)

    def generate_random_salt(self):
        """Genereer random salt"""
        # Genereer 16 bytes random salt
        alphabet = string.ascii_letters + string.digits + string.punctuation
        salt = ''.join(secrets.choice(alphabet) for _ in range(16))
        self.salt_entry.delete(0, "end")
        self.salt_entry.insert(0, salt)

    def generate_hash(self):
        """Genereer hash van input text"""
        input_text = self.input_text.get("1.0", "end-1c")
        if not input_text:
            log_message(self.app.output_text, "Please enter text to hash", "error")
            return

        # Get selected algorithm
        algo = self.selected_algo.get()
        
        # Add salt if enabled
        if self.use_salt.get():
            salt = self.salt_entry.get()
            if not salt:
                log_message(self.app.output_text, "Please enter or generate a salt", "error")
                return
            input_text = salt + input_text

        # Generate hash
        try:
            if algo == "MD5":
                hash_obj = hashlib.md5()
            elif algo == "SHA1":
                hash_obj = hashlib.sha1()
            elif algo == "SHA256":
                hash_obj = hashlib.sha256()
            elif algo == "SHA512":
                hash_obj = hashlib.sha512()
            elif algo == "SHA3-256":
                hash_obj = hashlib.sha3_256()
            elif algo == "Blake2b":
                hash_obj = hashlib.blake2b()

            hash_obj.update(input_text.encode())
            hash_result = hash_obj.hexdigest()
            
            # Show results
            self.output_text.delete("1.0", "end")
            self.output_text.insert("1.0", hash_result)
            
            # Log details
            log_message(self.app.output_text, "\nHash Generated Successfully:", "success")
            log_message(self.app.output_text, f"Algorithm: {algo}", "info")
            if self.use_salt.get():
                log_message(self.app.output_text, f"Salt Used: {salt}", "info")
            log_message(self.app.output_text, f"Hash: {hash_result}", "info")
            
        except Exception as e:
            log_message(self.app.output_text, f"Error generating hash: {str(e)}", "error")

    def clear_input(self):
        """Clear alle input velden"""
        self.input_text.delete("1.0", "end")
        self.output_text.delete("1.0", "end")
        self.salt_entry.delete(0, "end")
        self.app.output_text.delete("1.0", "end")

    def copy_to_clipboard(self):
        """Kopieer hash naar clipboard"""
        hash_text = self.output_text.get("1.0", "end-1c")
        if hash_text:
            self.app.clipboard_clear()
            self.app.clipboard_append(hash_text)
            log_message(self.app.output_text, "Hash copied to clipboard!", "success")
