import customtkinter as ctk
from PIL import Image
import os
from datetime import datetime
import threading
from utils import log_message

# Optional imports with fallbacks
try:
    from PyPDF2 import PdfReader
except ImportError:
    PdfReader = None
    print("Warning: PyPDF2 not installed. PDF extraction will be disabled.")

try:
    import docx
except ImportError:
    docx = None
    print("Warning: python-docx not installed. Office document extraction will be disabled.")

try:
    import exifread
except ImportError:
    exifread = None
    print("Warning: ExifRead not installed. EXIF extraction will be limited.")

class MetadataExtractor:
    def __init__(self, app):
        self.app = app
        self.scanning = False
        
        # Update checkboxes based on available modules
        self.pdf_available = PdfReader is not None
        self.doc_available = docx is not None
        self.exif_available = exifread is not None

    def setup_ui(self):
        """Setup de UI voor de Metadata Extractor"""
        for widget in self.app.main_frame.winfo_children():
            if widget != self.app.output_text:
                widget.destroy()

        # Scanner frame
        self.scanner_frame = ctk.CTkFrame(self.app.main_frame)
        self.scanner_frame.grid(row=0, column=0, columnspan=3, padx=20, pady=10, sticky="ew")

        # File selectie
        file_label = ctk.CTkLabel(self.scanner_frame, text="File Path:")
        file_label.grid(row=0, column=0, padx=5, pady=5)

        self.file_entry = ctk.CTkEntry(self.scanner_frame, width=400)
        self.file_entry.grid(row=0, column=1, padx=5, pady=5)
        self.file_entry.insert(0, "Enter file path or drag & drop file...")

        browse_button = ctk.CTkButton(
            self.scanner_frame,
            text="Browse",
            command=self._browse_file,
            width=100,
            fg_color="#1f538d"
        )
        browse_button.grid(row=0, column=2, padx=5, pady=5)

        # File type filters
        filters_frame = ctk.CTkFrame(self.scanner_frame)
        filters_frame.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky="ew")

        self.image_check = ctk.CTkCheckBox(
            filters_frame,
            text="Images (JPG, PNG, TIFF)",
            variable=ctk.BooleanVar(value=True)
        )
        self.image_check.grid(row=0, column=0, padx=5, pady=5)

        self.pdf_check = ctk.CTkCheckBox(
            filters_frame,
            text="PDF Documents",
            variable=ctk.BooleanVar(value=True)
        )
        self.pdf_check.grid(row=0, column=1, padx=5, pady=5)

        self.doc_check = ctk.CTkCheckBox(
            filters_frame,
            text="Office Documents",
            variable=ctk.BooleanVar(value=True)
        )
        self.doc_check.grid(row=0, column=2, padx=5, pady=5)

        # Update checkbox states based on available modules
        self.pdf_check.configure(state="normal" if self.pdf_available else "disabled")
        self.doc_check.configure(state="normal" if self.doc_available else "disabled")
        
        if not any([self.pdf_available, self.doc_available, self.exif_available]):
            log_message(self.app.output_text, 
                "Warning: No metadata extraction modules available. Please install required packages.", 
                "warning")

        # Start scan button
        self.scan_button = ctk.CTkButton(
            self.scanner_frame,
            text="Extract Metadata",
            command=self.start_extraction,
            fg_color="#1f538d"
        )
        self.scan_button.grid(row=2, column=0, columnspan=3, padx=5, pady=10)

        # Progress frame
        self.setup_progress_frame()

    def _browse_file(self):
        """Open file browser"""
        from tkinter import filedialog
        filetypes = [
            ('All supported files', '*.jpg *.jpeg *.png *.tiff *.pdf *.doc *.docx'),
            ('Images', '*.jpg *.jpeg *.png *.tiff'),
            ('PDF files', '*.pdf'),
            ('Word documents', '*.doc *.docx')
        ]
        filename = filedialog.askopenfilename(filetypes=filetypes)
        if filename:
            self.file_entry.delete(0, 'end')
            self.file_entry.insert(0, filename)

    def setup_progress_frame(self):
        """Setup progress frame"""
        self.progress_frame = ctk.CTkFrame(self.app.main_frame)
        self.progress_frame.grid(row=1, column=0, columnspan=3, padx=20, pady=10, sticky="ew")
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

    def start_extraction(self):
        """Start metadata extractie"""
        filepath = self.file_entry.get()
        if not filepath or filepath == "Enter file path or drag & drop file...":
            log_message(self.app.output_text, "Please select a file", "error")
            return

        if not os.path.exists(filepath):
            log_message(self.app.output_text, "File not found", "error")
            return

        self.scanning = True
        
        # Reset en toon output
        self.app.output_text.delete("1.0", "end")
        log_message(self.app.output_text, "Starting Metadata Extraction...", "header")
        log_message(self.app.output_text, f"Target File: {filepath}\n", "info")
        
        # Toon progress
        self.progress_bar.set(0)
        self.percentage_label.configure(text="0%")
        self.status_label.configure(text="Initializing extraction...")
        self.progress_frame.grid()
        
        # Update button
        self.scan_button.configure(text="Stop Extraction", command=self.stop_extraction)
        
        # Start extraction thread
        thread = threading.Thread(target=self._run_extraction, args=(filepath,))
        thread.daemon = True
        thread.start()

    def stop_extraction(self):
        """Stop metadata extractie"""
        self.scanning = False
        self.scan_button.configure(state="disabled")
        self.status_label.configure(text="STOPPING EXTRACTION...")
        log_message(self.app.output_text, "\nStopping metadata extraction...", "warning")

    def extraction_completed(self):
        """Reset UI na extractie"""
        self.scanning = False
        self.scan_button.configure(text="Extract Metadata", command=self.start_extraction, state="normal")
        self.progress_frame.grid_remove()
        self.update_progress(0, "")

    def update_progress(self, progress_value, status_text):
        """Update progress bar"""
        self.progress_bar.set(progress_value)
        percentage = int(progress_value * 100)
        self.percentage_label.configure(text=f"{percentage}%")
        self.status_label.configure(text=status_text)

    def _run_extraction(self, filepath):
        """Voer metadata extractie uit"""
        try:
            metadata = {}
            file_ext = os.path.splitext(filepath)[1].lower()

            # Image metadata
            if file_ext in ['.jpg', '.jpeg', '.png', '.tiff'] and self.image_check.get():
                self.update_progress(0.3, "Extracting image metadata...")
                metadata.update(self._extract_image_metadata(filepath))

            # PDF metadata
            elif file_ext == '.pdf' and self.pdf_check.get():
                self.update_progress(0.3, "Extracting PDF metadata...")
                metadata.update(self._extract_pdf_metadata(filepath))

            # Office document metadata
            elif file_ext in ['.doc', '.docx'] and self.doc_check.get():
                self.update_progress(0.3, "Extracting document metadata...")
                metadata.update(self._extract_doc_metadata(filepath))

            self.update_progress(0.8, "Generating report...")
            self._generate_metadata_report(filepath, metadata)
            
            self.update_progress(1.0, "Extraction complete")
            
        except Exception as e:
            log_message(self.app.output_text, f"Error extracting metadata: {str(e)}", "error")
        finally:
            self.extraction_completed()

    def _extract_image_metadata(self, filepath):
        """Extract metadata from images"""
        metadata = {
            'type': 'image',
            'exif': {},
            'basic': {}
        }
        
        # Basic image info (using PIL)
        try:
            with Image.open(filepath) as img:
                metadata['basic'] = {
                    'format': img.format,
                    'mode': img.mode,
                    'size': f"{img.size[0]}x{img.size[1]}",
                    'dpi': img.info.get('dpi', 'Unknown')
                }
        except Exception as e:
            metadata['basic']['error'] = str(e)

        # EXIF data (using exifread if available)
        if self.exif_available:
            try:
                with open(filepath, 'rb') as f:
                    tags = exifread.process_file(f)
                    for tag, value in tags.items():
                        if tag not in ('JPEGThumbnail', 'TIFFThumbnail'):
                            metadata['exif'][tag] = str(value)
            except Exception as e:
                metadata['exif']['error'] = str(e)
                
        return metadata

    def _extract_pdf_metadata(self, filepath):
        """Extract metadata from PDF files"""
        if not self.pdf_available:
            return {'type': 'pdf', 'error': 'PyPDF2 not installed'}
            
        metadata = {
            'type': 'pdf',
            'info': {},
            'statistics': {}
        }
        
        try:
            with open(filepath, 'rb') as f:
                pdf = PdfReader(f)
                
                # Document info
                if pdf.metadata:
                    metadata['info'] = {k: str(v) for k, v in pdf.metadata.items()}
                
                # Document statistics
                metadata['statistics'] = {
                    'pages': len(pdf.pages),
                    'encrypted': pdf.is_encrypted,
                    'size': f"{os.path.getsize(filepath):,} bytes"
                }
                
                # Extract text from first page for content type analysis
                if len(pdf.pages) > 0:
                    first_page = pdf.pages[0].extract_text()
                    metadata['statistics']['first_page_length'] = len(first_page)
        except Exception as e:
            metadata['error'] = str(e)
            
        return metadata

    def _extract_doc_metadata(self, filepath):
        """Extract metadata from Office documents"""
        if not self.doc_available:
            return {'type': 'document', 'error': 'python-docx not installed'}
            
        metadata = {
            'type': 'document',
            'core_properties': {},
            'extended_properties': {},
            'statistics': {}
        }
        
        try:
            doc = docx.Document(filepath)
            
            # Core properties
            core_props = doc.core_properties
            metadata['core_properties'] = {
                'author': core_props.author,
                'category': core_props.category,
                'comments': core_props.comments,
                'content_status': core_props.content_status,
                'created': core_props.created,
                'identifier': core_props.identifier,
                'keywords': core_props.keywords,
                'language': core_props.language,
                'last_modified_by': core_props.last_modified_by,
                'last_printed': core_props.last_printed,
                'modified': core_props.modified,
                'revision': core_props.revision,
                'subject': core_props.subject,
                'title': core_props.title,
                'version': core_props.version
            }
            
            # Document statistics
            metadata['statistics'] = {
                'paragraphs': len(doc.paragraphs),
                'sections': len(doc.sections),
                'size': f"{os.path.getsize(filepath):,} bytes"
            }
        except Exception as e:
            metadata['error'] = str(e)
            
        return metadata

    def _generate_metadata_report(self, filepath, metadata):
        """Generate metadata report"""
        log_message(self.app.output_text, "\nMetadata Extraction Report\n", "header")
        log_message(self.app.output_text, "="*50 + "\n", "header")
        
        # Basic file information
        log_message(self.app.output_text, "File Information:", "header")
        log_message(self.app.output_text, f"Path: {filepath}", "info")
        log_message(self.app.output_text, f"Size: {os.path.getsize(filepath):,} bytes", "info")
        log_message(self.app.output_text, f"Created: {datetime.fromtimestamp(os.path.getctime(filepath))}", "info")
        log_message(self.app.output_text, f"Modified: {datetime.fromtimestamp(os.path.getmtime(filepath))}", "info")
        
        if metadata.get('type') == 'image':
            # Image metadata
            if metadata.get('basic'):
                log_message(self.app.output_text, "\nImage Information:", "header")
                for key, value in metadata['basic'].items():
                    log_message(self.app.output_text, f"{key.title()}: {value}", "info")
            
            if metadata.get('exif'):
                log_message(self.app.output_text, "\nEXIF Metadata:", "header")
                for tag, value in metadata['exif'].items():
                    log_message(self.app.output_text, f"{tag}: {value}", "info")
                    
        elif metadata.get('type') == 'pdf':
            # PDF metadata
            if metadata.get('info'):
                log_message(self.app.output_text, "\nDocument Information:", "header")
                for key, value in metadata['info'].items():
                    log_message(self.app.output_text, f"{key}: {value}", "info")
            
            if metadata.get('statistics'):
                log_message(self.app.output_text, "\nDocument Statistics:", "header")
                for key, value in metadata['statistics'].items():
                    log_message(self.app.output_text, f"{key.replace('_', ' ').title()}: {value}", "info")
                    
        elif metadata.get('type') == 'document':
            # Office document metadata
            if metadata.get('core_properties'):
                log_message(self.app.output_text, "\nDocument Properties:", "header")
                for key, value in metadata['core_properties'].items():
                    if value:
                        log_message(self.app.output_text, f"{key.replace('_', ' ').title()}: {value}", "info")
            
            if metadata.get('statistics'):
                log_message(self.app.output_text, "\nDocument Statistics:", "header")
                for key, value in metadata['statistics'].items():
                    log_message(self.app.output_text, f"{key.replace('_', ' ').title()}: {value}", "info") 