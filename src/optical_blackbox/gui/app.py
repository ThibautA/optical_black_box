"""Optical BlackBox GUI Application.

Modern graphical interface for creating, extracting, and managing .obb files.
Supports both v1.0 (single recipient) and v2.0 (multi-recipient) formats.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
from typing import Optional
import traceback

from ..core.version import detect_obb_version
from ..formats.obb_file import OBBReader, OBBWriter
from ..formats.obb_file_v2 import OBBReaderV2, OBBWriterV2
from ..models.metadata import OBBMetadata, OBBMetadataV2
from ..crypto.keys import KeyManager
from ..crypto.rsa_oaep import generate_rsa_keypair
from ..core.result import Ok, Err


class OBBGuiApp:
    """Main GUI application for Optical BlackBox."""
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Optical BlackBox - OBB Manager")
        self.root.geometry("900x700")
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_tab = self._create_create_tab()
        self.extract_tab = self._create_extract_tab()
        self.inspect_tab = self._create_inspect_tab()
        self.keygen_tab = self._create_keygen_tab()
        
        self.notebook.add(self.create_tab, text="Create OBB")
        self.notebook.add(self.extract_tab, text="Extract OBB")
        self.notebook.add(self.inspect_tab, text="Inspect OBB")
        self.notebook.add(self.keygen_tab, text="Generate Keys")
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def _create_create_tab(self) -> ttk.Frame:
        """Create the 'Create OBB' tab."""
        frame = ttk.Frame(self.notebook, padding=10)
        
        # Version selection
        version_frame = ttk.LabelFrame(frame, text="Format Version", padding=10)
        version_frame.pack(fill='x', pady=(0, 10))
        
        self.version_var = tk.StringVar(value="v2.0")
        ttk.Radiobutton(version_frame, text="v1.0 (Single Recipient - ECDH)", 
                       variable=self.version_var, value="v1.0",
                       command=self._on_version_change).pack(anchor='w')
        ttk.Radiobutton(version_frame, text="v2.0 (Multi-Recipient - RSA-OAEP)", 
                       variable=self.version_var, value="v2.0",
                       command=self._on_version_change).pack(anchor='w')
        
        # Input file
        input_frame = ttk.LabelFrame(frame, text="Input File", padding=10)
        input_frame.pack(fill='x', pady=(0, 10))
        
        self.input_file_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.input_file_var, width=60).pack(side='left', padx=(0, 5))
        ttk.Button(input_frame, text="Browse...", command=self._browse_input_file).pack(side='left')
        
        # Output file
        output_frame = ttk.LabelFrame(frame, text="Output File (.obb)", padding=10)
        output_frame.pack(fill='x', pady=(0, 10))
        
        self.output_file_var = tk.StringVar()
        ttk.Entry(output_frame, textvariable=self.output_file_var, width=60).pack(side='left', padx=(0, 5))
        ttk.Button(output_frame, text="Browse...", command=self._browse_output_file).pack(side='left')
        
        # Metadata
        metadata_frame = ttk.LabelFrame(frame, text="Metadata", padding=10)
        metadata_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(metadata_frame, text="Vendor ID:").grid(row=0, column=0, sticky='w', pady=2)
        self.vendor_id_var = tk.StringVar()
        ttk.Entry(metadata_frame, textvariable=self.vendor_id_var, width=40).grid(row=0, column=1, pady=2)
        
        ttk.Label(metadata_frame, text="Model ID:").grid(row=1, column=0, sticky='w', pady=2)
        self.model_id_var = tk.StringVar()
        ttk.Entry(metadata_frame, textvariable=self.model_id_var, width=40).grid(row=1, column=1, pady=2)
        
        ttk.Label(metadata_frame, text="Description:").grid(row=2, column=0, sticky='w', pady=2)
        self.description_var = tk.StringVar()
        ttk.Entry(metadata_frame, textvariable=self.description_var, width=40).grid(row=2, column=1, pady=2)
        
        # Keys frame (dynamic based on version)
        self.keys_frame = ttk.LabelFrame(frame, text="Recipient Keys", padding=10)
        self.keys_frame.pack(fill='both', expand=True, pady=(0, 10))
        
        self.recipient_keys = []  # List of (key_path, name, widgets)
        self._setup_keys_frame()
        
        # Create button
        ttk.Button(frame, text="Create OBB File", command=self._create_obb).pack(pady=10)
        
        return frame
    
    def _on_version_change(self):
        """Handle version selection change."""
        self._setup_keys_frame()
    
    def _setup_keys_frame(self):
        """Setup the keys frame based on selected version."""
        # Clear existing widgets
        for widget in self.keys_frame.winfo_children():
            widget.destroy()
        
        self.recipient_keys.clear()
        
        if self.version_var.get() == "v1.0":
            # Single recipient (ECDH)
            ttk.Label(self.keys_frame, text="Platform Public Key (PEM):").pack(anchor='w', pady=(0, 5))
            
            key_frame = ttk.Frame(self.keys_frame)
            key_frame.pack(fill='x', pady=(0, 5))
            
            key_var = tk.StringVar()
            ttk.Entry(key_frame, textvariable=key_var, width=50).pack(side='left', padx=(0, 5))
            ttk.Button(key_frame, text="Browse...", 
                      command=lambda: self._browse_key(key_var)).pack(side='left')
            
            self.recipient_keys.append((key_var, None, None))
        else:
            # Multiple recipients (RSA-OAEP)
            ttk.Label(self.keys_frame, text="Platform Public Keys (RSA):").pack(anchor='w', pady=(0, 5))
            
            # Add first recipient
            self._add_recipient_row()
            
            # Add recipient button
            ttk.Button(self.keys_frame, text="+ Add Recipient", 
                      command=self._add_recipient_row).pack(pady=(5, 0))
    
    def _add_recipient_row(self):
        """Add a row for a recipient key."""
        row_frame = ttk.Frame(self.keys_frame)
        row_frame.pack(fill='x', pady=2)
        
        ttk.Label(row_frame, text=f"#{len(self.recipient_keys) + 1}:").pack(side='left', padx=(0, 5))
        
        key_var = tk.StringVar()
        ttk.Entry(row_frame, textvariable=key_var, width=35).pack(side='left', padx=(0, 5))
        ttk.Button(row_frame, text="Browse", 
                  command=lambda: self._browse_key(key_var)).pack(side='left', padx=(0, 5))
        
        ttk.Label(row_frame, text="Name:").pack(side='left', padx=(5, 5))
        name_var = tk.StringVar()
        ttk.Entry(row_frame, textvariable=name_var, width=15).pack(side='left', padx=(0, 5))
        
        # Remove button
        remove_btn = ttk.Button(row_frame, text="✕", width=3,
                               command=lambda: self._remove_recipient_row(row_frame))
        remove_btn.pack(side='left')
        
        self.recipient_keys.append((key_var, name_var, row_frame))
    
    def _remove_recipient_row(self, row_frame):
        """Remove a recipient row."""
        self.recipient_keys = [(k, n, w) for k, n, w in self.recipient_keys if w != row_frame]
        row_frame.destroy()
    
    def _browse_input_file(self):
        """Browse for input file."""
        filename = filedialog.askopenfilename(
            title="Select Input File",
            filetypes=[
                ("Zemax Files", "*.zmx"),
                ("All Files", "*.*")
            ]
        )
        if filename:
            self.input_file_var.set(filename)
            # Auto-suggest output filename
            if not self.output_file_var.get():
                output = Path(filename).with_suffix('.obb')
                self.output_file_var.set(str(output))
    
    def _browse_output_file(self):
        """Browse for output file."""
        filename = filedialog.asksaveasfilename(
            title="Save OBB File",
            defaultextension=".obb",
            filetypes=[("OBB Files", "*.obb"), ("All Files", "*.*")]
        )
        if filename:
            self.output_file_var.set(filename)
    
    def _browse_key(self, var: tk.StringVar):
        """Browse for key file."""
        filename = filedialog.askopenfilename(
            title="Select Key File",
            filetypes=[("PEM Files", "*.pem"), ("Public Key", "*.pub"), ("All Files", "*.*")]
        )
        if filename:
            var.set(filename)
    
    def _create_obb(self):
        """Create OBB file."""
        try:
            # Validate inputs
            input_file = Path(self.input_file_var.get())
            if not input_file.exists():
                messagebox.showerror("Error", "Input file does not exist")
                return
            
            output_file = Path(self.output_file_var.get())
            if not output_file.parent.exists():
                messagebox.showerror("Error", "Output directory does not exist")
                return
            
            vendor_id = self.vendor_id_var.get().strip()
            model_id = self.model_id_var.get().strip()
            if not vendor_id or not model_id:
                messagebox.showerror("Error", "Vendor ID and Model ID are required")
                return
            
            # Read input file
            self.status_var.set("Reading input file...")
            payload_bytes = input_file.read_bytes()
            
            if self.version_var.get() == "v1.0":
                # V1.0 - Single recipient
                key_path = self.recipient_keys[0][0].get().strip()
                if not key_path:
                    messagebox.showerror("Error", "Platform key is required")
                    return
                
                platform_key = Path(key_path).read_bytes()
                
                metadata = OBBMetadata(
                    vendor_id=vendor_id,
                    model_id=model_id,
                    description=self.description_var.get().strip() or None,
                    original_filename=input_file.name,
                )
                
                self.status_var.set("Encrypting with v1.0...")
                result = OBBWriter.write(
                    output_path=output_file,
                    payload_bytes=payload_bytes,
                    metadata=metadata,
                    platform_public_key=platform_key,
                )
            else:
                # V2.0 - Multi-recipient
                recipient_keys = []
                for key_var, name_var, _ in self.recipient_keys:
                    key_path = key_var.get().strip()
                    if not key_path:
                        continue
                    
                    public_key = Path(key_path).read_bytes()
                    name = name_var.get().strip() if name_var else None
                    recipient_keys.append((public_key, name))
                
                if not recipient_keys:
                    messagebox.showerror("Error", "At least one recipient key is required")
                    return
                
                metadata = OBBMetadataV2(
                    vendor_id=vendor_id,
                    model_id=model_id,
                    description=self.description_var.get().strip() or None,
                    original_filename=input_file.name,
                )
                
                self.status_var.set(f"Encrypting with v2.0 ({len(recipient_keys)} recipients)...")
                result = OBBWriterV2.write(
                    output_path=output_file,
                    payload_bytes=payload_bytes,
                    metadata=metadata,
                    recipient_public_keys=recipient_keys,
                )
            
            if isinstance(result, Ok):
                self.status_var.set("OBB file created successfully!")
                messagebox.showinfo("Success", f"OBB file created:\n{output_file}")
            else:
                self.status_var.set("Failed to create OBB file")
                messagebox.showerror("Error", f"Failed to create OBB file:\n{result.error}")
        
        except Exception as e:
            self.status_var.set("Error")
            messagebox.showerror("Error", f"An error occurred:\n{str(e)}\n\n{traceback.format_exc()}")
    
    def _create_extract_tab(self) -> ttk.Frame:
        """Create the 'Extract OBB' tab."""
        frame = ttk.Frame(self.notebook, padding=10)
        
        # OBB file
        obb_frame = ttk.LabelFrame(frame, text="OBB File", padding=10)
        obb_frame.pack(fill='x', pady=(0, 10))
        
        self.extract_obb_var = tk.StringVar()
        ttk.Entry(obb_frame, textvariable=self.extract_obb_var, width=60).pack(side='left', padx=(0, 5))
        ttk.Button(obb_frame, text="Browse...", command=self._browse_obb_file).pack(side='left')
        
        # Private key
        key_frame = ttk.LabelFrame(frame, text="Platform Private Key", padding=10)
        key_frame.pack(fill='x', pady=(0, 10))
        
        self.extract_key_var = tk.StringVar()
        ttk.Entry(key_frame, textvariable=self.extract_key_var, width=60).pack(side='left', padx=(0, 5))
        ttk.Button(key_frame, text="Browse...", command=self._browse_extract_key).pack(side='left')
        
        # Output file
        extract_output_frame = ttk.LabelFrame(frame, text="Output File", padding=10)
        extract_output_frame.pack(fill='x', pady=(0, 10))
        
        self.extract_output_var = tk.StringVar()
        ttk.Entry(extract_output_frame, textvariable=self.extract_output_var, width=60).pack(side='left', padx=(0, 5))
        ttk.Button(extract_output_frame, text="Browse...", command=self._browse_extract_output).pack(side='left')
        
        # Extract button
        ttk.Button(frame, text="Extract & Decrypt", command=self._extract_obb).pack(pady=10)
        
        # Info display
        info_frame = ttk.LabelFrame(frame, text="File Information", padding=10)
        info_frame.pack(fill='both', expand=True)
        
        self.extract_info_text = scrolledtext.ScrolledText(info_frame, height=15, width=80)
        self.extract_info_text.pack(fill='both', expand=True)
        
        return frame
    
    def _browse_obb_file(self):
        """Browse for OBB file to extract."""
        filename = filedialog.askopenfilename(
            title="Select OBB File",
            filetypes=[("OBB Files", "*.obb"), ("All Files", "*.*")]
        )
        if filename:
            self.extract_obb_var.set(filename)
            # Auto-detect version and suggest output
            try:
                version = detect_obb_version(Path(filename))
                self.extract_info_text.delete('1.0', tk.END)
                self.extract_info_text.insert('1.0', f"Detected format: v{version}.0\n")
                
                if not self.extract_output_var.get():
                    output = Path(filename).with_suffix('.zmx')
                    self.extract_output_var.set(str(output))
            except Exception as e:
                self.extract_info_text.delete('1.0', tk.END)
                self.extract_info_text.insert('1.0', f"Error detecting version: {e}\n")
    
    def _browse_extract_key(self):
        """Browse for private key."""
        filename = filedialog.askopenfilename(
            title="Select Private Key",
            filetypes=[("PEM Files", "*.pem"), ("All Files", "*.*")]
        )
        if filename:
            self.extract_key_var.set(filename)
    
    def _browse_extract_output(self):
        """Browse for extract output file."""
        filename = filedialog.asksaveasfilename(
            title="Save Extracted File",
            defaultextension=".zmx",
            filetypes=[("Zemax Files", "*.zmx"), ("All Files", "*.*")]
        )
        if filename:
            self.extract_output_var.set(filename)
    
    def _extract_obb(self):
        """Extract and decrypt OBB file."""
        try:
            obb_file = Path(self.extract_obb_var.get())
            if not obb_file.exists():
                messagebox.showerror("Error", "OBB file does not exist")
                return
            
            key_file = Path(self.extract_key_var.get())
            if not key_file.exists():
                messagebox.showerror("Error", "Private key file does not exist")
                return
            
            output_file = Path(self.extract_output_var.get())
            if not output_file.parent.exists():
                messagebox.showerror("Error", "Output directory does not exist")
                return
            
            # Detect version
            self.status_var.set("Detecting format version...")
            version = detect_obb_version(obb_file)
            
            # Read private key
            private_key = key_file.read_bytes()
            
            # Decrypt based on version
            if version == 1:
                self.status_var.set("Decrypting v1.0 file...")
                result = OBBReader.read_and_decrypt(obb_file, private_key)
            else:
                self.status_var.set("Decrypting v2.0 file...")
                result = OBBReaderV2.read_and_decrypt(obb_file, private_key)
            
            if isinstance(result, Err):
                self.status_var.set("Decryption failed")
                messagebox.showerror("Error", f"Decryption failed:\n{result.error}")
                return
            
            metadata, file_bytes = result.value
            
            # Write output file
            self.status_var.set("Writing output file...")
            output_file.write_bytes(file_bytes)
            
            # Display info
            info = f"Successfully extracted!\n\n"
            info += f"Format: v{version}.0\n"
            info += f"Vendor: {metadata.vendor_id}\n"
            info += f"Model: {metadata.model_id}\n"
            info += f"Original filename: {metadata.original_filename}\n"
            info += f"Description: {metadata.description or 'N/A'}\n"
            info += f"Size: {len(file_bytes):,} bytes\n"
            info += f"\nOutput: {output_file}"
            
            if version == 2:
                info += f"\n\nRecipients: {len(metadata.recipients)}"
            
            self.extract_info_text.delete('1.0', tk.END)
            self.extract_info_text.insert('1.0', info)
            
            self.status_var.set("Extraction successful!")
            messagebox.showinfo("Success", f"File extracted to:\n{output_file}")
        
        except Exception as e:
            self.status_var.set("Error")
            messagebox.showerror("Error", f"An error occurred:\n{str(e)}\n\n{traceback.format_exc()}")
    
    def _create_inspect_tab(self) -> ttk.Frame:
        """Create the 'Inspect OBB' tab."""
        frame = ttk.Frame(self.notebook, padding=10)
        
        # OBB file
        obb_frame = ttk.LabelFrame(frame, text="OBB File", padding=10)
        obb_frame.pack(fill='x', pady=(0, 10))
        
        self.inspect_obb_var = tk.StringVar()
        ttk.Entry(obb_frame, textvariable=self.inspect_obb_var, width=60).pack(side='left', padx=(0, 5))
        ttk.Button(obb_frame, text="Browse...", command=self._browse_inspect_file).pack(side='left', padx=(0, 5))
        ttk.Button(obb_frame, text="Inspect", command=self._inspect_obb).pack(side='left')
        
        # Info display
        info_frame = ttk.LabelFrame(frame, text="Metadata", padding=10)
        info_frame.pack(fill='both', expand=True)
        
        self.inspect_text = scrolledtext.ScrolledText(info_frame, height=25, width=80)
        self.inspect_text.pack(fill='both', expand=True)
        
        return frame
    
    def _browse_inspect_file(self):
        """Browse for OBB file to inspect."""
        filename = filedialog.askopenfilename(
            title="Select OBB File",
            filetypes=[("OBB Files", "*.obb"), ("All Files", "*.*")]
        )
        if filename:
            self.inspect_obb_var.set(filename)
    
    def _inspect_obb(self):
        """Inspect OBB file metadata."""
        try:
            obb_file = Path(self.inspect_obb_var.get())
            if not obb_file.exists():
                messagebox.showerror("Error", "OBB file does not exist")
                return
            
            self.status_var.set("Reading metadata...")
            
            # Detect version
            version = detect_obb_version(obb_file)
            
            # Read metadata
            if version == 1:
                result = OBBReader.read_metadata(obb_file)
            else:
                result = OBBReaderV2.read_metadata(obb_file)
            
            if isinstance(result, Err):
                self.status_var.set("Failed to read metadata")
                messagebox.showerror("Error", f"Failed to read metadata:\n{result.error}")
                return
            
            metadata = result.value
            
            # Format metadata info
            info = f"OBB FILE INFORMATION\n"
            info += f"{'=' * 60}\n\n"
            info += f"Format Version: v{version}.0\n"
            info += f"File: {obb_file.name}\n"
            info += f"Size: {obb_file.stat().st_size:,} bytes\n\n"
            info += f"METADATA\n"
            info += f"{'-' * 60}\n"
            info += f"Vendor ID: {metadata.vendor_id}\n"
            info += f"Model ID: {metadata.model_id}\n"
            info += f"Original Filename: {metadata.original_filename or 'N/A'}\n"
            info += f"Description: {metadata.description or 'N/A'}\n"
            info += f"Created: {metadata.created_at or 'N/A'}\n"
            
            if version == 2:
                info += f"\nRECIPIENTS ({len(metadata.recipients)})\n"
                info += f"{'-' * 60}\n"
                for i, recipient in enumerate(metadata.recipients, 1):
                    info += f"\n#{i}: {recipient.platform_name or 'Unnamed'}\n"
                    info += f"  Fingerprint: {recipient.platform_fingerprint[:32]}...\n"
                
                if metadata.sidecar_url:
                    info += f"\nSidecar URL: {metadata.sidecar_url}\n"
            
            self.inspect_text.delete('1.0', tk.END)
            self.inspect_text.insert('1.0', info)
            
            self.status_var.set("Metadata loaded successfully")
        
        except Exception as e:
            self.status_var.set("Error")
            messagebox.showerror("Error", f"An error occurred:\n{str(e)}\n\n{traceback.format_exc()}")
    
    def _create_keygen_tab(self) -> ttk.Frame:
        """Create the 'Generate Keys' tab."""
        frame = ttk.Frame(self.notebook, padding=10)
        
        # Key type selection
        type_frame = ttk.LabelFrame(frame, text="Key Type", padding=10)
        type_frame.pack(fill='x', pady=(0, 10))
        
        self.key_type_var = tk.StringVar(value="rsa")
        ttk.Radiobutton(type_frame, text="RSA-2048 (for v2.0 multi-recipient)", 
                       variable=self.key_type_var, value="rsa").pack(anchor='w')
        ttk.Radiobutton(type_frame, text="ECDSA P-256 (for v1.0 single recipient)", 
                       variable=self.key_type_var, value="ecdsa").pack(anchor='w')
        
        # Output directory
        dir_frame = ttk.LabelFrame(frame, text="Output Directory", padding=10)
        dir_frame.pack(fill='x', pady=(0, 10))
        
        self.keygen_dir_var = tk.StringVar(value=str(Path.cwd()))
        ttk.Entry(dir_frame, textvariable=self.keygen_dir_var, width=60).pack(side='left', padx=(0, 5))
        ttk.Button(dir_frame, text="Browse...", command=self._browse_keygen_dir).pack(side='left')
        
        # Prefix
        prefix_frame = ttk.LabelFrame(frame, text="Key Name Prefix", padding=10)
        prefix_frame.pack(fill='x', pady=(0, 10))
        
        self.keygen_prefix_var = tk.StringVar(value="platform")
        ttk.Entry(prefix_frame, textvariable=self.keygen_prefix_var, width=30).pack()
        ttk.Label(prefix_frame, text="(e.g., 'platform' → platform_private.pem, platform_public.pem)").pack()
        
        # Generate button
        ttk.Button(frame, text="Generate Key Pair", command=self._generate_keys).pack(pady=10)
        
        # Info display
        info_frame = ttk.LabelFrame(frame, text="Output", padding=10)
        info_frame.pack(fill='both', expand=True)
        
        self.keygen_text = scrolledtext.ScrolledText(info_frame, height=15, width=80)
        self.keygen_text.pack(fill='both', expand=True)
        
        return frame
    
    def _browse_keygen_dir(self):
        """Browse for key generation directory."""
        dirname = filedialog.askdirectory(title="Select Output Directory")
        if dirname:
            self.keygen_dir_var.set(dirname)
    
    def _generate_keys(self):
        """Generate key pair."""
        try:
            output_dir = Path(self.keygen_dir_var.get())
            if not output_dir.exists():
                messagebox.showerror("Error", "Output directory does not exist")
                return
            
            prefix = self.keygen_prefix_var.get().strip()
            if not prefix:
                prefix = "key"
            
            self.status_var.set("Generating keys...")
            
            if self.key_type_var.get() == "rsa":
                # Generate RSA keys
                private_pem, public_pem = generate_rsa_keypair(2048)
                
                private_path = output_dir / f"{prefix}_private.pem"
                public_path = output_dir / f"{prefix}_public.pem"
                
                private_path.write_bytes(private_pem)
                public_path.write_bytes(public_pem)
                
                info = "RSA-2048 Key Pair Generated!\n\n"
                info += f"Private Key: {private_path}\n"
                info += f"Public Key: {public_path}\n\n"
                info += "⚠️  Keep the private key secure!\n"
                info += "Share the public key with vendors to receive encrypted files.\n"
            else:
                # Generate ECDSA keys
                private_key, public_key = KeyManager.generate_keypair()
                
                private_path = output_dir / f"{prefix}_private.pem"
                public_path = output_dir / f"{prefix}_public.pem"
                
                KeyManager.save_private_key(private_key, private_path)
                KeyManager.save_public_key(public_key, public_path)
                
                info = "ECDSA P-256 Key Pair Generated!\n\n"
                info += f"Private Key: {private_path}\n"
                info += f"Public Key: {public_path}\n\n"
                info += "⚠️  Keep the private key secure!\n"
                info += "Share the public key with vendors to receive encrypted files.\n"
            
            self.keygen_text.delete('1.0', tk.END)
            self.keygen_text.insert('1.0', info)
            
            self.status_var.set("Keys generated successfully!")
            messagebox.showinfo("Success", f"Keys generated in:\n{output_dir}")
        
        except Exception as e:
            self.status_var.set("Error")
            messagebox.showerror("Error", f"An error occurred:\n{str(e)}\n\n{traceback.format_exc()}")


def launch_gui():
    """Launch the Optical BlackBox GUI application."""
    root = tk.Tk()
    app = OBBGuiApp(root)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
