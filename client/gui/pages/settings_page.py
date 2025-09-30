import ttkbootstrap as ttk
from tkinter import filedialog, messagebox, END

from .base_page import Page
from ...helpers import load_client_config, save_client_config

class SettingsPage(Page):
    def __init__(self, master, app, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.app = app
        self.fields = {}

        ttk.Label(self, text="Client Settings", font=('Montserrat', 16, 'bold'), bootstyle="primary").pack(anchor="w", padx=10, pady=(5,10))

        container = ttk.Frame(self)
        container.pack(fill="both", expand=True, padx=10, pady=5)

        canvas = ttk.Canvas(container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview, bootstyle="round-light")
        self.scrollable_frame = ttk.Frame(canvas)
        self.scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.build_form()
        self.load_settings()

    def build_form(self):
        company_frame = ttk.Labelframe(self.scrollable_frame, text="Your Company Details (for Quotations)", bootstyle="info")
        company_frame.pack(fill="x", expand=True, padx=10, pady=10)

        self.COMPANY_KEYS = {
            "COMPANY_NAME": "entry", "COMPANY_ADDRESS": "entry",
            "COMPANY_CONTACT": "entry", "COMPANY_LOGO_PATH": "file",
            "TAX_RATE_PERCENT": "entry"
        }
        for i, (key, field_type) in enumerate(self.COMPANY_KEYS.items()):
            ttk.Label(company_frame, text=f"{key.replace('_', ' ').title()}:").grid(row=i, column=0, padx=5, pady=6, sticky="w")
            self.fields[key] = ttk.StringVar()
            ttk.Entry(company_frame, textvariable=self.fields[key], width=60).grid(row=i, column=1, padx=5, pady=6, sticky="ew")
            if field_type == "file":
                ttk.Button(company_frame, text="Browse...", command=lambda k=key: self.browse_file(k), bootstyle="secondary-outline").grid(row=i, column=2, padx=(5, 10), pady=6)
        company_frame.columnconfigure(1, weight=1)

        path_frame = ttk.Labelframe(self.scrollable_frame, text="File & Folder Paths", bootstyle="info")
        path_frame.pack(fill="x", expand=True, padx=10, pady=10)

        self.PATH_KEYS = {
            "IMAGE_INPUT_FOLDER": "folder",
            "PROCESSED_IMAGES_FOLDER": "folder",
            "SKIPPED_IMAGES_FOLDER": "folder"
        }
        for i, (key, field_type) in enumerate(self.PATH_KEYS.items()):
            ttk.Label(path_frame, text=f"{key.replace('_', ' ').title()}:").grid(row=i, column=0, padx=5, pady=6, sticky="w")
            self.fields[key] = ttk.StringVar()
            ttk.Entry(path_frame, textvariable=self.fields[key], width=60).grid(row=i, column=1, padx=5, pady=6, sticky="ew")
            if field_type == "folder":
                ttk.Button(path_frame, text="Browse...", command=lambda k=key: self.browse_folder(k), bootstyle="secondary-outline").grid(row=i, column=2, padx=(5, 10), pady=6)
        path_frame.columnconfigure(1, weight=1)

        other_frame = ttk.Labelframe(self.scrollable_frame, text="Other Settings", bootstyle="info")
        other_frame.pack(fill="x", expand=True, padx=10, pady=10)

        self.OTHER_KEYS = {"labour_rate": "entry"}
        for i, (key, field_type) in enumerate(self.OTHER_KEYS.items()):
            ttk.Label(other_frame, text=f"{key.replace('_', ' ').title()}:").grid(row=i, column=0, padx=5, pady=6, sticky="w")
            self.fields[key] = ttk.StringVar()
            ttk.Entry(other_frame, textvariable=self.fields[key], width=60).grid(row=i, column=1, padx=5, pady=6, sticky="ew")
        other_frame.columnconfigure(1, weight=1)

        self.ALL_KEYS = {**self.COMPANY_KEYS, **self.PATH_KEYS, **self.OTHER_KEYS}

        button_frame = ttk.Frame(self.scrollable_frame)
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Save Settings", command=self.save_settings, bootstyle="primary").pack(side="left", padx=10)
        ttk.Button(button_frame, text="Reload Current Settings", command=self.load_settings, bootstyle="secondary").pack(side="left", padx=10)

    def browse_folder(self, key):
        if folder_selected := filedialog.askdirectory(title=f"Select Folder for {key}"):
            self.fields[key].set(folder_selected)

    def browse_file(self, key):
        filetypes = [("Image files", "*.png *.jpg"), ("All files", "*.*")]
        if file_selected := filedialog.askopenfilename(title=f"Select File for {key}", filetypes=filetypes):
            self.fields[key].set(file_selected)

    def load_settings(self):
        config = load_client_config()
        for key, var in self.fields.items():
            var.set(config.get(key, ""))
        self.app.get_status_box().insert(END, "⚙️ Client settings loaded.\n")

    def save_settings(self):
        config_data = {key: var.get() for key, var in self.fields.items()}
        save_client_config(config_data)
        messagebox.showinfo("Success", "Settings have been saved.", parent=self)
        self.app.get_status_box().insert(END, "✔️ Settings saved successfully.\n")

    def on_show(self):
        self.load_settings()