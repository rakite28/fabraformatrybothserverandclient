import time
import ttkbootstrap as ttk
from tkinter import messagebox, Toplevel
from datetime import datetime

from .base_page import Page
from ..widgets.image_canvas import ImageCanvas
from ...helpers import load_client_config, calculate_cogs_values

class VerificationPage(Page):
    def __init__(self, master, app, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.app = app
        self.vars = {}
        self.printers = []
        self.printer_ids = {}

        main_pane = ttk.PanedWindow(self, orient=ttk.HORIZONTAL)
        main_pane.pack(fill=ttk.BOTH, expand=True, padx=10, pady=10)

        image_frame = ttk.Labelframe(main_pane, text="Print Summary Image", bootstyle="info")
        self.canvas = ImageCanvas(image_frame)
        self.canvas.pack(fill="both", expand=True, padx=5, pady=5)
        main_pane.add(image_frame, weight=1)

        form_scroll_frame = ttk.Frame(main_pane)
        self.form_frame = ttk.Labelframe(form_scroll_frame, text="Verify OCR Data", bootstyle="info")
        self.form_frame.pack(fill="both", expand=True)
        main_pane.add(form_scroll_frame, weight=1)

        self.build_widgets()
        self.is_active = False

    def load_data(self, image_path, ocr_data):
        self.is_active = True
        self.original_image_path = image_path
        self.image_timestamp = datetime.fromtimestamp(time.time()).isoformat()
        self.ocr_data = ocr_data

        self.canvas.load_image_from_path(image_path)
        self.app.run_threaded_task(self._load_dropdown_data, "Loading Data...")

    def _load_dropdown_data(self):
        printers = self.app.api.get_printers()
        pricing_data = self.app.api.get_filaments()
        self.after(0, self._on_data_loaded, printers, pricing_data)

    def _on_data_loaded(self, printers, pricing_data):
        self.printers = printers
        self.pricing_data = pricing_data
        self.populate_form()
        self.calculate_cogs()

    def build_widgets(self):
        for widget in self.form_frame.winfo_children():
            widget.destroy()

        row_counter = 0
        fields_to_build = ["Filename", "Date", "Printer", "Material", "Brand", "Filament Cost (₹/kg)", "Filament (g)", "Time (e.g. 7h 30m)", "Labour Time (min)", "Labour Rate (₹/hr)"]

        for label_text in fields_to_build:
            ttk.Label(self.form_frame, text=f"{label_text}:").grid(row=row_counter, column=0, sticky="w", pady=5, padx=10)
            self.vars[label_text] = ttk.StringVar()

            if "Printer" in label_text:
                p_frame = ttk.Frame(self.form_frame)
                self.printer_dropdown = ttk.Combobox(p_frame, textvariable=self.vars["Printer"], state="readonly", width=35)
                self.printer_dropdown.pack(side="left", fill="x", expand=True)
                ttk.Button(p_frame, text="Add New...", command=self.add_new_printer, bootstyle="outline-secondary").pack(side="left", padx=(5,0))
                p_frame.grid(row=row_counter, column=1, sticky="ew", pady=5, padx=10)
            elif "Material" in label_text:
                self.material_dropdown = ttk.Combobox(self.form_frame, textvariable=self.vars["Material"], state="readonly")
                self.material_dropdown.grid(row=row_counter, column=1, sticky="ew", pady=5, padx=10)
            elif "Brand" in label_text:
                b_frame = ttk.Frame(self.form_frame)
                self.brand_dropdown = ttk.Combobox(b_frame, textvariable=self.vars["Brand"], state="readonly")
                self.brand_dropdown.pack(side="left", fill="x", expand=True)
                ttk.Button(b_frame, text="Add New...", command=self.add_new_filament, bootstyle="outline-secondary").pack(side="left", padx=(5,0))
                b_frame.grid(row=row_counter, column=1, sticky="ew", pady=5, padx=10)
            else:
                entry = ttk.Entry(self.form_frame, textvariable=self.vars[label_text])
                if "Filament Cost" in label_text:
                    entry.config(state="readonly")
                entry.grid(row=row_counter, column=1, sticky="ew", pady=5, padx=10)
            row_counter += 1

        self.form_frame.grid_columnconfigure(1, weight=1)
        ttk.Separator(self.form_frame).grid(row=row_counter, column=0, columnspan=2, sticky="ew", pady=15)
        row_counter += 1

        ttk.Label(self.form_frame, text="User COGS (₹):", font="-weight bold").grid(row=row_counter, column=0, sticky="w", padx=10)
        self.user_cogs_label = ttk.Label(self.form_frame, text="0.00", font="-weight bold")
        self.user_cogs_label.grid(row=row_counter, column=1, sticky="w", padx=10)
        row_counter += 1

        btn_frame = ttk.Frame(self.form_frame)
        btn_frame.grid(row=row_counter, column=0, columnspan=2, pady=20)
        ttk.Button(btn_frame, text="Confirm", command=self.confirm, bootstyle="primary").pack(side="left", padx=10)
        ttk.Button(btn_frame, text="Cancel (Redo)", command=self.cancel, bootstyle="secondary").pack(side="left", padx=10)
        ttk.Button(btn_frame, text="Skip", command=self.skip, bootstyle="secondary").pack(side="left", padx=10)
        ttk.Button(btn_frame, text="Stop Monitoring", command=self.stop_monitoring, bootstyle="danger-outline").pack(side="right", padx=20)

        for var in self.vars.values():
            var.trace_add("write", self.calculate_cogs)
        self.material_dropdown.bind("<<ComboboxSelected>>", self.on_material_select)
        self.brand_dropdown.bind("<<ComboboxSelected>>", self.on_brand_select)

    def stop_monitoring(self):
        if messagebox.askyesno("Confirm Stop", "Stop the monitoring bot? The current file will not be processed.", parent=self):
            self.is_active = False
            self.app.on_stop()
            self.app.show_page("Monitor")

    def add_new_printer(self):
        dialog = AddNewPrinterDialog(self, self.app)
        self.wait_window(dialog)
        if hasattr(dialog, 'result') and dialog.result:
            self.app.run_threaded_task(self._load_dropdown_data, "Refreshing Data...")

    def add_new_filament(self):
        dialog = AddNewFilamentDialog(self, self.app)
        self.wait_window(dialog)
        if hasattr(dialog, 'result') and dialog.result:
            self.app.run_threaded_task(self._load_dropdown_data, "Refreshing Data...")

    def populate_form(self):
        printer_names = [f"{p['brand']} {p['model']}" for p in self.printers]
        self.printer_ids = {f"{p['brand']} {p['model']}": p['id'] for p in self.printers}
        self.printer_dropdown['values'] = sorted(printer_names)

        material_options = sorted(list(self.pricing_data.keys()))
        self.material_dropdown['values'] = material_options

        client_config = load_client_config()
        self.vars["Filename"].set(time.strftime("%Y%m%d-%H%M%S"))
        self.vars["Date"].set(datetime.fromisoformat(self.image_timestamp).strftime("%Y-%m-%d"))

        detected_printer_name = next((name for name, pid in self.printer_ids.items() if pid == self.ocr_data.get("detected_printer_id")), None)
        if detected_printer_name:
            self.vars["Printer"].set(detected_printer_name)
        elif self.printer_dropdown['values']:
            self.vars["Printer"].set(self.printer_dropdown['values'][0])

        detected_material = self.ocr_data.get("material", "")
        if detected_material and detected_material.upper() in self.material_dropdown['values']:
            self.vars["Material"].set(detected_material.upper())
        elif self.material_dropdown['values']:
            self.vars["Material"].set(self.material_dropdown['values'][0])

        self.vars["Filament (g)"].set(self.ocr_data.get("filament", 0.0))
        self.vars["Time (e.g. 7h 30m)"].set(self.ocr_data.get("time_str", "0h 0m"))
        self.vars["Labour Time (min)"].set("30")
        self.vars["Labour Rate (₹/hr)"].set(client_config.get("labour_rate", 100))
        self.update_brands_list()

    def calculate_cogs(self, *args):
        try:
            form_data = {label: var.get() for label, var in self.vars.items()}
            printer_id = self.printer_ids.get(form_data["Printer"])
            printer_data = next((p for p in self.printers if p["id"] == printer_id), None)
            filament_data = self.pricing_data.get(form_data["Material"], {}).get(form_data["Brand"], {})
            if not printer_data or not filament_data:
                return
            cogs = calculate_cogs_values(form_data, printer_data, filament_data)
            self.user_cogs_label.config(text=f"{cogs['user_cogs']:.2f}")
        except (ValueError, TypeError, KeyError):
            self.user_cogs_label.config(text="Error")

    def update_brands_list(self, brand_to_select=None):
        material = self.vars["Material"].get()
        brand_options = sorted(list(self.pricing_data.get(material, {}).keys()))
        self.brand_dropdown['values'] = brand_options
        if brand_to_select and brand_to_select in brand_options:
            self.vars["Brand"].set(brand_to_select)
        elif brand_options:
            self.vars["Brand"].set(brand_options[0])
        else:
            self.vars["Brand"].set("")
        self.update_cost_from_brand()

    def update_cost_from_brand(self, *args):
        brand = self.vars["Brand"].get()
        material = self.vars["Material"].get()
        cost = self.pricing_data.get(material, {}).get(brand, {}).get("price", 0) if brand and material else "0"
        self.vars["Filament Cost (₹/kg)"].set(str(cost))
        self.calculate_cogs()

    def on_material_select(self, event):
        self.update_brands_list()

    def on_brand_select(self, event):
        self.update_cost_from_brand()

    def confirm(self):
        if not self.vars["Printer"].get():
            return messagebox.showerror("Error", "Please select a printer.", parent=self)

        result = {label: var.get() for label, var in self.vars.items()}
        result["printer_id"] = self.printer_ids[self.vars["Printer"].get()]
        result["timestamp"] = self.image_timestamp

        self.is_active = False
        self.app.on_verification_complete(self.original_image_path, result)

    def cancel(self):
        self.is_active = False
        self.app.on_verification_complete(self.original_image_path, None)

    def skip(self):
        self.is_active = False
        self.app.on_verification_complete(self.original_image_path, "skip")

class AddNewPrinterDialog(Toplevel):
    # ... (implementation will be added if needed, or assumed to exist) ...
    pass

class AddNewFilamentDialog(Toplevel):
    # ... (implementation will be added if needed, or assumed to exist) ...
    pass