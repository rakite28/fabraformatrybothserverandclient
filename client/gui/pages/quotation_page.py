import json
import re
import ttkbootstrap as ttk
from tkinter import filedialog, messagebox

from .base_page import Page
from ..widgets.log_selection_dialog import LogSelectionDialog
from ..widgets.slicer_dialog import SlicerDialog
from ...helpers import load_client_config, calculate_cogs_values

class QuotationPage(Page):
    def __init__(self, master, app, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.app = app
        self.vars = {}
        self.part_vars = {}
        self.printers = []
        self.printer_ids = {}
        self.pricing_data = {}
        self.current_part_cogs = 0.0

        ttk.Label(self, text="Quotation Generator", font=('Montserrat', 16, 'bold'), bootstyle="primary").pack(anchor="w", padx=10, pady=(5,10))

        main_pane = ttk.PanedWindow(self, orient=ttk.HORIZONTAL)
        main_pane.pack(fill=ttk.BOTH, expand=True, padx=10, pady=10)

        left_frame = ttk.Frame(main_pane)
        main_pane.add(left_frame, weight=1)

        self._create_customer_widgets(left_frame)
        self._create_load_widgets(left_frame)
        self._create_add_part_widgets(left_frame)

        right_pane = ttk.PanedWindow(main_pane, orient=ttk.VERTICAL)
        main_pane.add(right_pane, weight=1)

        items_frame = ttk.Labelframe(right_pane, text="Quotation Items", bootstyle="info")
        right_pane.add(items_frame, weight=2)
        self._create_items_widgets(items_frame)

        bottom_right_frame = ttk.Frame(right_pane)
        right_pane.add(bottom_right_frame, weight=1)

        pricing_frame = ttk.Labelframe(bottom_right_frame, text="Pricing", bootstyle="info")
        pricing_frame.pack(fill="x", padx=5)
        self._create_pricing_widgets(pricing_frame)

        ttk.Button(bottom_right_frame, text="Generate Quotation PDF", command=self.generate_pdf, bootstyle="success").pack(pady=20)

    def _create_customer_widgets(self, parent):
        customer_frame = ttk.Labelframe(parent, text="Customer Details", bootstyle="info")
        customer_frame.pack(fill="x", pady=(0, 10))
        for i, label in enumerate(["Customer Name", "Company Name"]):
            ttk.Label(customer_frame, text=f"{label}:").grid(row=i, column=0, sticky="w", padx=10, pady=5)
            self.vars[label] = ttk.StringVar()
            ttk.Entry(customer_frame, textvariable=self.vars[label], width=40).grid(row=i, column=1, sticky="ew", padx=10, pady=5)
        customer_frame.columnconfigure(1, weight=1)

    def _create_load_widgets(self, parent):
        load_frame = ttk.Labelframe(parent, text="Load Data for a New Part", bootstyle="info")
        load_frame.pack(fill="x", pady=(0, 10))
        button_container = ttk.Frame(load_frame)
        button_container.pack(padx=10, pady=10)
        ttk.Button(button_container, text="Upload STL for Quoting...", command=self.open_stl_slicer_dialog, bootstyle="primary").pack(side="left", padx=(0, 5))
        ttk.Button(button_container, text="Load from Image (OCR)", command=self.load_from_image, bootstyle="secondary").pack(side="left", padx=5)
        ttk.Button(button_container, text="Load from Logs", command=self.load_from_logs, bootstyle="secondary").pack(side="left", padx=5)

    def _create_add_part_widgets(self, parent):
        calc_frame = ttk.Labelframe(parent, text="Add Part Details (Manual/Loaded)", bootstyle="info")
        calc_frame.pack(fill="x")
        row_counter = 0

        ttk.Label(calc_frame, text="Part Name:").grid(row=row_counter, column=0, sticky="w", pady=5, padx=10)
        self.part_vars["Part Name"] = ttk.StringVar()
        ttk.Entry(calc_frame, textvariable=self.part_vars["Part Name"]).grid(row=row_counter, column=1, sticky="ew", pady=5, padx=10)
        row_counter += 1

        ttk.Label(calc_frame, text="Printer Used:").grid(row=row_counter, column=0, sticky="w", pady=5, padx=10)
        self.part_vars["Printer"] = ttk.StringVar()
        self.printer_dropdown = ttk.Combobox(calc_frame, textvariable=self.part_vars["Printer"], state="readonly", width=35)
        self.printer_dropdown.grid(row=row_counter, column=1, sticky="ew", pady=5, padx=10)
        row_counter += 1

        ttk.Label(calc_frame, text="Material:").grid(row=row_counter, column=0, sticky="w", pady=5, padx=10)
        self.part_vars["Material"] = ttk.StringVar()
        self.material_dropdown = ttk.Combobox(calc_frame, textvariable=self.part_vars["Material"], state="readonly")
        self.material_dropdown.grid(row=row_counter, column=1, sticky="ew", pady=5, padx=10)
        row_counter += 1

        ttk.Label(calc_frame, text="Filament Brand:").grid(row=row_counter, column=0, sticky="w", pady=5, padx=10)
        self.part_vars["Brand"] = ttk.StringVar()
        self.brand_dropdown = ttk.Combobox(calc_frame, textvariable=self.part_vars["Brand"], state="readonly")
        self.brand_dropdown.grid(row=row_counter, column=1, sticky="ew", pady=5, padx=10)
        row_counter += 1

        for label in ["Filament (g)", "Time (e.g. 7h 30m)", "Labour Time (min)"]:
            ttk.Label(calc_frame, text=f"{label}:").grid(row=row_counter, column=0, sticky="w", pady=5, padx=10)
            self.part_vars[label] = ttk.StringVar(value="0")
            ttk.Entry(calc_frame, textvariable=self.part_vars[label]).grid(row=row_counter, column=1, sticky="ew", pady=5, padx=10)
            row_counter += 1

        calc_frame.grid_columnconfigure(1, weight=1)
        ttk.Button(calc_frame, text="Add Part to Quote", command=self.add_part, bootstyle="success").grid(row=row_counter, column=0, columnspan=2, pady=10)

        for key in ["Printer", "Material", "Brand", "Filament (g)", "Time (e.g. 7h 30m)", "Labour Time (min)"]:
            self.part_vars[key].trace_add("write", self.calculate_part_cogs)

        self.printer_dropdown.bind("<<ComboboxSelected>>", self.calculate_part_cogs)
        self.material_dropdown.bind("<<ComboboxSelected>>", self.on_material_select)
        self.brand_dropdown.bind("<<ComboboxSelected>>", self.calculate_part_cogs)

    def _create_items_widgets(self, parent):
        tree_container = ttk.Frame(parent)
        tree_container.pack(fill='both', expand=True, padx=5, pady=5)

        columns = ("Part Name", "Details", "COGS (₹)")
        self.parts_tree = ttk.Treeview(tree_container, columns=columns, show="headings", bootstyle="primary")
        for col in columns:
            self.parts_tree.heading(col, text=col)
        self.parts_tree.column("Part Name", width=200)
        self.parts_tree.column("Details", width=200)
        self.parts_tree.column("COGS (₹)", width=100, anchor="e")

        scrollbar = ttk.Scrollbar(tree_container, orient="vertical", command=self.parts_tree.yview, bootstyle="round-light")
        self.parts_tree.configure(yscroll=scrollbar.set)
        self.parts_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        parts_btn_frame = ttk.Frame(parent)
        parts_btn_frame.pack(pady=5)
        ttk.Button(parts_btn_frame, text="Remove Selected", command=self.remove_part, bootstyle="danger-outline").pack(side="left", padx=5)
        ttk.Button(parts_btn_frame, text="Clear All", command=self.clear_all_parts, bootstyle="secondary-outline").pack(side="left", padx=5)

    def _create_pricing_widgets(self, parent):
        ttk.Label(parent, text="Total COGS:", font="-weight bold").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.cogs_label = ttk.Label(parent, text="₹ 0.00", font="-weight bold")
        self.cogs_label.grid(row=0, column=1, sticky="w", padx=10, pady=5)

        ttk.Separator(parent).grid(row=1, column=0, columnspan=3, sticky="ew", pady=5)

        ttk.Label(parent, text="Select Margin:", font="-weight bold").grid(row=2, column=0, columnspan=3, sticky="w", padx=10, pady=5)
        self.margin_var = ttk.IntVar(value=50)
        self.custom_margin_var = ttk.StringVar(value="90")
        self.custom_margin_var.trace_add("write", self.on_margin_select)

        margin_options_frame = ttk.Frame(parent)
        margin_options_frame.grid(row=3, column=0, columnspan=3, sticky="w")
        for i, (text, val) in enumerate([("50%", 50), ("60%", 60), ("70%", 70), ("80%", 80)]):
            ttk.Radiobutton(margin_options_frame, text=text, variable=self.margin_var, value=val, command=self.on_margin_select, bootstyle="primary-toolbutton").pack(side="left", padx=5)

        self.custom_rb = ttk.Radiobutton(margin_options_frame, text="Custom:", variable=self.margin_var, value=999, command=self.on_margin_select, bootstyle="primary-toolbutton")
        self.custom_rb.pack(side="left", padx=(10, 0))
        self.custom_margin_entry = ttk.Entry(margin_options_frame, textvariable=self.custom_margin_var, width=5, state="disabled")
        self.custom_margin_entry.pack(side="left", padx=(0, 2))
        ttk.Label(margin_options_frame, text="%").pack(side="left")

        ttk.Separator(parent).grid(row=4, column=0, columnspan=3, sticky="ew", pady=5)

        ttk.Label(parent, text="Subtotal:").grid(row=5, column=0, sticky="e", padx=10, pady=2)
        self.subtotal_label = ttk.Label(parent, text="₹ 0.00")
        self.subtotal_label.grid(row=5, column=1, sticky="w", padx=10, pady=2)

        ttk.Label(parent, text="Tax:").grid(row=6, column=0, sticky="e", padx=10, pady=2)
        self.tax_label = ttk.Label(parent, text="₹ 0.00")
        self.tax_label.grid(row=6, column=1, sticky="w", padx=10, pady=2)

        ttk.Label(parent, text="Total Price:", font="-size 12 -weight bold").grid(row=7, column=0, sticky="e", padx=10, pady=(5,10))
        self.total_price_label = ttk.Label(parent, text="₹ 0.00", font="-size 12 -weight bold", bootstyle="success")
        self.total_price_label.grid(row=7, column=1, sticky="w", padx=10, pady=(5,10))

        parent.columnconfigure(1, weight=1)

    def on_show(self):
        self.app.run_threaded_task(self._load_page_data, "Loading Quotation Data...")

    def _load_page_data(self):
        client_config = load_client_config()
        pricing_data = self.app.api.get_filaments()
        printers = self.app.api.get_printers()
        self.after(0, self._on_page_data_loaded, client_config, pricing_data, printers)

    def _on_page_data_loaded(self, client_config, pricing_data, printers):
        self.part_vars["Labour Rate (₹/hr)"] = ttk.StringVar(value=client_config.get("labour_rate", 100))
        self.pricing_data = pricing_data
        self.printers = printers

        printer_names = [f"{p['brand']} {p['model']}" for p in self.printers]
        self.printer_ids = {f"{p['brand']} {p['model']}": p['id'] for p in self.printers}
        self.printer_dropdown['values'] = sorted(printer_names)
        if printer_names:
            self.part_vars["Printer"].set(sorted(printer_names)[0])

        material_options = sorted(list(self.pricing_data.keys()))
        self.material_dropdown['values'] = material_options
        if material_options:
            self.part_vars["Material"].set(material_options[0])

        self.update_brands_list()
        self.calculate_part_cogs()

    def load_from_image(self):
        if not (image_path := filedialog.askopenfilename(title="Select Print Summary Image", filetypes=[("Image files", "*.png *.jpg *.jpeg"), ("All files", "*.*")])):
            return

        def task():
            ocr_data = self.app.api.upload_for_ocr(image_path)
            self.after(0, self._process_ocr_result, ocr_data, image_path)

        self.app.run_threaded_task(task, "Performing OCR...")

    def _process_ocr_result(self, ocr_data, image_path):
        if ocr_data:
            self.part_vars["Part Name"].set(re.sub(r'\..*$', '', image_path.split('/')[-1]))
            self.populate_form_with_data(ocr_data)
            self.app.get_status_box().insert(ttk.END, "✔️ OCR data loaded. Review and add part.\n")
        else:
            self.app.get_status_box().insert(ttk.END, f"❌ Failed to get OCR data for {image_path.split('/')[-1]}.\n")

    def load_from_logs(self):
        self.app.run_threaded_task(self._load_logs_task, "Loading Logs...")

    def _load_logs_task(self):
        logs = self.app.api.get_logs()
        self.after(0, self._on_logs_loaded, logs)

    def _on_logs_loaded(self, logs):
        if not logs:
            return messagebox.showinfo("No Logs", "No processed logs found to load from.", parent=self)

        dialog = LogSelectionDialog(self, logs)
        self.wait_window(dialog)

        if dialog.result:
            self.part_vars["Part Name"].set(dialog.result['filename'])
            self.populate_form_with_data(dialog.result['data'])

    def populate_form_with_data(self, data):
        self.part_vars["Filament (g)"].set(data.get('filament') or data.get('Filament (g)', '0'))
        self.part_vars["Time (e.g. 7h 30m)"].set(data.get('time_str') or data.get('Time', '0h 0m'))

        if (printer_name := data.get('Printer')) and printer_name in self.printer_dropdown['values']:
            self.part_vars["Printer"].set(printer_name)

        if (material := data.get('material') or data.get('Material')) and material in self.material_dropdown['values']:
            self.part_vars["Material"].set(material)
            self.update_brands_list()
            if (brand := data.get('brand') or data.get('Brand')) and brand in self.brand_dropdown['values']:
                self.part_vars["Brand"].set(brand)

        self.calculate_part_cogs()

    def on_material_select(self, *args):
        self.update_brands_list()
        self.calculate_part_cogs()

    def update_brands_list(self):
        material = self.part_vars["Material"].get()
        brand_options = sorted(list(self.pricing_data.get(material, {}).keys()))
        self.brand_dropdown['values'] = brand_options
        if brand_options:
            self.part_vars["Brand"].set(brand_options[0])
        else:
            self.part_vars["Brand"].set("")

    def calculate_part_cogs(self, *args):
        try:
            form_data = {label: var.get() for label, var in self.part_vars.items()}
            printer_data = next((p for p in self.printers if p["id"] == self.printer_ids.get(form_data.get("Printer"))), None)
            filament_data = self.pricing_data.get(form_data.get("Material"), {}).get(form_data.get("Brand"), {})
            if not all([printer_data, filament_data]):
                self.current_part_cogs = 0.0
                return
            self.current_part_cogs = calculate_cogs_values(form_data, printer_data, filament_data)['user_cogs']
        except (ValueError, TypeError, KeyError):
            self.current_part_cogs = 0.0

    def add_part(self):
        if not (part_name := self.part_vars["Part Name"].get()):
            return messagebox.showwarning("Input Error", "Please enter a name for the part.", parent=self)

        self.calculate_part_cogs()
        values = (part_name, f"{self.part_vars['Material'].get()} ({self.part_vars['Brand'].get()})", f"{self.current_part_cogs:.2f}")
        data_to_store = {key: var.get() for key, var in self.part_vars.items()}
        data_to_store['cogs'] = self.current_part_cogs
        self.parts_tree.insert('', 'end', values=values, tags=(json.dumps(data_to_store),))
        self.update_total_cogs()

    def remove_part(self):
        if not (selected_items := self.parts_tree.selection()):
            return
        for item in selected_items:
            self.parts_tree.delete(item)
        self.update_total_cogs()

    def clear_all_parts(self):
        for item in self.parts_tree.get_children():
            self.parts_tree.delete(item)
        self.update_total_cogs()

    def update_total_cogs(self):
        total_cogs = sum(json.loads(self.parts_tree.item(item_id, 'tags')[0]).get('cogs', 0.0) for item_id in self.parts_tree.get_children())
        self.cogs_label.config(text=f"₹ {total_cogs:.2f}")
        self.update_final_price(total_cogs)

    def on_margin_select(self, *args):
        self.custom_margin_entry.config(state="normal" if self.margin_var.get() == 999 else "disabled")
        self.update_total_cogs()

    def update_final_price(self, total_cogs=None):
        if total_cogs is None:
            total_cogs = sum(json.loads(self.parts_tree.item(item_id, 'tags')[0]).get('cogs', 0.0) for item_id in self.parts_tree.get_children())

        try:
            margin_percent = float(self.custom_margin_var.get()) if self.margin_var.get() == 999 else self.margin_var.get()
            subtotal = 0.0 if margin_percent >= 100 else total_cogs / (1 - (margin_percent / 100.0))
            tax_rate = float(load_client_config().get("TAX_RATE_PERCENT", 0))
            tax_amount = subtotal * (tax_rate / 100.0)
            total = subtotal + tax_amount

            self.subtotal_label.config(text=f"₹ {subtotal:.2f}")
            self.tax_label.config(text=f"₹ {tax_amount:.2f} ({tax_rate}%)")
            self.total_price_label.config(text=f"₹ {total:.2f}")
        except (AttributeError, ValueError, ZeroDivisionError):
            self.subtotal_label.config(text="₹ 0.00")
            self.tax_label.config(text="₹ 0.00")
            self.total_price_label.config(text="₹ 0.00")

    def generate_pdf(self):
        customer_name = self.vars["Customer Name"].get()
        if not customer_name:
            return messagebox.showerror("Input Error", "Customer Name is required.", parent=self)

        parts_data = [{"name": d.get("Part Name"), "cogs": d.get("cogs")} for item_id in self.parts_tree.get_children() if (d := json.loads(self.parts_tree.item(item_id, 'tags')[0]))]
        if not parts_data:
            return messagebox.showerror("Input Error", "Please add at least one part to the quotation.", parent=self)

        customer_name_safe = re.sub(r'[^a-zA-Z0-9_]', '', customer_name.replace(' ', '_'))
        initial_filename = f"Quotation_{customer_name_safe}.pdf"
        save_path = filedialog.asksaveasfilename(initialfile=initial_filename, defaultextension=".pdf", filetypes=[("PDF Documents", "*.pdf")])
        if not save_path:
            return

        def task():
            client_config = load_client_config()
            margin_percent = float(self.custom_margin_var.get()) if self.margin_var.get() == 999 else self.margin_var.get()
            quotation_data = {
                "customer_name": customer_name,
                "customer_company": self.vars["Company Name"].get(),
                "parts": parts_data,
                "margin_percent": margin_percent,
                "tax_rate_percent": float(client_config.get("TAX_RATE_PERCENT", 0)),
                "company_details": {
                    k: client_config.get(v) for k, v in {
                        "name": "COMPANY_NAME", "address": "COMPANY_ADDRESS",
                        "contact": "COMPANY_CONTACT", "logo_path": "COMPANY_LOGO_PATH"
                    }.items()
                }
            }

            success = self.app.api.generate_quotation(quotation_data, save_path)

            if success:
                self.after(0, lambda: messagebox.showinfo("Success", f"Quotation PDF downloaded successfully!\n\nSaved to: {save_path}", parent=self))

        self.app.run_threaded_task(task, "Generating PDF...")

    def open_stl_slicer_dialog(self):
        stl_path = filedialog.askopenfilename(title="Select STL File", filetypes=[("3D Models", "*.stl *.3mf"), ("All Files", "*.*")])
        if not stl_path:
            return

        dialog = SlicerDialog(self, self.app, stl_path)
        self.wait_window(dialog)

        if hasattr(dialog, 'result') and dialog.result:
            self.add_part_from_slicer(dialog.result)

    def add_part_from_slicer(self, server_data):
        part_name = server_data.get('part_name', 'Unnamed Part')
        details_for_display = f"Time: {server_data['print_time_hours']:.2f} hrs, Filament: {server_data['filament_grams']:.2f} g"
        cogs_value = f"{server_data['total_cogs']:.2f}"

        values = (part_name, details_for_display, cogs_value)

        full_part_data = {"name": part_name, "cogs": server_data['total_cogs']}
        self.parts_tree.insert('', 'end', values=values, tags=(json.dumps(full_part_data),))
        self.update_total_cogs()