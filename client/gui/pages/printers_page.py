import time
import ttkbootstrap as ttk
from tkinter import messagebox

from .base_page import Page
from ...helpers import calculate_printer_hourly_rate

class PrintersPage(Page):
    def __init__(self, master, app, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.app = app
        self.selected_printer_id = None
        self.printers_data = []

        ttk.Label(self, text="Printer Management", font=('Montserrat', 16, 'bold'), bootstyle="primary").pack(anchor="w", padx=10, pady=(5,10))

        self.list_frame = ttk.Frame(self)
        self.form_frame = ttk.Frame(self)

        self._create_list_view()
        self._create_form_view()

        self.show_list_view()

    def _create_list_view(self):
        button_frame = ttk.Frame(self.list_frame)
        button_frame.pack(fill='x', pady=5, padx=5)

        ttk.Button(button_frame, text="Add New Printer", command=self.show_form_view, bootstyle="primary").pack(side='left')
        ttk.Button(button_frame, text="Edit Selected", command=self.edit_selected, bootstyle="secondary").pack(side='left', padx=5)
        ttk.Button(button_frame, text="Delete Selected", command=self.delete_printer, bootstyle="danger-outline").pack(side='left')
        ttk.Button(button_frame, text="Refresh", command=self.on_show, bootstyle="info").pack(side='right', padx=5)

        tree_container = ttk.Frame(self.list_frame)
        tree_container.pack(fill='both', expand=True, padx=5, pady=5)

        columns = ("Brand", "Model", "Setup Cost (₹)", "Maintenance (₹/yr)", "Lifetime (yrs)", "Power (W)", "Price/kWh (₹)", "Uptime (%)", "Buffer Factor", "Hourly Rate (₹)")
        self.tree = ttk.Treeview(tree_container, columns=columns, show="headings", bootstyle="primary")
        for col in columns:
            self.tree.heading(col, text=col, command=lambda _col=col: self.sort_column(_col, False))
            self.tree.column(col, width=95, anchor="w")

        scrollbar = ttk.Scrollbar(tree_container, orient="vertical", command=self.tree.yview, bootstyle="round")
        self.tree.configure(yscroll=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        self.loading_label = ttk.Label(self.list_frame, text="Loading printers...")

    def _create_form_view(self):
        self.form_title = ttk.Label(self.form_frame, font=('Montserrat', 14, 'bold'), bootstyle="info")
        self.form_title.pack(anchor="w", pady=(0, 10))

        form_fields_container = ttk.Frame(self.form_frame)
        form_fields_container.pack(fill="x")

        self.fields = {}
        labels = ["Brand", "Model", "Setup Cost (₹)", "Maintenance (₹/yr)", "Lifetime (yrs)", "Power (W)", "Price/kWh (₹)", "Uptime (%)", "Buffer Factor"]
        for i, label in enumerate(labels):
            ttk.Label(form_fields_container, text=f"{label}:").grid(row=i, column=0, padx=5, pady=6, sticky="w")
            self.fields[label] = ttk.StringVar()
            ttk.Entry(form_fields_container, textvariable=self.fields[label], width=40).grid(row=i, column=1, padx=5, pady=6, sticky="ew")

        form_fields_container.columnconfigure(1, weight=1)

        form_button_frame = ttk.Frame(self.form_frame)
        form_button_frame.pack(pady=20)
        ttk.Button(form_button_frame, text="Save", command=self.save_printer, bootstyle="primary").pack(side="left", padx=10)
        ttk.Button(form_button_frame, text="Cancel", command=self.show_list_view, bootstyle="secondary").pack(side="left", padx=10)

    def on_show(self):
        self.show_list_view()
        self.tree.delete(*self.tree.get_children())
        self.loading_label.place(relx=0.5, rely=0.4, anchor="center")
        self.app.run_threaded_task(self.fetch_printers_thread, "Refreshing Printers...")

    def fetch_printers_thread(self):
        try:
            self.printers_data = self.app.api.get_printers()
            self.after(0, self.populate_tree)
        except Exception as e:
            print(f"Error fetching printers: {e}")
            self.after(0, self.loading_label.config, {"text": "Failed to load printers."})

    def show_list_view(self):
        self.form_frame.pack_forget()
        self.list_frame.pack(fill="both", expand=True, padx=10, pady=0)

    def show_form_view(self, printer_id=None):
        self.list_frame.pack_forget()
        self.form_frame.pack(fill="both", expand=True, padx=20, pady=10)
        if printer_id:
            self.form_title.config(text="Edit Printer")
            self.populate_form_for_edit(printer_id)
        else:
            self.form_title.config(text="Add New Printer")
            self.clear_form()

    def populate_form_for_edit(self, printer_id):
        self.selected_printer_id = printer_id
        printer_to_edit = next((p for p in self.printers_data if p.get("id") == printer_id), None)
        if not printer_to_edit:
            return messagebox.showerror("Error", "Could not find the selected printer.", parent=self)

        key_map = {"brand": "Brand", "model": "Model", "setup_cost": "Setup Cost (₹)", "maintenance_cost": "Maintenance (₹/yr)", "lifetime_years": "Lifetime (yrs)", "power_w": "Power (W)", "price_kwh": "Price/kWh (₹)", "uptime_percent": "Uptime (%)", "buffer_factor": "Buffer Factor"}
        for key, field in key_map.items():
            self.fields[field].set(printer_to_edit.get(key, ""))

    def clear_form(self):
        self.selected_printer_id = None
        for var in self.fields.values():
            var.set("")
        self.fields["Uptime (%)"].set("50")
        self.fields["Buffer Factor"].set("1.0")

    def edit_selected(self):
        if self.selected_printer_id:
            self.show_form_view(printer_id=self.selected_printer_id)
        else:
            messagebox.showwarning("No Selection", "Please select a printer to edit.", parent=self)

    def on_double_click(self, event):
        if self.selected_printer_id:
            self.show_form_view(printer_id=self.selected_printer_id)

    def populate_tree(self, sort_by='Brand', reverse=False):
        self.loading_label.place_forget()
        self.tree.delete(*self.tree.get_children())

        display_data = []
        for p in self.printers_data:
            hourly_rate = p.get('hourly_rate', calculate_printer_hourly_rate(p))
            display_data.append((
                p.get("brand", ""), p.get("model", ""), p.get("setup_cost", 0),
                p.get("maintenance_cost", 0), p.get("lifetime_years", 0),
                p.get("power_w", 0), p.get("price_kwh", 0),
                p.get("uptime_percent", 50), p.get("buffer_factor", 1.0),
                f"{hourly_rate:.2f}", p.get("id")
            ))

        try:
            col_index = self.tree["columns"].index(sort_by)
            numeric_cols = ["Setup Cost (₹)", "Maintenance (₹/yr)", "Lifetime (yrs)", "Power (W)", "Price/kWh (₹)", "Uptime (%)", "Buffer Factor", "Hourly Rate (₹)"]
            display_data.sort(key=lambda x: float(x[col_index]) if sort_by in numeric_cols else str(x[col_index]).lower(), reverse=reverse)
        except (ValueError, IndexError):
            display_data.sort(key=lambda x: x[0], reverse=reverse)

        for i, item in enumerate(display_data):
            self.tree.insert('', 'end', iid=item[10], values=item[:10], tags=('oddrow' if i % 2 else 'evenrow',))

    def sort_column(self, col, reverse):
        self.populate_tree(sort_by=col, reverse=reverse)
        self.tree.heading(col, command=lambda: self.sort_column(col, not reverse))

    def on_tree_select(self, event):
        self.selected_printer_id = self.tree.selection()[0] if self.tree.selection() else None

    def save_printer(self):
        try:
            if float(self.fields["Buffer Factor"].get()) < 1:
                return messagebox.showerror("Validation Error", "Buffer Factor cannot be less than 1.", parent=self)

            new_data = {
                "id": self.selected_printer_id or str(time.time()),
                "brand": self.fields["Brand"].get().strip(),
                "model": self.fields["Model"].get().strip(),
                "setup_cost": float(self.fields["Setup Cost (₹)"].get()),
                "maintenance_cost": float(self.fields["Maintenance (₹/yr)"].get()),
                "lifetime_years": int(self.fields["Lifetime (yrs)"].get()),
                "power_w": float(self.fields["Power (W)"].get()),
                "price_kwh": float(self.fields["Price/kWh (₹)"].get()),
                "uptime_percent": float(self.fields["Uptime (%)"].get()),
                "buffer_factor": float(self.fields["Buffer Factor"].get())
            }
            if not new_data["brand"] or not new_data["model"]:
                return messagebox.showerror("Validation Error", "Brand and Model are required.", parent=self)
        except (ValueError, TypeError):
            return messagebox.showerror("Validation Error", "Please enter valid numbers for all numeric fields.", parent=self)

        printers_to_save = self.printers_data.copy()
        if self.selected_printer_id:
            printers_to_save = [new_data if p.get("id") == self.selected_printer_id else p for p in printers_to_save]
        else:
            printers_to_save.append(new_data)

        def task():
            if self.app.api.save_printers(printers_to_save):
                messagebox.showinfo("Success", "Printer saved successfully.", parent=self)
                self.on_show()

        self.app.run_threaded_task(task, "Saving Printer...")

    def delete_printer(self):
        if not self.selected_printer_id:
            return messagebox.showwarning("No Selection", "Please select a printer to delete.", parent=self)

        printer_to_delete = next((p for p in self.printers_data if p["id"] == self.selected_printer_id), None)
        if printer_to_delete and messagebox.askyesno("Confirm Delete", f"Delete {printer_to_delete['brand']} {printer_to_delete['model']}?", parent=self):
            printers_to_save = [p for p in self.printers_data if p["id"] != self.selected_printer_id]

            def task():
                if self.app.api.save_printers(printers_to_save):
                    self.on_show()
                    messagebox.showinfo("Success", "Printer deleted.", parent=self)

            self.app.run_threaded_task(task, "Deleting Printer...")