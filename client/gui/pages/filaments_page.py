import ttkbootstrap as ttk
from tkinter import messagebox

from .base_page import Page

class FilamentsPage(Page):
    def __init__(self, master, app, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.app = app
        self.selected_filament_key = None
        self.filaments_data = {}

        ttk.Label(self, text="Filament Management", font=('Montserrat', 16, 'bold'), bootstyle="primary").pack(anchor="w", padx=10, pady=(5,10))

        self.list_frame = ttk.Frame(self)
        self.form_frame = ttk.Frame(self)

        self._create_list_view()
        self._create_form_view()

        self.show_list_view()

    def _create_list_view(self):
        button_frame = ttk.Frame(self.list_frame)
        button_frame.pack(fill='x', pady=5, padx=5)

        ttk.Button(button_frame, text="Add New Filament", command=self.show_form_view, bootstyle="primary").pack(side='left')
        ttk.Button(button_frame, text="Edit Selected", command=self.edit_selected, bootstyle="secondary").pack(side='left', padx=5)
        ttk.Button(button_frame, text="Delete Selected", command=self.delete_filament, bootstyle="danger-outline").pack(side='left')
        ttk.Button(button_frame, text="Refresh", command=self.on_show, bootstyle="info").pack(side='right', padx=5)

        tree_container = ttk.Frame(self.list_frame)
        tree_container.pack(fill='both', expand=True, padx=5, pady=5)

        columns = ("Material", "Brand", "Price (₹/kg)", "Stock (g)", "Efficiency Factor")
        self.tree = ttk.Treeview(tree_container, columns=columns, show="headings", bootstyle="primary")
        for col in columns:
            self.tree.heading(col, text=col, command=lambda _col=col: self.sort_column(_col, False))
            self.tree.column(col, width=130, anchor="w")

        scrollbar = ttk.Scrollbar(tree_container, orient="vertical", command=self.tree.yview, bootstyle="round-light")
        self.tree.configure(yscroll=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        self.loading_label = ttk.Label(self.list_frame, text="Loading filaments...")

    def _create_form_view(self):
        self.form_title = ttk.Label(self.form_frame, font=('Montserrat', 14, 'bold'), bootstyle="info")
        self.form_title.pack(anchor="w", pady=(0, 10))

        form_fields_container = ttk.Frame(self.form_frame)
        form_fields_container.pack(fill="x")

        self.fields = {}
        labels = ["Material", "Brand", "Price (₹/kg)", "Stock (g)", "Efficiency Factor"]
        for i, label in enumerate(labels):
            ttk.Label(form_fields_container, text=f"{label}:").grid(row=i, column=0, padx=5, pady=6, sticky="w")
            self.fields[label] = ttk.StringVar()
            ttk.Entry(form_fields_container, textvariable=self.fields[label], width=40).grid(row=i, column=1, padx=5, pady=6, sticky="ew")

        form_fields_container.columnconfigure(1, weight=1)

        form_button_frame = ttk.Frame(self.form_frame)
        form_button_frame.pack(pady=20)
        ttk.Button(form_button_frame, text="Save", command=self.save_filament, bootstyle="primary").pack(side="left", padx=10)
        ttk.Button(form_button_frame, text="Cancel", command=self.show_list_view, bootstyle="secondary").pack(side="left", padx=10)

    def on_show(self):
        self.show_list_view()
        self.tree.delete(*self.tree.get_children())
        self.loading_label.place(relx=0.5, rely=0.4, anchor="center")
        self.app.run_threaded_task(self.fetch_filaments_thread, "Refreshing Filaments...")

    def fetch_filaments_thread(self):
        try:
            self.filaments_data = self.app.api.get_filaments()
            self.after(0, self.populate_tree)
        except Exception as e:
            print(f"Error fetching filaments: {e}")
            self.after(0, self.loading_label.config, {"text": "Failed to load filaments."})

    def show_list_view(self):
        self.form_frame.pack_forget()
        self.list_frame.pack(fill="both", expand=True, padx=10, pady=0)

    def show_form_view(self, key=None):
        self.list_frame.pack_forget()
        self.form_frame.pack(fill="both", expand=True, padx=20, pady=10)
        if key:
            self.form_title.config(text="Edit Filament")
            self.populate_form_for_edit(key)
        else:
            self.form_title.config(text="Add New Filament")
            self.clear_form()

    def populate_form_for_edit(self, key):
        self.selected_filament_key = key
        material, brand = key
        filament_data = self.filaments_data.get(material, {}).get(brand)
        if not filament_data:
            return messagebox.showerror("Error", "Could not find the selected filament.", parent=self)

        self.fields["Material"].set(material)
        self.fields["Brand"].set(brand)
        for k, field in {"price": "Price (₹/kg)", "stock_g": "Stock (g)", "efficiency_factor": "Efficiency Factor"}.items():
            self.fields[field].set(filament_data.get(k, ""))

    def clear_form(self):
        self.selected_filament_key = None
        for var in self.fields.values():
            var.set("")
        self.fields["Efficiency Factor"].set("1.0")

    def edit_selected(self):
        if self.selected_filament_key:
            self.show_form_view(key=self.selected_filament_key)
        else:
            messagebox.showwarning("No Selection", "Please select a filament to edit.", parent=self)

    def on_double_click(self, event):
        if self.selected_filament_key:
            self.show_form_view(key=self.selected_filament_key)

    def populate_tree(self, sort_by='Material', reverse=False):
        self.loading_label.place_forget()
        self.tree.delete(*self.tree.get_children())

        all_filaments = []
        if self.filaments_data:
            all_filaments = [(m, b, d.get("price", 0), d.get("stock_g", 0), d.get("efficiency_factor", 1.0)) for m, bs in self.filaments_data.items() for b, d in bs.items()]

        try:
            col_index = self.tree["columns"].index(sort_by)
            numeric_cols = ["Price (₹/kg)", "Stock (g)", "Efficiency Factor"]
            all_filaments.sort(key=lambda x: float(x[col_index]) if sort_by in numeric_cols else str(x[col_index]).lower(), reverse=reverse)
        except (ValueError, IndexError):
            all_filaments.sort(key=lambda x: x[0], reverse=reverse)

        for i, item in enumerate(all_filaments):
            self.tree.insert('', 'end', values=item, tags=('oddrow' if i % 2 else 'evenrow',))

    def sort_column(self, col, reverse):
        self.populate_tree(sort_by=col, reverse=reverse)
        self.tree.heading(col, command=lambda: self.sort_column(col, not reverse))

    def on_tree_select(self, event):
        if selected_items := self.tree.selection():
            self.selected_filament_key = self.tree.item(selected_items[0])['values'][:2]
        else:
            self.selected_filament_key = None

    def save_filament(self):
        try:
            material = self.fields["Material"].get().strip().upper()
            brand = self.fields["Brand"].get().strip()
            if not all([material, brand]):
                return messagebox.showerror("Validation Error", "Material and Brand are required.", parent=self)

            new_data = {
                "price": float(self.fields["Price (₹/kg)"].get()),
                "stock_g": float(self.fields["Stock (g)"].get()),
                "efficiency_factor": float(self.fields["Efficiency Factor"].get())
            }
        except (ValueError, TypeError):
            return messagebox.showerror("Validation Error", "Price, Stock, and Efficiency must be valid numbers.", parent=self)

        pricing_data_to_save = self.filaments_data.copy()
        if self.selected_filament_key and tuple(self.selected_filament_key) != (material, brand):
            old_material, old_brand = self.selected_filament_key
            if old_material in pricing_data_to_save and old_brand in pricing_data_to_save[old_material]:
                del pricing_data_to_save[old_material][old_brand]
                if not pricing_data_to_save[old_material]:
                    del pricing_data_to_save[old_material]

        if material not in pricing_data_to_save:
            pricing_data_to_save[material] = {}
        pricing_data_to_save[material][brand] = new_data

        def task():
            if self.app.api.save_filaments(pricing_data_to_save):
                messagebox.showinfo("Success", f"Saved: {brand} {material}", parent=self)
                self.on_show()

        self.app.run_threaded_task(task, "Saving Filament...")

    def delete_filament(self):
        if not self.selected_filament_key:
            return messagebox.showwarning("No Selection", "Please select a filament to delete.", parent=self)

        material, brand = self.selected_filament_key
        if messagebox.askyesno("Confirm Delete", f"Delete {brand} {material}?", parent=self):
            pricing_data_to_save = self.filaments_data.copy()
            if material in pricing_data_to_save and brand in pricing_data_to_save[material]:
                del pricing_data_to_save[material][brand]
                if not pricing_data_to_save[material]:
                    del pricing_data_to_save[material]

                def task():
                    if self.app.api.save_filaments(pricing_data_to_save):
                        self.on_show()
                        messagebox.showinfo("Success", f"{brand} {material} deleted.", parent=self)

                self.app.run_threaded_task(task, "Deleting Filament...")