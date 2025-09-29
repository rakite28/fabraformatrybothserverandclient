import os
import ttkbootstrap as ttk
from tkinter import messagebox, Toplevel

class SlicerDialog(Toplevel):
    def __init__(self, parent, app, stl_path):
        super().__init__(parent)
        self.app = app
        self.stl_path = stl_path
        self.result = None
        self.profiles = None
        self.profile_data = {}

        self.title("Slice for Quotation")
        self.transient(parent)
        self.grab_set()

        container = ttk.Frame(self, padding=20)
        container.pack(fill="both", expand=True)
        container.columnconfigure(1, weight=1)

        ttk.Label(container, text=f"File: {os.path.basename(stl_path)}").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))

        # --- Dropdowns ---
        self.machine_var = ttk.StringVar()
        self.filament_var = ttk.StringVar()
        self.process_var = ttk.StringVar()

        ttk.Label(container, text="Printer Profile:").grid(row=1, column=0, sticky="w", padx=5, pady=6)
        self.machine_combo = ttk.Combobox(container, textvariable=self.machine_var, state="readonly")
        self.machine_combo.grid(row=1, column=1, sticky="ew", padx=5, pady=6)

        ttk.Label(container, text="Filament Profile:").grid(row=2, column=0, sticky="w", padx=5, pady=6)
        self.filament_combo = ttk.Combobox(container, textvariable=self.filament_var, state="readonly")
        self.filament_combo.grid(row=2, column=1, sticky="ew", padx=5, pady=6)

        ttk.Label(container, text="Quality Profile:").grid(row=3, column=0, sticky="w", padx=5, pady=6)
        self.process_combo = ttk.Combobox(container, textvariable=self.process_var, state="readonly")
        self.process_combo.grid(row=3, column=1, sticky="ew", padx=5, pady=6)

        # --- Buttons ---
        button_frame = ttk.Frame(container)
        button_frame.grid(row=4, column=0, columnspan=2, pady=(20, 0))
        self.quote_button = ttk.Button(button_frame, text="Get Quote", command=self.slice_and_quote, bootstyle="primary")
        self.quote_button.pack(side="left", padx=10)
        ttk.Button(button_frame, text="Cancel", command=self.destroy, bootstyle="secondary").pack(side="left", padx=10)

        # --- Bindings ---
        self.machine_combo.bind("<<ComboboxSelected>>", self.filter_profiles)

        self.app.run_threaded_task(self.load_profiles, "Fetching Slicer Profiles...")

    def load_profiles(self):
        profiles = self.app.api.get_slicer_profiles()
        self.after(0, self._on_profiles_loaded, profiles)

    def _on_profiles_loaded(self, profiles):
        if not profiles:
            messagebox.showerror("Error", "Could not load slicer profiles from the server.", parent=self)
            self.destroy()
            return

        self.profiles = profiles
        all_machine = sorted(profiles.get("system", {}).get("machine", []) + profiles.get("user", {}).get("machine", []))
        self.machine_combo['values'] = all_machine
        if all_machine:
            self.machine_var.set(all_machine[0])

        self.filter_profiles()

    def filter_profiles(self, event=None):
        all_filaments = sorted(self.profiles.get("system", {}).get("filament", []) + self.profiles.get("user", {}).get("filament", []))
        all_processes = sorted(self.profiles.get("system", {}).get("process", []) + self.profiles.get("user", {}).get("process", []))

        current_filament = self.filament_var.get()
        self.filament_combo['values'] = all_filaments
        if current_filament in all_filaments:
            self.filament_var.set(current_filament)
        elif all_filaments:
            self.filament_var.set(all_filaments[0])

        current_process = self.process_var.get()
        self.process_combo['values'] = all_processes
        if current_process in all_processes:
            self.process_var.set(current_process)
        elif all_processes:
            self.process_var.set(all_processes[0])

    def slice_and_quote(self):
        machine = self.machine_var.get()
        filament = self.filament_var.get()
        process = self.process_var.get()

        if not all([machine, filament, process]):
            return messagebox.showwarning("Incomplete Selection", "Please select a profile for the printer, filament, and quality.", parent=self)

        def task():
            result = self.app.api.slice_and_calculate(self.stl_path, machine, filament, process)
            if result and result.get("status") == "success":
                result['part_name'] = os.path.basename(self.stl_path)
                result['material'] = filament.split('@')[0].strip()
                result['brand'] = "N/A"
                self.result = result
                self.after(0, self.destroy)
            else:
                self.after(0, self.deiconify)

        self.app.run_threaded_task(task, f"Slicing {os.path.basename(self.stl_path)}...")
        self.withdraw()