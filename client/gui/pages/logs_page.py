import os
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import scrolledtext, filedialog, simpledialog, messagebox
from datetime import datetime

from .base_page import Page
from ..widgets.image_canvas import ImageCanvas
from ...api.client import SERVER_URL

class LogsPage(Page):
    def __init__(self, master, app, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.app = app
        self.logs = []
        self.sort_column_name = "Date"
        self.sort_reverse = True

        ttk.Label(self, text="Processed Logs", font=('Montserrat', 16, 'bold'), bootstyle="primary").pack(anchor="w", padx=10, pady=(5,10))

        self.list_frame = ttk.Frame(self)
        self.details_frame = ttk.Frame(self)

        self._create_list_view()
        self._create_details_view()

        self.show_list_view()

    def _create_list_view(self):
        controls_frame = ttk.Frame(self.list_frame)
        controls_frame.pack(fill='x', pady=5, padx=5)

        self.search_var = ttk.StringVar()
        self.search_var.trace_add("write", lambda *args: self.filter_and_populate_tree())
        ttk.Label(controls_frame, text="Search:").pack(side='left', padx=(0,5))
        ttk.Entry(controls_frame, textvariable=self.search_var, width=30).pack(side='left')

        ttk.Button(controls_frame, text="Download Selected", command=self.download_selected_logs, bootstyle="success-outline").pack(side='right', padx=5)
        ttk.Button(controls_frame, text="Refresh Logs", command=self.on_show, bootstyle="info").pack(side='right')

        tree_container = ttk.Frame(self.list_frame)
        tree_container.pack(fill='both', expand=True, padx=5, pady=5)

        columns = ("Date", "Filename", "Material", "User COGS (₹)")
        self.tree = ttk.Treeview(tree_container, columns=columns, show="headings", bootstyle="primary")
        for col in columns:
            self.tree.heading(col, text=col, command=lambda _col=col: self.sort_column(_col))

        self.tree.column("Date", width=160)
        self.tree.column("Filename", width=200)
        self.tree.column("Material", width=150)
        self.tree.column("User COGS (₹)", width=100, anchor="e")

        scrollbar = ttk.Scrollbar(tree_container, orient="vertical", command=self.tree.yview, bootstyle="round")
        self.tree.configure(yscroll=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_log_select)

        total_frame = ttk.Frame(self.list_frame)
        total_frame.pack(fill='x', padx=5, pady=(5,0))
        self.total_cogs_label = ttk.Label(total_frame, text="Total COGS: ₹0.00", font=('-weight', 'bold'))
        self.total_cogs_label.pack(side='right')

        self.loading_label = ttk.Label(self.list_frame, text="Loading logs...")

    def _create_details_view(self):
        ttk.Button(self.details_frame, text="← Back to List", command=self.show_list_view, bootstyle="secondary").pack(anchor="w", pady=5, padx=5)

        main_pane = ttk.PanedWindow(self.details_frame, orient=HORIZONTAL)
        main_pane.pack(fill=BOTH, expand=True, padx=5, pady=5)

        self.image_canvas = ImageCanvas(main_pane)
        main_pane.add(self.image_canvas, weight=3)

        right_details_frame = ttk.Frame(main_pane)
        self.details_text = scrolledtext.ScrolledText(right_details_frame, height=8, bg="#1c246d", fg="#ffafda", relief="flat", bd=5, insertbackground="#ffafda")
        self.details_text.pack(fill="both", expand=True)

        download_frame = ttk.Frame(right_details_frame)
        download_frame.pack(pady=10)
        ttk.Button(download_frame, text="Download Excel Log", command=self.download_log, bootstyle="success").pack(side="left", padx=10)
        ttk.Button(download_frame, text="Download Master Log", command=self.download_master_log, bootstyle="success-outline").pack(side="left", padx=10)

        main_pane.add(right_details_frame, weight=1)

    def on_show(self):
        self.show_list_view()
        self.tree.delete(*self.tree.get_children())
        self.loading_label.place(relx=0.5, rely=0.4, anchor="center")
        self.app.run_threaded_task(self.fetch_logs_thread, "Refreshing Logs...")

    def fetch_logs_thread(self):
        try:
            logs = self.app.api.get_logs()
            self.after(0, self.update_tree_with_logs, logs)
        except Exception as e:
            print(f"Error fetching logs thread: {e}")
            self.after(0, self.show_load_error)

    def update_tree_with_logs(self, logs):
        self.loading_label.place_forget()
        self.logs = logs
        self.filter_and_populate_tree()

    def show_load_error(self):
        self.loading_label.config(text="Failed to load logs. Check connection and refresh.")

    def show_list_view(self):
        self.details_frame.pack_forget()
        self.list_frame.pack(fill="both", expand=True, padx=10, pady=0)
        if self.tree.selection():
            self.tree.selection_remove(self.tree.selection()[0])

    def on_log_select(self, event):
        selected_items = self.tree.selection()
        if not selected_items or len(selected_items) > 1:
            return

        self.list_frame.pack_forget()
        self.details_frame.pack(fill="both", expand=True, padx=10, pady=0)

        log_entry = next((log for log in self.logs if log['timestamp'] == selected_items[0]), None)
        if log_entry:
            self.image_canvas.load_image_from_url(f"{SERVER_URL}/images/{log_entry['image_path']}")
            self.details_text.delete('1.0', END)
            self.details_text.insert('1.0', "\n".join(f"{k}: {v}" for k, v in log_entry['data'].items()))

    def filter_and_populate_tree(self):
        for i in self.tree.get_children():
            self.tree.delete(i)

        search_term = self.search_var.get().lower()

        filtered_logs = []
        if self.logs:
            for log in self.logs:
                log_filename = log.get('filename', '')
                log_material = log.get('data', {}).get('Material', '')
                log_brand = log.get('data', {}).get('Brand', '')
                if not search_term or any(search_term in str(val).lower() for val in (log_filename, log_material, log_brand)):
                    filtered_logs.append(log)

        sort_key_map = {
            "Date": lambda log: log.get('timestamp', ''),
            "Filename": lambda log: log.get('filename', ''),
            "Material": lambda log: f"{log.get('data', {}).get('Material', '')} {log.get('data', {}).get('Brand', '')}",
            "User COGS (₹)": lambda log: float(log.get('data', {}).get('User COGS (₹)', 0))
        }

        sort_function = sort_key_map.get(self.sort_column_name, sort_key_map["Date"])
        filtered_logs.sort(key=sort_function, reverse=self.sort_reverse)

        for i, log in enumerate(filtered_logs):
            try:
                dt_obj = datetime.fromisoformat(log['timestamp'])
                date_str = dt_obj.strftime("%Y-%m-%d %H:%M:%S")
                data = log.get('data', {})
                values = (date_str, log.get('filename', 'N/A'), f"{data.get('Material', 'N/A')} ({data.get('Brand', 'N/A')})", data.get('User COGS (₹)', '0.00'))
                self.tree.insert('', 'end', iid=log['timestamp'], values=values, tags=('oddrow' if i % 2 else 'evenrow',))
            except (KeyError, ValueError, Exception) as e:
                print(f"Skipping malformed log entry: {log.get('timestamp')}. Error: {e}")

        self.update_total_cogs()

    def update_total_cogs(self):
        total_cogs = 0.0
        for item_id in self.tree.get_children():
            try:
                cogs_value = self.tree.item(item_id, 'values')[3]
                total_cogs += float(cogs_value)
            except (ValueError, IndexError):
                continue
        self.total_cogs_label.config(text=f"Total COGS: ₹{total_cogs:.2f}")

    def sort_column(self, col):
        self.sort_reverse = not self.sort_reverse if self.sort_column_name == col else True
        self.sort_column_name = col
        self.filter_and_populate_tree()

    def download_log(self):
        selected_items = self.tree.selection()
        if not selected_items or len(selected_items) > 1:
            return messagebox.showwarning("Selection Error", "Please select exactly one log to download.")

        log_entry = next((log for log in self.logs if log['timestamp'] == selected_items[0]), None)
        if not log_entry: return

        filename = f"{log_entry['filename']}.xlsx"
        save_path = filedialog.asksaveasfilename(initialfile=filename, defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")])
        if not save_path: return

        def task():
            if self.app.api.download_file(f"download/log/{filename}", save_path):
                messagebox.showinfo("Success", f"Log downloaded to:\n{save_path}")

        self.app.run_threaded_task(task, "Downloading...")

    def download_selected_logs(self):
        selected_items = self.tree.selection()
        if not selected_items:
            return messagebox.showwarning("No Selection", "Please select one or more logs to download.")

        folder_selected = filedialog.askdirectory(title="Select Folder to Save Logs")
        if not folder_selected: return

        logs_to_download = [log for log in self.logs if log['timestamp'] in selected_items]

        def task():
            for log_entry in logs_to_download:
                filename = f"{log_entry['filename']}.xlsx"
                save_path = os.path.join(folder_selected, filename)
                self.app.api.download_file(f"download/log/{filename}", save_path)
            messagebox.showinfo("Success", f"{len(logs_to_download)} logs downloaded to:\n{folder_selected}")

        self.app.run_threaded_task(task, f"Downloading {len(logs_to_download)} logs...")

    def download_master_log(self):
        year = simpledialog.askstring("Input", "Enter Year (e.g., 2024):", parent=self)
        month = simpledialog.askstring("Input", "Enter Month Name (e.g., January):", parent=self)

        if not year or not month: return

        year_month = f"{year}_{month.capitalize()}"
        filename = f"master_log_{month.capitalize()}.xlsx"
        save_path = filedialog.asksaveasfilename(initialfile=filename, defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")])
        if not save_path: return

        def task():
            if self.app.api.download_file(f"download/masterlog/{year_month}", save_path):
                messagebox.showinfo("Success", f"Master log for {month} {year} downloaded to:\n{save_path}")

        self.app.run_threaded_task(task, "Downloading Master Log...")