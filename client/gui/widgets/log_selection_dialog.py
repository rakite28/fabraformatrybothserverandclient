import ttkbootstrap as ttk
from tkinter import messagebox, Toplevel

class LogSelectionDialog(Toplevel):
    def __init__(self, parent, logs):
        super().__init__(parent)
        self.title("Select Log Entry")
        self.transient(parent)
        self.grab_set()
        self.result = None
        self.logs = logs

        search_frame = ttk.Frame(self)
        search_frame.pack(fill='x', padx=10, pady=5)

        self.search_var = ttk.StringVar()
        self.search_var.trace_add("write", lambda *args: self.filter_and_populate_tree())
        ttk.Label(search_frame, text="Search:").pack(side='left', padx=(0,5))
        ttk.Entry(search_frame, textvariable=self.search_var, width=30).pack(side='left')

        tree_container = ttk.Frame(self)
        tree_container.pack(fill='both', expand=True, padx=10, pady=5)

        columns = ("Filename", "Material", "Filament (g)", "Time")
        self.tree = ttk.Treeview(tree_container, columns=columns, show="headings", bootstyle="primary")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120)

        scrollbar = ttk.Scrollbar(tree_container, orient="vertical", command=self.tree.yview, bootstyle="round-light")
        self.tree.configure(yscroll=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", self.on_ok)

        self.filter_and_populate_tree()

        button_frame = ttk.Frame(self)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="OK", command=self.on_ok, bootstyle="primary").pack(side="left", padx=10)
        ttk.Button(button_frame, text="Cancel", command=self.destroy, bootstyle="secondary").pack(side="left", padx=10)

        self.geometry("600x400")

    def filter_and_populate_tree(self):
        for i in self.tree.get_children():
            self.tree.delete(i)

        search_term = self.search_var.get().lower()

        filtered_logs = []
        if self.logs:
            filtered_logs = [
                log for log in self.logs if not search_term or any(
                    search_term in str(val).lower() for val in (
                        log['filename'],
                        log['data']['Material'],
                        log['data']['Brand']
                    )
                )
            ]

        for i, log in enumerate(filtered_logs):
            values = (log['filename'], f"{log['data']['Material']} ({log['data']['Brand']})", log['data']['Filament (g)'], log['data']['Time'])
            self.tree.insert('', 'end', iid=log['timestamp'], values=values, tags=('oddrow' if i % 2 else 'evenrow',))

    def on_ok(self, event=None):
        if not (selected_items := self.tree.selection()):
            return messagebox.showwarning("No Selection", "Please select a log entry.", parent=self)

        self.result = next((log for log in self.logs if log['timestamp'] == selected_items[0]), None)
        self.destroy()