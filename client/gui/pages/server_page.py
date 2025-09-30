import json
import os
import ttkbootstrap as ttk
from tkinter import messagebox, scrolledtext, filedialog

from .base_page import Page

class ServerPage(Page):
    def __init__(self, master, app, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.app = app
        self.current_path = ""

        ttk.Label(self, text="Server Management", font=('Montserrat', 16, 'bold'), bootstyle="primary").pack(anchor="w", padx=10, pady=(5,10))

        main_pane = ttk.PanedWindow(self, orient=ttk.HORIZONTAL)
        main_pane.pack(fill=ttk.BOTH, expand=True, padx=10, pady=10)

        browser_frame = ttk.Labelframe(main_pane, text="File Browser (Shared Folder)", bootstyle="info")
        settings_frame = ttk.Labelframe(main_pane, text="Server Config (server_config.json)", bootstyle="info")

        self._create_browser_widgets(browser_frame)
        self._create_settings_widgets(settings_frame)

        main_pane.add(browser_frame, weight=1)
        main_pane.add(settings_frame, weight=1)

    def _create_browser_widgets(self, parent):
        browser_controls = ttk.Frame(parent)
        browser_controls.pack(fill='x', padx=5, pady=5)

        ttk.Button(browser_controls, text="⬆️ Up", command=self.go_up_dir, bootstyle="secondary").pack(side='left')
        ttk.Button(browser_controls, text="🔄 Refresh", command=self.refresh_all, bootstyle="secondary").pack(side='left', padx=5)
        self.path_label = ttk.Label(browser_controls, text="Path: /")
        self.path_label.pack(side='left', padx=10)

        tree_container = ttk.Frame(parent)
        tree_container.pack(fill='both', expand=True, padx=5, pady=(0, 5))

        self.tree = ttk.Treeview(tree_container, columns=("Name", "Type", "Size"), show="headings", bootstyle="primary")
        self.tree.heading("Name", text="Name")
        self.tree.heading("Type", text="Type")
        self.tree.heading("Size", text="Size")
        self.tree.column("Name", width=250)
        self.tree.column("Type", width=80)
        self.tree.column("Size", width=100, anchor='e')
        self.tree.bind("<Double-1>", self.on_item_double_click)

        scrollbar = ttk.Scrollbar(tree_container, orient="vertical", command=self.tree.yview, bootstyle="round-light")
        self.tree.configure(yscroll=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        action_buttons = ttk.Frame(parent)
        action_buttons.pack(fill='x', padx=5, pady=5)
        ttk.Button(action_buttons, text="Download Selected", command=self.download_selected, bootstyle="secondary").pack(side='left')
        ttk.Button(action_buttons, text="Upload to This Folder", command=self.upload_file, bootstyle="primary").pack(side='right')

    def _create_settings_widgets(self, parent):
        self.settings_text = scrolledtext.ScrolledText(parent, height=15, width=60,
                                                      bg="#1c246d", fg="#ffafda", relief="flat", bd=5,
                                                      font=("Consolas", 10), insertbackground="#ffafda")
        self.settings_text.pack(fill='both', expand=True, padx=5, pady=5)

        settings_buttons = ttk.Frame(parent)
        settings_buttons.pack(fill='x', pady=5)
        ttk.Button(settings_buttons, text="Load from Server", command=self.load_settings, bootstyle="secondary").pack(side='left', padx=5)
        ttk.Button(settings_buttons, text="Save to Server", command=self.save_settings, bootstyle="success").pack(side='right', padx=5)

    def on_show(self):
        self.refresh_all()

    def refresh_all(self):
        self.app.run_threaded_task(self.populate_browser, "Loading Files...")
        self.load_settings()

    def populate_browser(self):
        files = self.app.api.list_server_files(self.current_path)
        self.after(0, self._update_browser_ui, files)

    def _update_browser_ui(self, files):
        for i in self.tree.get_children():
            self.tree.delete(i)

        if files is None:
            return

        files.sort(key=lambda x: (x['type'] == 'file', x['name'].lower()))

        for item in files:
            if item['type'] == 'dir':
                self.tree.insert('', 'end', values=(f"📁 {item['name']}", "Folder", ""), tags=('dir', item['name']))
            else:
                size_mb = item['size'] / (1024 * 1024)
                size_str = f"{size_mb:.2f} MB" if size_mb >= 1 else f"{item['size'] / 1024:.2f} KB"
                self.tree.insert('', 'end', values=(f"📄 {item['name']}", "File", size_str), tags=('file', item['name']))

        self.path_label.config(text=f"Path: /{self.current_path}")

    def on_item_double_click(self, event):
        selected_item_id = self.tree.focus()
        if not selected_item_id:
            return

        tags = self.tree.item(selected_item_id, 'tags')
        if 'dir' in tags:
            dir_name = tags[1]
            self.current_path = os.path.join(self.current_path, dir_name).replace("\\", "/")
            self.app.run_threaded_task(self.populate_browser, "Loading Files...")

    def go_up_dir(self):
        if not self.current_path:
            return
        self.current_path = os.path.dirname(self.current_path).replace("\\", "/")
        self.app.run_threaded_task(self.populate_browser, "Loading Files...")

    def download_selected(self):
        selected_item_id = self.tree.focus()
        if not selected_item_id:
            return messagebox.showwarning("No Selection", "Please select a file to download.", parent=self)

        tags = self.tree.item(selected_item_id, 'tags')
        if 'file' not in tags:
            return messagebox.showwarning("Invalid Selection", "Please select a file, not a folder.", parent=self)

        filename = tags[1]
        server_filepath = os.path.join(self.current_path, filename).replace("\\", "/")

        local_save_path = filedialog.asksaveasfilename(initialfile=filename, parent=self)
        if not local_save_path:
            return

        def task():
            success = self.app.api.download_server_file(server_filepath, local_save_path)
            if success:
                messagebox.showinfo("Success", f"File downloaded successfully to:\n{local_save_path}", parent=self)
        self.app.run_threaded_task(task, "Downloading...")

    def upload_file(self):
        local_path = filedialog.askopenfilename(parent=self)
        if not local_path:
            return

        def task():
            result = self.app.api.upload_file_to_server(local_path, self.current_path)
            self.after(0, self._on_upload_complete, result)

        self.app.run_threaded_task(task, "Uploading...")

    def _on_upload_complete(self, result):
        if result and result.get("status") == "success":
            messagebox.showinfo("Success", result.get("message", "File uploaded successfully!"), parent=self)
            self.app.run_threaded_task(self.populate_browser, "Refreshing Files...")

    def load_settings(self):
        self.app.run_threaded_task(self._load_settings_task, "Loading Settings...")

    def _load_settings_task(self):
        settings = self.app.api.get_server_settings()
        self.after(0, self._update_settings_ui, settings)

    def _update_settings_ui(self, settings):
        if settings:
            self.settings_text.delete('1.0', ttk.END)
            self.settings_text.insert('1.0', json.dumps(settings, indent=4))

    def save_settings(self):
        try:
            settings_str = self.settings_text.get('1.0', ttk.END)
            data_to_save = json.loads(settings_str)
        except json.JSONDecodeError:
            return messagebox.showerror("JSON Error", "The settings text is not valid JSON.", parent=self)

        if messagebox.askyesno("Confirm Save", "Overwrite the server's configuration file? This could break the server if done incorrectly.", parent=self):
            def task():
                result = self.app.api.save_server_settings(data_to_save)
                if result and result.get('status') == 'success':
                    messagebox.showinfo("Success", "Server settings saved successfully.", parent=self)
            self.app.run_threaded_task(task, "Saving Settings...")