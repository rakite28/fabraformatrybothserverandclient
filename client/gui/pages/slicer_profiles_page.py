import ttkbootstrap as ttk
from tkinter import filedialog, messagebox

from .base_page import Page

class SlicerProfilesPage(Page):
    def __init__(self, master, app, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.app = app
        self.profiles = {}

        ttk.Label(self, text="Slicer Profile Management", font=('Montserrat', 16, 'bold'), bootstyle="primary").pack(anchor="w", padx=10, pady=(5,10))

        button_frame = ttk.Frame(self)
        button_frame.pack(fill='x', padx=10, pady=5)
        ttk.Button(button_frame, text="Refresh Profiles", command=self.on_show, bootstyle="info").pack(side='right')

        main_pane = ttk.PanedWindow(self, orient=ttk.HORIZONTAL)
        main_pane.pack(fill=ttk.BOTH, expand=True, padx=10, pady=10)

        self.profile_types = ['machine', 'filament', 'process']
        self.trees = {}

        for p_type in self.profile_types:
            frame = ttk.Labelframe(main_pane, text=f"{p_type.title()} Profiles", bootstyle="info")
            main_pane.add(frame, weight=1)

            tree_container = ttk.Frame(frame)
            tree_container.pack(fill='both', expand=True, padx=5, pady=5)

            tree = ttk.Treeview(tree_container, columns=("Name", "Source"), show="headings", bootstyle="primary")
            tree.heading("Name", text="Profile Name")
            tree.heading("Source", text="Source")
            tree.column("Name", width=250)
            tree.column("Source", width=80, anchor="center")

            scrollbar = ttk.Scrollbar(tree_container, orient="vertical", command=tree.yview, bootstyle="round-light")
            tree.configure(yscroll=scrollbar.set)
            tree.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            self.trees[p_type] = tree

            tree.tag_configure('custom', foreground=self.app.master.style.colors.info)

            action_buttons = ttk.Frame(frame)
            action_buttons.pack(fill='x', padx=5, pady=5)
            ttk.Button(action_buttons, text="Upload New...", command=lambda t=p_type: self.upload_profile(t), bootstyle="primary").pack(side='left')
            ttk.Button(action_buttons, text="Delete Selected", command=lambda t=p_type: self.delete_profile(t), bootstyle="danger-outline").pack(side='left', padx=5)

    def on_show(self):
        self.app.run_threaded_task(self.fetch_profiles, "Loading Slicer Profiles...")

    def fetch_profiles(self):
        profiles = self.app.api.get_slicer_profiles()
        self.after(0, self.populate_trees, profiles)

    def populate_trees(self, profiles):
        self.profiles = profiles
        if not profiles:
            return

        for p_type, tree in self.trees.items():
            tree.delete(*tree.get_children())

            for filename in sorted(profiles.get("user", {}).get(p_type, [])):
                tree.insert('', 'end', values=(filename, "Custom"), tags=('custom',))

            for filename in sorted(profiles.get("system", {}).get(p_type, [])):
                tree.insert('', 'end', values=(filename, "System"), tags=('system',))

    def upload_profile(self, profile_type):
        file_path = filedialog.askopenfilename(
            title=f"Select {profile_type.title()} Profile",
            filetypes=[("JSON Config", "*.json")]
        )
        if not file_path: return

        def task():
            result = self.app.api.upload_slicer_profile(profile_type, file_path)
            if result and result.get("status") == "success":
                self.after(0, lambda: messagebox.showinfo("Success", result['message'], parent=self))
                self.fetch_profiles()

        self.app.run_threaded_task(task, f"Uploading {profile_type} profile...")

    def delete_profile(self, profile_type):
        tree = self.trees[profile_type]
        selected_item = tree.focus()
        if not selected_item:
            return messagebox.showwarning("No Selection", "Please select a custom profile to delete.", parent=self)

        item_tags = tree.item(selected_item, 'tags')
        if 'system' in item_tags:
            return messagebox.showerror("Permission Denied", "System profiles cannot be deleted.", parent=self)

        filename = tree.item(selected_item, 'values')[0]
        if not messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete your custom profile:\n\n{filename}", parent=self):
            return

        def task():
            result = self.app.api.delete_slicer_profile(profile_type, filename)
            if result and result.get("status") == "success":
                self.after(0, lambda: messagebox.showinfo("Success", result['message'], parent=self))
                self.fetch_profiles()

        self.app.run_threaded_task(task, f"Deleting {profile_type} profile...")