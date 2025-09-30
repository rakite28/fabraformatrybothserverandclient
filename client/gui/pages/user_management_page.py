import ttkbootstrap as ttk
from tkinter import messagebox

from .base_page import Page

class UserManagementPage(Page):
    def __init__(self, master, app, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.app = app

        ttk.Label(self, text="User Management", font=('Montserrat', 16, 'bold'), bootstyle="primary").pack(anchor="w", padx=10, pady=(5,10))

        container = ttk.Frame(self, padding=20)
        container.pack(fill="both", expand=True, padx=10)

        # Use packing to center the form vertically
        ttk.Frame(container).pack(fill="y", expand=True)

        form_frame = ttk.Labelframe(container, text="Create New User", bootstyle="info")
        form_frame.pack(fill="x", expand=False)

        ttk.Label(form_frame, text="Username:").grid(row=0, column=0, sticky="w", padx=10, pady=6)
        self.username = ttk.StringVar()
        ttk.Entry(form_frame, textvariable=self.username, width=40).grid(row=0, column=1, padx=10, pady=6, sticky="ew")

        ttk.Label(form_frame, text="Email:").grid(row=1, column=0, sticky="w", padx=10, pady=6)
        self.email = ttk.StringVar()
        ttk.Entry(form_frame, textvariable=self.email, width=40).grid(row=1, column=1, padx=10, pady=6, sticky="ew")

        ttk.Label(form_frame, text="Password:").grid(row=2, column=0, sticky="w", padx=10, pady=6)
        self.password = ttk.StringVar()
        ttk.Entry(form_frame, textvariable=self.password, show="*", width=40).grid(row=2, column=1, padx=10, pady=6, sticky="ew")

        ttk.Label(form_frame, text="Role:").grid(row=3, column=0, sticky="w", padx=10, pady=6)
        self.role = ttk.StringVar(value='user')
        role_dropdown = ttk.Combobox(form_frame, textvariable=self.role, state="readonly", values=['user', 'admin'])
        role_dropdown.grid(row=3, column=1, padx=10, pady=6, sticky="ew")

        form_frame.columnconfigure(1, weight=1)

        ttk.Button(container, text="Create User", command=self.create_user, bootstyle="primary").pack(pady=20)

        ttk.Frame(container).pack(fill="y", expand=True)

    def on_show(self):
        self.username.set("")
        self.email.set("")
        self.password.set("")
        self.role.set("user")

    def create_user(self):
        user = self.username.get()
        email = self.email.get()
        pwd = self.password.get()
        role = self.role.get()

        if not all([user, email, pwd, role]):
            return messagebox.showerror("Input Error", "Username, Email, Password, and Role are required.", parent=self)

        def task():
            result = self.app.api.create_user(user, email, pwd, role)
            if result:
                messagebox.showinfo("Success", result.get("message", "User created successfully!"), parent=self)
                self.on_show()

        self.app.run_threaded_task(task, "Creating User...")