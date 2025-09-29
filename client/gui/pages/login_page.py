import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox

from .base_page import Page
from ...helpers import load_client_config, save_client_config

class LoginPage(Page):
    def __init__(self, master, app, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.app = app
        self.container = ttk.Frame(self)
        self.container.place(relx=0.5, rely=0.5, anchor="center")

        self.create_login_widgets()
        self.create_register_widgets()

        self.show_login()

    def create_login_widgets(self):
        self.login_frame = ttk.Frame(self.container)

        title = ttk.Label(self.login_frame, text="FabraForma AL Login", font=('Montserrat', 16, 'bold'), bootstyle="primary")
        title.pack(pady=(0, 20))

        ttk.Label(self.login_frame, text="Email or Username:").pack(anchor='w', padx=10)
        self.identifier_var = ttk.StringVar()
        ttk.Entry(self.login_frame, textvariable=self.identifier_var, width=40).pack(pady=(0, 10), padx=10)

        ttk.Label(self.login_frame, text="Password:").pack(anchor='w', padx=10)
        self.password_var = ttk.StringVar()
        ttk.Entry(self.login_frame, textvariable=self.password_var, show="*", width=40).pack(pady=(0, 10), padx=10)

        self.remember_me_var = ttk.BooleanVar()
        ttk.Checkbutton(self.login_frame, text="Remember Me", variable=self.remember_me_var, bootstyle="primary").pack(pady=5, padx=10, anchor='w')

        self.login_button = ttk.Button(self.login_frame, text="Login", command=self.attempt_login, bootstyle="primary")
        self.login_button.pack(pady=10, fill=X, padx=10)

        self.switch_to_reg_button = ttk.Button(self.login_frame, text="Register New Company", command=self.show_register, bootstyle="secondary")
        self.switch_to_reg_button.pack(pady=(5,10), fill=X, padx=10)

        self.status_label = ttk.Label(self.login_frame, text="", bootstyle="danger")
        self.status_label.pack()

    def create_register_widgets(self):
        self.register_frame = ttk.Frame(self.container)

        title = ttk.Label(self.register_frame, text="Register New Company", font=('Montserrat', 16, 'bold'), bootstyle="primary")
        title.pack(pady=(0, 20))

        fields = {
            "Company Name:": ttk.StringVar(),
            "Your Username:": ttk.StringVar(),
            "Your Email:": ttk.StringVar(),
            "Password:": ttk.StringVar(),
            "Confirm Password:": ttk.StringVar()
        }
        self.reg_vars = fields

        for label, var in fields.items():
            ttk.Label(self.register_frame, text=label).pack(anchor='w', padx=10)
            show_char = "*" if "Password" in label else ""
            ttk.Entry(self.register_frame, textvariable=var, show=show_char, width=40).pack(pady=(0, 10), padx=10)

        self.register_button = ttk.Button(self.register_frame, text="Register", command=self.attempt_register, bootstyle="primary")
        self.register_button.pack(pady=10, fill=X, padx=10)

        self.switch_to_login_button = ttk.Button(self.register_frame, text="Back to Login", command=self.show_login, bootstyle="secondary")
        self.switch_to_login_button.pack(pady=(5,10), fill=X, padx=10)

    def show_login(self):
        self.register_frame.pack_forget()
        self.login_frame.pack(fill="both", expand=True)

    def show_register(self):
        self.login_frame.pack_forget()
        self.register_frame.pack(fill="both", expand=True)

    def attempt_login(self):
        identifier = self.identifier_var.get()
        password = self.password_var.get()
        remember = self.remember_me_var.get()

        if not all([identifier, password]):
            self.status_label.config(text="Username/Email and password are required.")
            return
        self.login_button.config(state="disabled")
        self.status_label.config(text="")

        def login_task():
            response_data = self.app.api.login(identifier, password, remember)
            self.master.after(0, self._process_login_result, response_data)

        self.app.run_threaded_task(login_task, "Logging In...")

    def _process_login_result(self, response_data):
        self.login_button.config(state="normal")
        if response_data and 'token' in response_data:
            if 'remember_token' in response_data:
                config = load_client_config()
                config['remember_token'] = response_data['remember_token']
                save_client_config(config)
            self.status_label.config(text="")
            self.app.on_login_success()
        else:
            # The API client now shows a detailed error popup, so this label is less critical
            self.status_label.config(text="Login failed. Check credentials.")
            self.password_var.set("")

    def attempt_register(self):
        company = self.reg_vars["Company Name:"].get()
        user = self.reg_vars["Your Username:"].get()
        email = self.reg_vars["Your Email:"].get()
        pwd1 = self.reg_vars["Password:"].get()
        pwd2 = self.reg_vars["Confirm Password:"].get()

        if not all([company, user, email, pwd1, pwd2]):
            messagebox.showerror("Input Error", "All fields are required.", parent=self)
            return
        if pwd1 != pwd2:
            messagebox.showerror("Input Error", "Passwords do not match.", parent=self)
            return

        def task():
            result = self.app.api.register_company(company, user, email, pwd1)
            if result and result.get('message'):
                messagebox.showinfo("Success", result['message'], parent=self)
                if "successfully" in result['message']:
                    self.master.after(0, self.show_login)

        self.app.run_threaded_task(task, "Registering...")