import os
import sys
import threading
import traceback
from datetime import datetime

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox

# Add the project root to the path to allow for absolute imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from client.api.client import APIClient
from client.controllers.monitor import MonitorController
from client.helpers import load_client_config, save_client_config, create_circular_image
from client.gui.pages.base_page import Page
from client.gui.pages.login_page import LoginPage
from client.gui.pages.monitor_page import MonitorPage
from client.gui.pages.logs_page import LogsPage
from client.gui.pages.printers_page import PrintersPage
from client.gui.pages.filaments_page import FilamentsPage
from client.gui.pages.settings_page import SettingsPage
from client.gui.pages.server_page import ServerPage
from client.gui.pages.user_management_page import UserManagementPage
from client.gui.pages.profile_page import ProfilePage
from client.gui.pages.verification_page import VerificationPage
from client.gui.pages.quotation_page import QuotationPage
from client.gui.pages.slicer_profiles_page import SlicerProfilesPage

class MainApp:
    def __init__(self, master):
        self.master = master
        master.title("FabraForma AL - Additive Ledger Client")
        master.minsize(1280, 720)
        master.app = self

        self.api = APIClient()
        self.monitor_controller = None
        self.main_ui_built = False
        self.sidebar_frame = None
        self.main_frame = None
        self.pages = {}
        self.sidebar_buttons = {}
        self.profile_photo = None
        self.cache = {}

        self.login_page = LoginPage(self.master, self)
        self.login_page.pack(fill="both", expand=True)

        self.loading_frame = None
        self._create_loading_widget()

        master.after(100, self.attempt_auto_login)

    def _create_loading_widget(self):
        self.loading_frame = ttk.Frame(self.master, bootstyle="dark")
        container = ttk.Frame(self.loading_frame, padding=20, bootstyle="dark")
        container.place(relx=0.5, rely=0.5, anchor="center")

        self.loading_label = ttk.Label(container, text="Loading...", font=('-size', 12), bootstyle="inverse-dark")
        self.loading_label.pack(pady=(0, 10))

        progress = ttk.Progressbar(container, mode='indeterminate', bootstyle="primary")
        progress.pack()
        progress.start(10)

    def show_loader(self, title="Processing..."):
        if self.loading_frame:
            self.loading_label.config(text=title)
            self.loading_frame.place(relx=0, rely=0, relwidth=1, relheight=1)
            self.loading_frame.lift()

    def hide_loader(self):
        if self.loading_frame:
            self.loading_frame.place_forget()

    def run_threaded_task(self, task_func, loader_title="Processing..."):
        self.show_loader(loader_title)
        def task_wrapper():
            try:
                task_func()
            except Exception as e:
                print(f"Error in threaded task: {e}")
                traceback.print_exc()
            finally:
                self.master.after(0, self.hide_loader)
        threading.Thread(target=task_wrapper, daemon=True).start()

    def attempt_auto_login(self):
        config = load_client_config()
        remember_token = config.get('remember_token')
        if remember_token:
            def auto_login_task():
                success = self.api.refresh_token(remember_token)
                self.master.after(0, self._on_auto_login_complete, success)

            self.show_loader("Logging In...")
            threading.Thread(target=auto_login_task, daemon=True).start()

    def _on_auto_login_complete(self, success):
        self.hide_loader()
        if success:
            self.on_login_success()

    def on_login_success(self):
        self.login_page.pack_forget()
        if not self.main_ui_built:
            self.build_main_ui()
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.main_frame.grid(row=0, column=1, sticky="nsew")
        self.update_ui_for_role()
        self.show_page("Monitor")
        self.update_profile_widget()

    def on_logout(self):
        if self.monitor_controller and not self.monitor_controller.stop_event.is_set():
            self.on_stop()

        self.cache = {}
        config = load_client_config()
        remember_token = config.pop('remember_token', None)
        save_client_config(config)

        self.api.logout(remember_token=remember_token)

        if self.sidebar_frame: self.sidebar_frame.grid_forget()
        if self.main_frame: self.main_frame.grid_forget()
        self.login_page.pack(fill="both", expand=True)
        self.login_page.password_var.set("")

    def build_main_ui(self):
        self.master.rowconfigure(0, weight=1)
        self.master.columnconfigure(1, weight=5)

        style = ttk.Style()
        style.configure('.', font=('Montserrat', 10))
        style.configure('TLabel', font=('Montserrat', 10))
        style.configure('TButton', font=('Montserrat', 10))
        style.configure('Treeview.Heading', font=('Montserrat', 11, 'bold'))

        self.sidebar_frame = ttk.Frame(self.master, bootstyle="secondary")
        self.main_frame = ttk.Frame(self.master)

        self.sidebar_frame.columnconfigure(0, weight=1)

        page_list = [
            (MonitorPage, "Monitor"), (QuotationPage, "Quotation"),
            (SlicerProfilesPage, "Slicer Profiles"),
            (LogsPage, "Logs"), (PrintersPage, "Printers"),
            (FilamentsPage, "Filaments"), (UserManagementPage, "User Management"),
            (ServerPage, "Server"), (SettingsPage, "Settings"),
            (ProfilePage, "Profile"), (VerificationPage, "Verification")
        ]

        for PageClass, name in page_list:
            frame = PageClass(self.main_frame, self)
            self.pages[name] = frame
            frame.place(x=0, y=0, relwidth=1, relheight=1)

        self.profile_frame = ttk.Frame(self.sidebar_frame, bootstyle="dark")
        self.profile_icon_label = ttk.Label(self.profile_frame, text="👤", font=('Montserrat', 16), bootstyle="inverse-dark")
        self.profile_icon_label.pack(side="left", padx=(10, 5), pady=5)
        self.profile_name_label = ttk.Label(self.profile_frame, text="Loading...", anchor="w", bootstyle="inverse-dark")
        self.profile_name_label.pack(side="left", fill="x", expand=True, pady=5)

        self.profile_frame.bind("<Button-1>", lambda e: self.show_page("Profile"))
        self.profile_icon_label.bind("<Button-1>", lambda e: self.show_page("Profile"))
        self.profile_name_label.bind("<Button-1>", lambda e: self.show_page("Profile"))

        self.main_ui_built = True

    def update_ui_for_role(self):
        for widget in self.sidebar_frame.winfo_children():
            if widget != self.profile_frame:
                widget.destroy()

        is_admin = self.api.user_info.get('role') == 'admin'
        button_order = [
            "Monitor", "Quotation", "Slicer Profiles", "Logs", "Printers",
            "Filaments", "User Management", "Server", "Settings"
        ]

        self.sidebar_buttons = {}
        row_counter = 0
        for name in button_order:
            if name in ["Server", "User Management"] and not is_admin:
                continue

            button = ttk.Button(self.sidebar_frame, text=name, bootstyle="dark-outline", command=lambda n=name: self.show_page(n))
            button.grid(row=row_counter, column=0, sticky="ew", padx=10, pady=2, ipady=5)
            self.sidebar_buttons[name] = button
            row_counter += 1

        self.sidebar_frame.rowconfigure(row_counter, weight=1)
        self.profile_frame.grid(row=row_counter + 1, column=0, sticky="sew", padx=10, pady=10)

    def cache_data(self, key, data):
        self.cache[key] = data

    def get_cached_data(self, key):
        return self.cache.get(key)

    def update_profile_widget(self, force_refresh=False):
        # ... (implementation to be added)
        pass

    def show_page(self, page_name):
        for name, button in self.sidebar_buttons.items():
            button.config(bootstyle="dark-outline" if name != page_name else "primary")
        self.profile_frame.config(bootstyle="dark" if page_name != "Profile" else "primary")
        self.profile_icon_label.config(bootstyle="inverse-dark" if page_name != "Profile" else "inverse-primary")
        self.profile_name_label.config(bootstyle="inverse-dark" if page_name != "Profile" else "inverse-primary")
        page = self.pages[page_name]
        page.on_show()
        page.show()

    def on_start(self):
        self.monitor_controller = MonitorController(self)
        self.monitor_controller.start()
        self.pages["Monitor"].set_bot_status(is_running=True)

    def on_stop(self):
        if self.monitor_controller:
            self.monitor_controller.stop()
        self.pages["Monitor"].set_bot_status(is_running=False)

    def get_status_box(self):
        return self.pages["Monitor"].get_status_box()

    def show_verification_page(self, image_path, ocr_data):
        self.hide_loader()
        self.show_page("Verification")
        self.pages["Verification"].load_data(image_path, ocr_data)

    def on_verification_complete(self, original_image_path, result):
        if self.monitor_controller:
            self.monitor_controller.put_dialog_result(original_image_path, result)
        if self.pages["Verification"].is_active:
            self.show_page("Monitor")

def initialize_client_config():
    # ... (implementation to be added)
    return True

if __name__ == "__main__":
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except (ImportError, AttributeError):
        pass

    if initialize_client_config():
        root = ttk.Window()

        # Set the window icon, assuming execution from the 'client' directory
        try:
            logo_path = 'logo.png'
            if os.path.exists(logo_path):
                root.iconphoto(False, ttk.PhotoImage(file=logo_path))
        except Exception as e:
            print(f"Could not load window icon: {e}")
        style = ttk.Style()
        theme_colors = {
            "primary": "#3a4be3", "secondary": "#29349b", "success": "#3498db",
            "info": "#ffafda", "warning": "#f39c12", "danger": "#e74c3c",
            "light": "#3b4a91", "dark": "#1c246d", "bg": "#1c246d", "fg": "#ffafda",
            "selectbg": "#3a4be3", "selectfg": "#ffffff", "border": "#3a4be3",
            "inputfg": "#ffafda", "inputbg": "#29349b"
        }
        style.theme_create("fabraforma_custom", parent="darkly", settings={
            ".": {"configure": {"background": theme_colors["bg"], "foreground": theme_colors["fg"]}},
            "TLabel": {"configure": {"foreground": theme_colors["fg"], "background": theme_colors["bg"]}},
            "TButton": {"map": {"background": [("active", theme_colors["selectbg"])]}},
            "Treeview": {"map": {"background": [('selected', theme_colors["selectbg"])]}}
        })
        style.theme_use("fabraforma_custom")

        app = MainApp(root)

        app_width, app_height = 1280, 720
        screen_width, screen_height = root.winfo_screenwidth(), root.winfo_screenheight()
        x = (screen_width / 2) - (app_width / 2)
        y = (screen_height / 2) - (app_height / 2)
        root.geometry(f'{app_width}x{app_height}+{int(x)}+{int(y)}')

        def on_closing():
            if app.monitor_controller and not app.monitor_controller.stop_event.is_set():
                if messagebox.askokcancel("Quit", "The bot is still running. Are you sure you want to quit?"):
                    app.on_stop()
                    root.destroy()
            else:
                root.destroy()

        root.protocol("WM_DELETE_WINDOW", on_closing)
        root.mainloop()