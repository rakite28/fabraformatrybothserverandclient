import threading
import ttkbootstrap as ttk
from tkinter import messagebox, filedialog
from PIL import Image, ImageTk, ImageOps
from io import BytesIO
import requests

from .base_page import Page
from ...helpers import create_circular_image

class ProfilePage(Page):
    def __init__(self, master, app, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.app = app
        self.profile_photo = None

        ttk.Label(self, text="User Profile", font=('Montserrat', 16, 'bold'), bootstyle="primary").pack(anchor="w", padx=20, pady=(10,5))

        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill="both", expand=True, padx=20, pady=10)
        main_frame.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)

        details_frame = ttk.Labelframe(main_frame, text="Profile Details", bootstyle="info", padding=15)
        details_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 20))
        details_frame.columnconfigure(1, weight=1)
        details_frame.rowconfigure(5, weight=1)

        self.username_var = ttk.StringVar()
        self.email_var = ttk.StringVar()
        self.phone_var = ttk.StringVar()
        self.dob_var = ttk.StringVar()

        ttk.Label(details_frame, text="Username:").grid(row=0, column=0, sticky="w", pady=6)
        ttk.Entry(details_frame, textvariable=self.username_var, width=40).grid(row=0, column=1, sticky="ew", pady=6)

        ttk.Label(details_frame, text="Email:").grid(row=1, column=0, sticky="w", pady=6)
        ttk.Entry(details_frame, textvariable=self.email_var, state="readonly", width=40).grid(row=1, column=1, sticky="ew", pady=6)

        ttk.Label(details_frame, text="Phone Number:").grid(row=2, column=0, sticky="w", pady=6)
        ttk.Entry(details_frame, textvariable=self.phone_var, width=40).grid(row=2, column=1, sticky="ew", pady=6)

        ttk.Label(details_frame, text="Date of Birth (YYYY-MM-DD):").grid(row=3, column=0, sticky="w", pady=6)
        ttk.Entry(details_frame, textvariable=self.dob_var, width=40).grid(row=3, column=1, sticky="ew", pady=6)

        ttk.Button(details_frame, text="Save Profile Changes", command=self.save_profile, bootstyle="primary").grid(row=4, column=0, columnspan=2, pady=(20, 5))

        right_frame = ttk.Frame(main_frame)
        right_frame.grid(row=0, column=1, sticky="nsew")

        pic_frame = ttk.Labelframe(right_frame, text="Profile Picture", bootstyle="info", padding=15)
        pic_frame.pack(fill="x", pady=(0, 20))

        self.pic_label = ttk.Label(pic_frame, text="No Image", width=20, anchor=ttk.CENTER)
        self.pic_label.pack(pady=5)
        ttk.Button(pic_frame, text="Upload New Picture", command=self.upload_picture, bootstyle="secondary").pack(pady=(5,0))

        pass_frame = ttk.Labelframe(right_frame, text="Change Password", bootstyle="info", padding=15)
        pass_frame.pack(fill="x")
        pass_frame.columnconfigure(1, weight=1)
        pass_frame.rowconfigure(4, weight=1)

        self.current_pass_var = ttk.StringVar()
        self.new_pass1_var = ttk.StringVar()
        self.new_pass2_var = ttk.StringVar()

        ttk.Label(pass_frame, text="Current Password:").grid(row=0, column=0, sticky="w", pady=6)
        ttk.Entry(pass_frame, textvariable=self.current_pass_var, show="*", width=30).grid(row=0, column=1, sticky="ew", pady=6)

        ttk.Label(pass_frame, text="New Password:").grid(row=1, column=0, sticky="w", pady=6)
        ttk.Entry(pass_frame, textvariable=self.new_pass1_var, show="*", width=30).grid(row=1, column=1, sticky="ew", pady=6)

        ttk.Label(pass_frame, text="Confirm New Password:").grid(row=2, column=0, sticky="w", pady=6)
        ttk.Entry(pass_frame, textvariable=self.new_pass2_var, show="*", width=30).grid(row=2, column=1, sticky="ew", pady=6)

        ttk.Button(pass_frame, text="Change Password", command=self.change_password, bootstyle="info").grid(row=3, column=0, columnspan=2, pady=(20, 5))

        ttk.Button(main_frame, text="Logout", command=self.app.on_logout, bootstyle="danger").grid(row=1, column=0, columnspan=2, pady=(30, 10), sticky="s")
        main_frame.rowconfigure(1, weight=1)

    def on_show(self):
        cached_data = self.app.get_cached_data('profile')
        if cached_data:
            self.populate_form(cached_data)
            self.pic_label.config(image='', text="Loading...")
        else:
            self.clear_form()

        threading.Thread(target=self._refresh_profile_data, daemon=True).start()

    def _refresh_profile_data(self):
        profile_data = self.app.api.get_profile()
        if profile_data:
            self.app.cache_data('profile', profile_data)
            self.after(0, self.populate_form, profile_data)

            if profile_data.get('profile_picture_url'):
                try:
                    headers = self.app.api._get_auth_header()
                    if not headers: return
                    response = requests.get(profile_data['profile_picture_url'], stream=True, headers=headers)
                    response.raise_for_status()
                    image = Image.open(BytesIO(response.content))
                    resized_image = ImageOps.fit(image, (150, 150), Image.Resampling.LANCZOS)
                    self.after(0, self._update_image_ui, resized_image)
                except Exception as e:
                    print(f"Failed to load profile page image: {e}")
                    self.after(0, self._update_image_ui, None)

    def populate_form(self, data):
        self.username_var.set(data.get('username', ''))
        self.email_var.set(data.get('email', ''))
        self.phone_var.set(data.get('phone_number', ''))
        self.dob_var.set(data.get('dob', ''))

    def _update_image_ui(self, pil_image):
        if pil_image:
            try:
                self.profile_photo = ImageTk.PhotoImage(pil_image)
                self.pic_label.config(image=self.profile_photo, text="")
            except Exception as e:
                print(f"Failed to create Tkinter image for profile page: {e}")
                self.pic_label.config(image='', text="Load Failed")
        else:
            self.pic_label.config(image='', text="Load Failed")

    def clear_form(self):
        self.username_var.set("Loading...")
        self.email_var.set("Loading...")
        self.phone_var.set("Loading...")
        self.dob_var.set("Loading...")
        self.current_pass_var.set("")
        self.new_pass1_var.set("")
        self.new_pass2_var.set("")
        self.pic_label.config(image='', text="Loading...")

    def save_profile(self):
        data_to_save = {
            "username": self.username_var.get(),
            "phone_number": self.phone_var.get(),
            "dob": self.dob_var.get()
        }
        def task():
            result = self.app.api.update_profile(data_to_save)
            if result:
                messagebox.showinfo("Success", "Profile updated successfully.", parent=self)
                self.app.update_profile_widget(force_refresh=True)
        self.app.run_threaded_task(task, "Saving Profile...")

    def upload_picture(self):
        file_path = filedialog.askopenfilename(title="Select Profile Picture", filetypes=[("Image files", "*.png *.jpg *.jpeg"), ("All files", "*.*")])
        if not file_path: return

        def task():
            result = self.app.api.upload_profile_picture(file_path)
            if result:
                messagebox.showinfo("Success", "Profile picture uploaded. It will update shortly.", parent=self)
                self.on_show()
                self.app.update_profile_widget(force_refresh=True)
        self.app.run_threaded_task(task, "Uploading Picture...")

    def change_password(self):
        current_pass = self.current_pass_var.get()
        new_pass1 = self.new_pass1_var.get()
        new_pass2 = self.new_pass2_var.get()

        if not all([current_pass, new_pass1, new_pass2]):
            return messagebox.showerror("Input Error", "All password fields are required.", parent=self)
        if new_pass1 != new_pass2:
            return messagebox.showerror("Input Error", "New passwords do not match.", parent=self)

        def task():
            result = self.app.api.change_password(current_pass, new_pass1)
            if result:
                messagebox.showinfo("Success", "Password changed successfully.", parent=self)
                self.current_pass_var.set("")
                self.new_pass1_var.set("")
                self.new_pass2_var.set("")

        self.app.run_threaded_task(task, "Changing Password...")