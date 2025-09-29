import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import scrolledtext

from .base_page import Page

class MonitorPage(Page):
    def __init__(self, master, app, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.app = app
        ttk.Label(self, text="Monitoring Log", font=('Montserrat', 16, 'bold'), bootstyle="primary").pack(anchor="w", padx=10, pady=(5,0))

        top_frame = ttk.Frame(self)
        top_frame.pack(pady=10, padx=10, fill="x")

        self.start_button = ttk.Button(top_frame, text="Start Monitoring", command=app.on_start, bootstyle="primary")
        self.start_button.pack(side="left", padx=5)

        self.stop_button = ttk.Button(top_frame, text="Stop Monitoring", command=app.on_stop, state="disabled", bootstyle="secondary")
        self.stop_button.pack(side="left", padx=5)

        self.skip_button = ttk.Button(top_frame, text="Process Skipped Files", command=self.process_skipped, bootstyle="info")
        self.skip_button.pack(side="right", padx=5)

        self.status_text = scrolledtext.ScrolledText(self, height=15, width=100,
                                                      bg="#3a4be3", fg="#ffafda", relief="flat", bd=5,
                                                      font=("Consolas", 11), insertbackground="#ffafda")
        self.status_text.pack(padx=10, pady=(0, 10), fill="both", expand=True)
        self.status_text.insert(END, "📡 Bot is idle. Press Start to begin monitoring.\n")

    def get_status_box(self):
        return self.status_text

    def set_bot_status(self, is_running):
        self.start_button.config(state="disabled" if is_running else "normal")
        self.stop_button.config(state="normal" if is_running else "disabled")
        self.skip_button.config(state="disabled" if is_running else "normal")
        self.app.update_sidebar_state(is_running)

    def process_skipped(self):
        if self.app.monitor_controller:
            self.app.run_threaded_task(self.app.monitor_controller.requeue_skipped_files, "Processing Skipped Files...")