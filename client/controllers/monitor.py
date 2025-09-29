import os
import shutil
import threading
import queue
import time
from datetime import datetime
import traceback
import sys

from ..helpers import load_client_config

class MonitorController:
    """
    Manages the background thread for monitoring the image input folder.
    """
    def __init__(self, app):
        self.app = app
        self.stop_event = threading.Event()
        self.file_queue = queue.Queue()
        self.dialog_result_queue = queue.Queue(maxsize=1)
        self.monitor_thread = None
        self.known_files = set()

    def _log_status(self, message):
        """Thread-safe method to log messages to the GUI's status box."""
        self.app.master.after(0, self.app.get_status_box().insert, "end", f"{datetime.now().strftime('%H:%M:%S')} - {message}\n")
        self.app.master.after(0, self.app.get_status_box().see, "end")

    def start(self):
        """Starts the monitoring background thread."""
        self.stop_event.clear()
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        self._log_status("✅ Monitoring started...")

    def stop(self):
        """Signals the monitoring thread to stop."""
        self.stop_event.set()
        self._log_status("🛑 Monitoring stopped.")

    def put_dialog_result(self, image_path, result):
        """Receives the result from the verification dialog and puts it in a queue for the monitor thread."""
        if not self.dialog_result_queue.empty():
            try:
                self.dialog_result_queue.get_nowait()
            except queue.Empty:
                pass
        self.dialog_result_queue.put(result)

    def _get_config_paths(self):
        """Safely loads and returns required folder paths from the client config."""
        config = load_client_config()
        return {
            "input": config.get("IMAGE_INPUT_FOLDER"),
            "processed": config.get("PROCESSED_IMAGES_FOLDER"),
            "skipped": config.get("SKIPPED_IMAGES_FOLDER")
        }

    def requeue_skipped_files(self):
        """Moves all files from the skipped folder back to the input folder for processing."""
        paths = self._get_config_paths()
        if not paths["input"] or not paths["skipped"]:
            self._log_status("❌ Error: Input or Skipped folder not configured.")
            return

        try:
            skipped_files = [f for f in os.listdir(paths["skipped"]) if f.lower().endswith(('.png', '.jpg', '.jpeg'))]
            if not skipped_files:
                self._log_status("ℹ️ No skipped files found to re-process.")
                return

            self._log_status(f"➡️ Re-queueing {len(skipped_files)} skipped files...")
            for filename in skipped_files:
                shutil.move(os.path.join(paths["skipped"], filename), os.path.join(paths["input"], filename))
            self._log_status("✅ All skipped files moved back to the input folder.")
        except Exception as e:
            self._log_status(f"❌ Error re-queueing files: {e}")

    def _monitor_loop(self):
        """The main loop that runs in the background thread."""
        time.sleep(1)
        paths = self._get_config_paths()
        if not all(paths.values()):
            self._log_status("❌ CRITICAL: Monitoring stopped. Please configure all folder paths in Settings.")
            self.app.master.after(0, self.app.on_stop)
            return

        processed_server_log = self.app.api.get_processed_log()

        while not self.stop_event.is_set():
            try:
                current_files = {f for f in os.listdir(paths["input"]) if f.lower().endswith(('.png', '.jpg', '.jpeg'))}
                new_files = current_files - self.known_files

                for f in new_files:
                    if f not in processed_server_log:
                        self.file_queue.put(os.path.join(paths["input"], f))
                        self.known_files.add(f)
                        self._log_status(f"📂 New file detected: {f}")

                if not self.file_queue.empty():
                    image_path = self.file_queue.get()
                    filename = os.path.basename(image_path)

                    if not os.path.exists(image_path):
                        self._log_status(f"⚠️ File no longer exists, skipping: {filename}")
                        self.known_files.discard(filename)
                        continue

                    self._log_status(f"🧠 Processing with OCR: {filename}")
                    self.app.master.after(0, self.app.show_loader, f"Performing OCR on\n{filename}")
                    ocr_data = self.app.api.upload_for_ocr(image_path)

                    if not ocr_data or "error" in ocr_data:
                        self._log_status(f"❌ OCR failed for {filename}. Moving to skipped.")
                        self.app.master.after(0, self.app.hide_loader)
                        shutil.move(image_path, os.path.join(paths["skipped"], filename))
                        self.known_files.discard(filename)
                        continue

                    self._log_status(f"👤 Waiting for user verification for: {filename}")
                    self.app.master.after(0, self.app.show_verification_page, image_path, ocr_data)

                    dialog_result = self.dialog_result_queue.get()

                    if self.stop_event.is_set():
                        break

                    if dialog_result is None:
                        self._log_status(f"↩️ Verification cancelled. Re-queueing: {filename}")
                        self.file_queue.put(image_path)
                    elif dialog_result == "skip":
                        self._log_status(f"⏭️ File skipped by user. Moving to skipped folder: {filename}")
                        shutil.move(image_path, os.path.join(paths["skipped"], filename))
                        self.known_files.discard(filename)
                    else:
                        self.app.master.after(0, self.app.show_loader, f"Saving Log for\n{filename}")
                        self._log_status(f"➡️ Submitting final data for: {filename}")
                        response = self.app.api.process_image(image_path, dialog_result)
                        if response and response.get("status") == "success":
                            self._log_status(f"✅ Successfully processed and logged: {filename}")
                            shutil.move(image_path, os.path.join(paths["processed"], filename))
                            self.known_files.discard(filename)
                        else:
                            self._log_status(f"❌ Server failed to process {filename}. Re-queueing.")
                            self.file_queue.put(image_path)
                        self.app.master.after(0, self.app.hide_loader)

                time.sleep(2)

            except Exception as e:
                self._log_status(f"💥 Unhandled error in monitor loop: {e}")
                traceback.print_exc(file=sys.stdout)
                time.sleep(5)