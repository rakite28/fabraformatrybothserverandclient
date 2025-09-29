import ttkbootstrap as ttk
from PIL import Image, ImageTk
import requests
from io import BytesIO
import threading

class ImageCanvas(ttk.Frame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.original_image = None
        self.zoom_factor = 1.0
        self.image_tk = None

        self.canvas = ttk.Canvas(self, highlightthickness=0)
        self.canvas.grid(row=0, column=0, sticky='nsew')

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.canvas.bind('<MouseWheel>', self.zoom)
        self.canvas.bind('<ButtonPress-1>', self.start_pan)
        self.canvas.bind('<B1-Motion>', self.pan)

    def load_image_from_url(self, url):
        self.canvas.delete("all")
        self.canvas.create_text(self.winfo_width()/2, self.winfo_height()/2, text="Loading image...", fill="#ffafda", font=('Montserrat', 12))
        self.original_image = None
        threading.Thread(target=self._fetch_image, args=(url,), daemon=True).start()

    def _fetch_image(self, url):
        try:
            api_client = self.winfo_toplevel().app.api
            headers = api_client._get_auth_header()
            if not headers: raise Exception("Authentication failed.")
            response = requests.get(url, stream=True, headers=headers)
            response.raise_for_status()
            image = Image.open(BytesIO(response.content))
            self.after(0, self._display_fetched_image, image)
        except (requests.exceptions.RequestException, IOError, Exception) as e:
            self.after(0, self._display_fetch_error, e)

    def _display_fetched_image(self, image):
        self.original_image = image
        self.after(100, self.fit_image_to_canvas)

    def _display_fetch_error(self, e):
        self.canvas.delete("all")
        self.canvas.create_text(self.winfo_width()/2, self.winfo_height()/2, text=f"Image not found\n{e}", fill="#ffafda", font=('Montserrat', 12))
        self.original_image = None

    def load_image_from_path(self, path):
        try:
            self.original_image = Image.open(path)
            self.after(100, self.fit_image_to_canvas)
        except (IOError) as e:
            self.canvas.delete("all")
            self.canvas.create_text(self.winfo_width()/2, self.winfo_height()/2, text=f"Image not found\n{e}", fill="#ffafda", font=('Montserrat', 12))
            self.original_image = None

    def fit_image_to_canvas(self):
        if not self.original_image: return
        if (canvas_width := self.winfo_width()) <= 1 or (canvas_height := self.winfo_height()) <= 1:
            self.after(100, self.fit_image_to_canvas)
            return
        img_width, img_height = self.original_image.size
        self.zoom_factor = min(canvas_width / img_width, canvas_height / img_height)
        self.display_image()

    def display_image(self):
        if not self.original_image: return
        width = int(self.original_image.width * self.zoom_factor)
        height = int(self.original_image.height * self.zoom_factor)
        resized_image = self.original_image.resize((width, height), Image.Resampling.LANCZOS)
        self.image_tk = ImageTk.PhotoImage(resized_image)
        self.canvas.delete("all")
        self.canvas.create_image((self.winfo_width() - width) / 2, (self.winfo_height() - height) / 2, anchor='nw', image=self.image_tk)
        self.canvas.config(scrollregion=self.canvas.bbox("all"))

    def zoom(self, event):
        if not self.original_image: return
        self.zoom_factor *= 1.1 if event.delta > 0 else 1/1.1
        self.zoom_factor = max(0.1, min(5.0, self.zoom_factor))
        self.display_image()

    def start_pan(self, event):
        self.canvas.scan_mark(event.x, event.y)

    def pan(self, event):
        self.canvas.scan_dragto(event.x, event.y, gain=1)