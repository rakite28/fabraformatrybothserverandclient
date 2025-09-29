import ttkbootstrap as ttk

class Page(ttk.Frame):
    """Base class for all pages in the application."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def show(self):
        """Brings the page to the top of the stacking order."""
        self.lift()

    def on_show(self):
        """
        A lifecycle method called when the page is shown.
        Subclasses should override this to refresh their content.
        """
        pass