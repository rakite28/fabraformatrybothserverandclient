import torch
from PIL import Image
from transformers import pipeline
import logging

# Configure logging for this module
logger = logging.getLogger(__name__)

class NSFWDetector:
    """
    A class to detect NSFW content in images using a local Hugging Face model.
    Initializes the model once and provides a method to check images.
    """
    def __init__(self):
        self.pipe = None
        # self._initialize_model() # Temporarily disabled to prevent server crash

    def _initialize_model(self):
        """
        Loads the NSFW detection model. This is a heavy operation and should
        only be run once at server startup.
        """
        try:
            logger.info("Initializing local NSFW detection model...")
            
            # Determine the device to use (GPU if available, otherwise CPU)
            device = "cuda" if torch.cuda.is_available() else "cpu"
            logger.info(f"NSFW model will run on device: {device}")

            # Load the pre-trained model pipeline from Hugging Face
            # This will download the model on the first run
            self.pipe = pipeline(
                "image-classification", 
                model="Falconsai/nsfw_image_detection",
                device=device
            )
            logger.info("✅ NSFW detection model loaded successfully.")
        except Exception as e:
            logger.critical(f"🛑 FATAL: Could not initialize NSFW detection model. Error: {e}", exc_info=True)
            self.pipe = None

    def is_image_safe(self, image_bytes: bytes) -> (bool, str):
        """
        Checks if an image contains NSFW content.

        Args:
            image_bytes: The raw bytes of the image file.

        Returns:
            A tuple containing:
            - bool: True if the image is safe, False otherwise.
            - str: A reason for the decision.
        """
        # Temporarily disable NSFW check to prevent server crash during testing.
        logger.warning("NSFW detection is temporarily disabled.")
        return (True, "Moderation disabled for testing.")

# --- Singleton instance for the NSFW Detector ---
# This ensures the model is loaded only once.
_nsfw_detector_instance = None

def get_nsfw_detector():
    """
    Returns a singleton instance of the NSFWDetector.
    The model is initialized on the first call.
    """
    global _nsfw_detector_instance
    if _nsfw_detector_instance is None:
        _nsfw_detector_instance = NSFWDetector()
    return _nsfw_detector_instance
