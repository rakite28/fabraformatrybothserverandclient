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
        self._initialize_model()

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
        if not self.pipe:
            logger.error("NSFW detector is not available. Allowing image by default.")
            # Fail open: if the model isn't loaded, we can't check, so we allow it.
            # A stricter policy could be to return (False, "Moderation system offline").
            return (True, "Moderation system is currently offline.")

        try:
            # The pipeline can handle raw bytes, but opening with Pillow is more robust
            image = Image.open(image_bytes)
            results = self.pipe(image)
            
            # The model returns a list of dictionaries with 'label' and 'score'.
            # We are interested in the top result.
            if not results:
                return (True, "Could not determine content type.")

            top_result = results[0]
            label = top_result['label']
            score = top_result['score']
            
            logger.info(f"Image moderation check complete. Top result: {label} (Score: {score:.2f})")

            # Define the threshold for flagging content.
            # If the model is more than 85% confident it's NSFW, we block it.
            nsfw_threshold = 0.85
            if label == 'nsfw' and score > nsfw_threshold:
                return (False, f"Image flagged as '{label}' with high confidence ({score:.0%}).")
            
            return (True, "Image passed content moderation.")

        except Exception as e:
            logger.error(f"An error occurred during NSFW detection: {e}", exc_info=True)
            # Fail open in case of an unexpected error during processing.
            return (True, "Could not perform moderation check due to an error.")

