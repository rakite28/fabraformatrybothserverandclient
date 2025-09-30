import re
from flask import g, current_app
import easyocr

ocr_reader = None

def get_ocr_reader():
    """Initializes and returns the EasyOCR reader instance."""
    global ocr_reader
    if ocr_reader is None:
        current_app.logger.info("⏳ Loading EasyOCR model into memory...")
        try:
            ocr_reader = easyocr.Reader(['en'], gpu=True)
            current_app.logger.info("✅ EasyOCR model loaded with GPU.")
        except Exception as e:
            current_app.logger.warning(f"Could not load EasyOCR model with GPU, trying CPU. Error: {e}")
            try:
                ocr_reader = easyocr.Reader(['en'], gpu=False)
                current_app.logger.info("✅ EasyOCR model loaded with CPU.")
            except Exception as e2:
                current_app.logger.critical(f"🛑 FATAL: Could not load EasyOCR model on CPU. OCR will not be available. Error: {e2}")
                ocr_reader = None
    return ocr_reader

def extract_data_from_ocr(company_id, ocr_results):
    """
    Parses the raw text from OCR to extract structured data about the print job.
    """
    full_text = " ".join([item[1] for item in ocr_results]).lower()
    extracted_data = {
        "filament": 0.0,
        "time_str": "0h 0m",
        "material": None,
        "detected_printer_id": None
    }

    # --- Extract Filament Usage ---
    filament_g = 0.0
    priority_match = re.search(r'total filament\D*(\d+\.?\d*)\s*g', full_text)
    if priority_match:
        filament_g = round(float(priority_match.group(1)), 2)
    else:
        all_g_matches = re.findall(r'(\d+\.?\d*)\s*g', full_text)
        if all_g_matches:
            try:
                numeric_values = [float(val) for val in all_g_matches]
                if numeric_values:
                    filament_g = round(max(numeric_values), 2)
            except (ValueError, TypeError):
                filament_g = 0.0
    extracted_data["filament"] = filament_g

    # --- Extract Print Time ---
    hours, minutes = 0, 0
    time_block_match = re.search(r'(?:total time|print time)\D*(?:(\d+)\s*h)?\s*(?:(\d+)\s*m)?', full_text)
    if time_block_match:
        h_val, m_val = time_block_match.groups()
        if h_val: hours = int(h_val)
        if m_val: minutes = int(m_val)
    if hours == 0 and minutes == 0:
        h_values = [int(h) for h in re.findall(r'(\d+)\s*h', full_text)]
        m_values = [int(m) for m in re.findall(r'(\d+)\s*m', full_text)]
        if h_values: hours = max(h_values)
        if m_values: minutes = max(m_values)
    if hours > 0 or minutes > 0:
        extracted_data["time_str"] = f"{hours}h {minutes}m"

    # --- Detect Material and Printer from Database ---
    db = g.db

    filaments_cur = db.execute("SELECT DISTINCT material FROM filaments WHERE company_id = ?", (company_id,)).fetchall()
    known_materials = [row['material'].lower() for row in filaments_cur]
    for material in known_materials:
        if re.search(r'\b' + re.escape(material) + r'\b', full_text):
            extracted_data["material"] = material.upper()
            break

    printers_cur = db.execute("SELECT id, brand, model FROM printers WHERE company_id = ?", (company_id,)).fetchall()
    for printer in printers_cur:
        if printer['brand'].lower() in full_text or printer['model'].lower() in full_text:
            extracted_data["detected_printer_id"] = printer['id']
            break

    return extracted_data