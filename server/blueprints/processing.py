from flask import Blueprint, jsonify, request, g, current_app
import os

from database import get_db_connection
from decorators import token_required, validate_with
from validators import ProcessImageModel
from helpers import get_company_data_path
from moderator import NSFWDetector
from services.ocr_service import get_ocr_reader, extract_data_from_ocr
from services.calculation_service import calculate_cogs_values
from services.excel_service import create_excel_file, log_to_master_excel
from services.log_service import save_app_log, update_processed_log

processing_bp = Blueprint('processing', __name__)

def update_filament_stock(company_id, final_data):
    """Decrements the stock for a given filament after a print job."""
    try:
        db = get_db_connection()
        material, brand = final_data.get("Material"), final_data.get("Brand")
        grams_used = float(final_data.get("Filament (g)", 0))
        if not all([material, brand, grams_used > 0]):
            return
        db.execute("UPDATE filaments SET stock_g = stock_g - ? WHERE company_id = ? AND material = ? AND brand = ?",
                   (grams_used, company_id, material, brand))
        db.commit()
    except Exception as e:
        db.rollback()
        current_app.logger.error(f"Error updating stock for company {company_id}: {e}")

@processing_bp.route('/ocr_upload', methods=['POST'])
@token_required
def ocr_upload():
    if 'image' not in request.files:
        return jsonify({"error": "No image file provided"}), 400

    image_file = request.files['image']
    image_bytes = image_file.read()
    image_file.seek(0)

    detector = NSFWDetector()
    is_safe, reason = detector.is_image_safe(image_bytes)
    if not is_safe:
        current_app.logger.warning(f"User {g.current_user['user_id']} tried to upload NSFW image for OCR. Reason: {reason}")
        return jsonify({'error': 'Image was flagged as inappropriate and was rejected.'}), 400

    reader = get_ocr_reader()
    if not reader:
        return jsonify({"error": "OCR model not available."}), 503

    ocr_results = reader.readtext(image_bytes)
    return jsonify(extract_data_from_ocr(g.current_user['company_id'], ocr_results))

@processing_bp.route('/process_image', methods=['POST'])
@token_required
@validate_with(ProcessImageModel)
def process_image_upload():
    company_id = g.current_user['company_id']
    final_data = g.validated_data.dict(by_alias=True)
    db = get_db_connection()

    if 'image' not in request.files:
        return jsonify({"error": "Missing image file"}), 400
    image_file = request.files['image']

    image_bytes = image_file.read()
    image_file.seek(0)
    detector = NSFWDetector()
    is_safe, reason = detector.is_image_safe(image_bytes)
    if not is_safe:
        current_app.logger.warning(f"User {g.current_user['user_id']} tried to process NSFW image. Reason: {reason}")
        return jsonify({'error': 'Image was flagged as inappropriate and was rejected.'}), 400

    # Step 1: Save the uploaded image
    image_dir = get_company_data_path(company_id, "local_log_images")
    new_filename = final_data["Filename"] + os.path.splitext(image_file.filename)[1]
    image_file.save(os.path.join(image_dir, new_filename))

    # Step 2: Validate Printer and Filament data from the database
    printer_row = db.execute("SELECT * FROM printers WHERE id=? AND company_id=?", (final_data.get("printer_id"), company_id)).fetchone()
    filament_row = db.execute("SELECT * FROM filaments WHERE material=? AND brand=? AND company_id=?", (final_data.get("Material"), final_data.get("Brand"), company_id)).fetchone()

    if not printer_row or not filament_row:
        return jsonify({"status": "error", "message": "Critical data missing: Printer or filament not found in the database."}), 400

    printer, filament = dict(printer_row), dict(filament_row)

    # Step 3: Perform Calculations
    cogs = calculate_cogs_values(final_data, printer, filament)

    # Step 4: Create Individual Excel Log
    config = current_app.config['APP_CONFIG']
    excel_path, excel_msg = create_excel_file(company_id, final_data, printer, filament, config)
    if not excel_path:
        return jsonify({"status": "error", "message": f"Failed to create Excel log: {excel_msg}"}), 500

    # Step 5: Update Master Log
    success, msg = log_to_master_excel(company_id, excel_path, final_data, cogs['user_cogs'], cogs['default_cogs'], config)
    if not success:
        return jsonify({"status": "error", "message": f"Failed to update master log: {msg}"}), 500

    # Step 6: Finalize and commit changes
    update_filament_stock(company_id, final_data)
    save_app_log(company_id, final_data, cogs, new_filename)
    update_processed_log(company_id, os.path.basename(image_file.filename))

    return jsonify({"status": "success", "message": "File processed and logged successfully."})