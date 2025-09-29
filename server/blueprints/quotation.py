from flask import Blueprint, jsonify, request, g, current_app, send_file
from werkzeug.utils import secure_filename
import os
import shutil
import uuid
from io import BytesIO
import re

from ..decorators import validate_with, token_required
from ..validators import SliceRequestModel, GenerateQuotationModel
from ..helpers import get_company_data_path
from ..services.slicer_service import run_slicer, find_profile_path
from ..services.pdf_service import generate_quotation_pdf

quotation_bp = Blueprint('quotation', __name__, url_prefix='/quotation')

@quotation_bp.route('/slice_model', methods=['POST'])
@token_required
def slice_model():
    company_id = g.current_user['company_id']
    if 'stl_file' not in request.files:
        return jsonify({"error": "Missing 'stl_file' in request"}), 400

    try:
        profiles = SliceRequestModel.parse_obj(request.form)
    except Exception as e:
        return jsonify({"error": f"Invalid form data: {e}"}), 400

    stl_file = request.files['stl_file']
    if not stl_file.filename.lower().endswith('.stl'):
        return jsonify({"error": "Invalid file type. Only .stl is supported."}), 400

    temp_dir = get_company_data_path(company_id, "temp_slice", str(uuid.uuid4()))
    os.makedirs(temp_dir, exist_ok=True)

    safe_stl_filename = secure_filename(stl_file.filename)
    stl_path = os.path.join(temp_dir, safe_stl_filename)
    stl_file.save(stl_path)

    slicer_config = current_app.config['APP_CONFIG']
    machine_profile_path = find_profile_path(company_id, "machine", profiles.machine_profile, slicer_config)
    filament_profile_path = find_profile_path(company_id, "filament", profiles.filament_profile, slicer_config)
    process_profile_path = find_profile_path(company_id, "process", profiles.process_profile, slicer_config)

    if not all([machine_profile_path, filament_profile_path, process_profile_path]):
        shutil.rmtree(temp_dir)
        missing = [
            p[0] for p in [
                ("machine", machine_profile_path), ("filament", filament_profile_path), ("process", process_profile_path)
            ] if not p[1]
        ]
        return jsonify({"error": f"Could not find the following profiles: {', '.join(missing)}"}), 404

    slicer_result = run_slicer(stl_path, machine_profile_path, filament_profile_path, process_profile_path, slicer_config)

    shutil.rmtree(temp_dir)

    if slicer_result["success"]:
        return jsonify(slicer_result["data"])
    else:
        return jsonify({"error": slicer_result["error"]}), 500

@quotation_bp.route('/generate', methods=['POST'])
@token_required
@validate_with(GenerateQuotationModel)
def generate_quotation_route():
    company_id = g.current_user['company_id']
    data = g.validated_data.dict()

    if data.get("company_details", {}).get("logo_path"):
        logo_filename = os.path.basename(data["company_details"]["logo_path"])
        safe_logo_path = get_company_data_path(company_id, "uploads", logo_filename)
        if os.path.exists(safe_logo_path):
            data["company_details"]["logo_path"] = safe_logo_path
        else:
            data["company_details"]["logo_path"] = None

    buffer = BytesIO()
    generate_quotation_pdf(buffer, data)
    buffer.seek(0)

    customer_name_safe = re.sub(r'[^a-zA-Z0-9_]', '', data['customer_name'].replace(' ', '_'))
    filename = f"Quotation_{customer_name_safe}_{uuid.uuid4().hex[:6]}.pdf"

    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype='application/pdf'
    )