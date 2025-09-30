from flask import Blueprint, jsonify, request, g, current_app, send_from_directory
from werkzeug.utils import secure_filename
import os

from decorators import admin_required, token_required
from helpers import get_safe_path, get_company_data_path

files_bp = Blueprint('files', __name__)

# --- Server Admin File Management ---

@files_bp.route('/server/files/', defaults={'subpath': ''})
@files_bp.route('/server/files/<path:subpath>')
@admin_required
def list_files(subpath):
    safe_path = get_safe_path(subpath)
    if not safe_path or not os.path.isdir(safe_path):
        return jsonify({"error": "Invalid path"}), 404
    try:
        file_list = []
        for item in os.listdir(safe_path):
            item_path = os.path.join(safe_path, item)
            is_dir = os.path.isdir(item_path)
            file_list.append({
                "name": item,
                "type": "dir" if is_dir else "file",
                "size": os.path.getsize(item_path) if not is_dir else 0
            })
        return jsonify(file_list)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@files_bp.route('/server/upload/', defaults={'subpath': ''}, methods=['POST'])
@files_bp.route('/server/upload/<path:subpath>', methods=['POST'])
@admin_required
def upload_file(subpath):
    safe_path = get_safe_path(subpath)
    if not safe_path or not os.path.isdir(safe_path):
        return jsonify({"error": "Invalid destination"}), 400
    if 'file' not in request.files or not request.files['file'].filename:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    filename = secure_filename(file.filename)
    file.save(os.path.join(safe_path, filename))
    return jsonify({"status": "success", "message": f"File '{filename}' uploaded."})

@files_bp.route('/server/download/<path:filepath>')
@admin_required
def download_server_file(filepath):
    safe_path = get_safe_path(filepath)
    if not safe_path or not os.path.isfile(safe_path):
        return jsonify({"error": "File not found"}), 404
    return send_from_directory(os.path.dirname(safe_path), os.path.basename(safe_path), as_attachment=True)

# --- Company-Specific File Serving ---

@files_bp.route('/logs', methods=['GET'])
@token_required
def get_logs():
    log_path = get_company_data_path(g.current_user['company_id'], "app_logs.json")
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            return jsonify(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        return jsonify([])

@files_bp.route('/processed_log', methods=['GET'])
@token_required
def get_processed_log():
    log_path = get_company_data_path(g.current_user['company_id'], "processed_log.json")
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            return jsonify(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        return jsonify({})

@files_bp.route('/images/<path:filename>')
@token_required
def serve_image(filename):
    image_dir = get_company_data_path(g.current_user['company_id'], "local_log_images")
    return send_from_directory(image_dir, filename)

@files_bp.route('/download/log/<path:filename>')
@token_required
def download_log_file(filename):
    excel_dir = get_company_data_path(g.current_user['company_id'], "Excel_Logs")
    return send_from_directory(os.path.abspath(excel_dir), filename, as_attachment=True)

@files_bp.route('/download/masterlog/<year_month>')
@token_required
def download_master_log_file(year_month):
    try:
        year, month = year_month.split('_')
        filename = f"master_log_{month}.xlsx"
        directory = get_company_data_path(g.current_user['company_id'], "Monthly_Expenditure", year_month)
        return send_from_directory(os.path.abspath(directory), filename, as_attachment=True)
    except ValueError:
        return jsonify({"error": "Invalid year_month format. Expected 'YYYY_Monthname'."}), 400
    except FileNotFoundError:
        return jsonify({"error": "Master log for the specified period not found."}), 404