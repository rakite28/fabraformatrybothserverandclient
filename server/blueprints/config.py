from flask import Blueprint, jsonify, request, current_app
import json

from decorators import admin_required

config_bp = Blueprint('config', __name__, url_prefix='/server')

def load_app_config(app):
    """Loads the application configuration from the JSON file."""
    config_path = app.config['CONFIG_PATH']
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_app_config(app, data):
    """Saves the application configuration to the JSON file."""
    config_path = app.config['CONFIG_PATH']
    with open(config_path, 'w') as f:
        json.dump(data, f, indent=4)
    app.config['APP_CONFIG'] = data.copy()

@config_bp.route('/settings', methods=['GET', 'POST'])
@admin_required
def handle_server_settings():
    if request.method == 'POST':
        try:
            save_app_config(current_app, request.json)
            return jsonify({"status": "success", "message": "Settings saved."})
        except Exception as e:
            current_app.logger.error(f"Failed to save server settings: {e}")
            return jsonify({"status": "error", "message": "Failed to save settings."}), 500
    else:
        # The config loaded at startup is returned
        return jsonify(current_app.config.get('APP_CONFIG', {}))