import os
import json
import logging
from logging.handlers import RotatingFileHandler
import secrets
import threading

from flask import Flask, jsonify, g, request
from flask_cors import CORS
from pydantic import ValidationError

from database import init_db, get_db_connection
from helpers import get_company_data_path
from services.ocr_service import get_ocr_reader
from moderator import get_nsfw_detector

# --- Blueprint Imports ---
from blueprints.auth import auth_bp
from blueprints.users import users_bp
from blueprints.printers import printers_bp
from blueprints.filaments import filaments_bp
from blueprints.quotation import quotation_bp
from blueprints.processing import processing_bp
from blueprints.files import files_bp
from blueprints.config import config_bp, load_app_config, save_app_config

def create_app():
    """Application factory for the Flask app."""
    app = Flask(__name__)
    CORS(app)

    # --- Initial Setup ---
    # SCRIPT_DIR is the 'server' directory.
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

    # All paths should be absolute or relative to the app's instance folder,
    # not dependent on the current working directory.
    CONFIG_PATH = os.path.join(SCRIPT_DIR, "server_config.json")
    app.config['CONFIG_PATH'] = CONFIG_PATH

    # --- Centralized Logging Setup ---
    setup_logging(app)

    # --- Load Configuration ---
    APP_CONFIG = load_app_config(app)
    defaults = {
        "SERVER_SHARE_DIR": "server_share",
        "TEMPLATE_PATH": "FDM.xlsx",
        "SLICER_EXECUTABLE_PATH": r"C:\Program Files\OrcaSlicer\orca-slicer.exe",
        "SLICER_SYSTEM_PROFILE_PATH": r"C:\Users\YourUser\AppData\Roaming\OrcaSlicer\user",
        "cells": ["D4", "D9", "D10", "D11", "D12", "D13"],
        "headers": ["Sr. No", "Date", "Part Number", "Filename", "Material", "Filament Cost (₹/kg)", "Filament (g)", "Time (h)", "Labour Time (min)", "User COGS (₹)", "Default COGS (₹)", "Source Link"]
    }
    app.config['SECRET_KEY'] = APP_CONFIG.get('SECRET_KEY', secrets.token_hex(32))

    config_updated = False
    for key, value in defaults.items():
        if key not in APP_CONFIG:
            APP_CONFIG[key] = value
            config_updated = True

    # Make the template path absolute to avoid ambiguity
    if not os.path.isabs(APP_CONFIG.get("TEMPLATE_PATH", "")):
        # The path is relative to the server directory, where app.py is
        APP_CONFIG['TEMPLATE_PATH'] = os.path.join(SCRIPT_DIR, APP_CONFIG['TEMPLATE_PATH'])
        config_updated = True

    if config_updated or 'SECRET_KEY' not in APP_CONFIG:
        APP_CONFIG['SECRET_KEY'] = app.config['SECRET_KEY']
        save_app_config(app, APP_CONFIG)

    # Store the final, potentially updated, config in the app context
    app.config['APP_CONFIG'] = APP_CONFIG.copy()

    # Create necessary directories
    # The share dir is at the root level, so we go up one level from the script dir
    os.makedirs(os.path.join(SCRIPT_DIR, '..', APP_CONFIG["SERVER_SHARE_DIR"]), exist_ok=True)

    # --- Database Initialization ---
    with app.app_context():
        # The database file will be created in the root directory
        init_db()

    # --- Register Blueprints ---
    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(printers_bp)
    app.register_blueprint(filaments_bp)
    app.register_blueprint(quotation_bp)
    app.register_blueprint(processing_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(config_bp)

    # --- Global Error Handlers ---
    @app.errorhandler(Exception)
    def handle_unexpected_error(e):
        app.logger.error(f"An unhandled exception occurred: {e}", exc_info=True)
        return jsonify({
            "error": "An unexpected server error occurred.",
            "message": "The issue has been logged for investigation."
        }), 500

    @app.errorhandler(ValidationError)
    def handle_validation_error(e):
        app.logger.warning(f"Validation error for request on '{request.path}': {e.errors()}")
        error_details = {err['loc'][0]: err['msg'] for err in e.errors()}
        return jsonify({
            "error": "Input validation failed",
            "message": "One or more fields are invalid.",
            "details": error_details
        }), 400

    # --- Request Lifecycle ---
    @app.before_request
    def before_request():
        g.db = get_db_connection()

    @app.teardown_request
    def teardown_request(exception):
        db = g.pop('db', None)
        if db is not None:
            db.close()

    # --- Pre-load Models ---
    # Load models in a background thread to not block the app startup
    model_loader_thread = threading.Thread(target=load_models_in_background, args=(app,))
    model_loader_thread.daemon = True  # Allows app to exit even if thread is running
    model_loader_thread.start()

    return app

def load_models_in_background(app):
    """
    Loads the OCR and NSFW models in a background thread
    to avoid blocking the server startup.
    """
    with app.app_context():
        get_ocr_reader()
        get_nsfw_detector()

def setup_logging(app):
    """Configures logging for the application."""
    # Log directory is at the root level
    log_dir = os.path.join(app.root_path, '..', 'logs')
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, 'server.log')

    handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024 * 5, backupCount=5)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s [in %(pathname)s:%(lineno)d]')
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    if not root_logger.handlers:
        root_logger.addHandler(handler)
        root_logger.setLevel(logging.INFO)

    app.logger.handlers = []
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info("Application starting up...")
