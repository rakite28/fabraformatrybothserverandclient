import os
import json
from flask import current_app

from ..helpers import get_company_data_path

def save_app_log(company_id, final_data, cogs_data, local_image_filename):
    """Saves a new entry to the company's JSON application log."""
    log_path = get_company_data_path(company_id, "app_logs.json")
    try:
        logs = []
        if os.path.exists(log_path):
            with open(log_path, 'r') as f:
                content = f.read()
                logs = json.loads(content) if content else []

        log_entry = {
            "timestamp": final_data["timestamp"],
            "filename": final_data["Filename"],
            "image_path": local_image_filename,
            "data": {
                "Printer": final_data["Printer"],
                "Material": final_data["Material"],
                "Brand": final_data["Brand"],
                "Filament (g)": final_data["Filament (g)"],
                "Time": final_data["Time (e.g. 7h 30m)"],
                "User COGS (₹)": f"{cogs_data['user_cogs']:.2f}",
                "Default COGS (₹)": f"{cogs_data['default_cogs']:.2f}"
            }
        }
        logs.append(log_entry)
        logs.sort(key=lambda x: x['timestamp'], reverse=True)

        with open(log_path, 'w') as f:
            json.dump(logs, f, indent=4)

    except Exception as e:
        current_app.logger.error(f"FAILED to save app log for company {company_id}: {e}")

def update_processed_log(company_id, original_filename):
    """Adds a filename to the log of processed files to prevent duplicates."""
    processed_log_path = get_company_data_path(company_id, "processed_log.json")
    try:
        processed_log = {}
        if os.path.exists(processed_log_path):
            with open(processed_log_path, 'r') as f:
                content = f.read()
                processed_log = json.loads(content) if content else {}

        processed_log[original_filename] = "completed"

        with open(processed_log_path, 'w') as f:
            json.dump(processed_log, f, indent=2)

    except Exception as e:
        current_app.logger.error(f"FAILED to update processed log for company {company_id}: {e}")