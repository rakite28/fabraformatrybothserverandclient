import os
import re
import subprocess
import sys
from werkzeug.utils import secure_filename
from flask import current_app

from helpers import get_company_data_path

def find_profile_path(company_id, profile_type, filename, config):
    safe_filename = secure_filename(filename)
    user_profile_dir = get_company_data_path(company_id, "slicer_profiles", profile_type)
    user_profile_path = os.path.join(user_profile_dir, safe_filename)
    if os.path.exists(user_profile_path):
        return user_profile_path

    system_profile_base = config.get("SLICER_SYSTEM_PROFILE_PATH")
    if not system_profile_base or not os.path.exists(system_profile_base):
        return None

    for root, _, files in os.walk(system_profile_base):
        if safe_filename in files:
            return os.path.join(root, safe_filename)

    return None

def parse_gcode_for_data(gcode_path):
    filament_grams = 0.0
    print_time_hours = 0.0
    with open(gcode_path, 'r', errors='ignore') as f: content = f.read()

    filament_match = re.search(r';\s*filament used \[g\]\s*=\s*([\d\.]+)', content)
    if filament_match: filament_grams = float(filament_match.group(1))

    time_match = re.search(r';\s*estimated printing time .*\s*=\s*(?:(\d+)h\s*)?(?:(\d+)m\s*)?(?:(\d+)s)?', content)
    if time_match:
        h = int(time_match.group(1) or 0)
        m = int(time_match.group(2) or 0)
        s = int(time_match.group(3) or 0)
        print_time_hours = h + (m / 60.0) + (s / 3600.0)

    return {"filament_grams": round(filament_grams, 2), "print_time_hours": round(print_time_hours, 4)}

def run_slicer(stl_path, machine_profile, filament_profile, process_profile, config):
    slicer_exe = config.get("SLICER_EXECUTABLE_PATH")
    if not slicer_exe or not os.path.exists(slicer_exe):
        return {"success": False, "error": "Slicer executable not configured or not found."}

    output_dir = os.path.dirname(stl_path)

    command = [
        slicer_exe, "--slice", stl_path,
        "--load", machine_profile,
        "--load", filament_profile,
        "--load", process_profile,
        "--output", output_dir
    ]
    try:
        current_app.logger.info(f"Running slicer command: {' '.join(command)}")
        creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
        result = subprocess.run(command, capture_output=True, text=True, check=True, creationflags=creation_flags)

        gcode_files = [f for f in os.listdir(output_dir) if f.endswith('.gcode')]
        if not gcode_files:
            current_app.logger.error(f"Slicing stdout: {result.stdout}\nSlicing stderr: {result.stderr}")
            return {"success": False, "error": "Slicing completed, but no G-code file was generated."}

        gcode_path = os.path.join(output_dir, gcode_files[0])
        parsed_data = parse_gcode_for_data(gcode_path)

        for f in os.listdir(output_dir):
            if f.endswith(('.gcode', '.3mf')):
                os.remove(os.path.join(output_dir, f))

        return {"success": True, "data": parsed_data}

    except subprocess.CalledProcessError as e:
        error_message = f"OrcaSlicer failed with exit code {e.returncode}:\n{e.stderr}"
        current_app.logger.error(error_message)
        user_friendly_error = "Slicing failed. The STL file may be invalid, or the object may be too large for the selected printer's build plate."
        return {"success": False, "error": user_friendly_error}
    except Exception as e:
        current_app.logger.error(f"An unexpected error occurred during slicing: {e}", exc_info=True)
        return {"success": False, "error": "An unexpected server error occurred during slicing."}