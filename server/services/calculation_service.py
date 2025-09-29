import re
from flask import current_app

def parse_time_string(time_str):
    h_match = re.search(r'(\d+)\s*h', time_str, re.IGNORECASE)
    h = int(h_match.group(1)) if h_match else 0
    m_match = re.search(r'(\d+)\s*m', time_str, re.IGNORECASE)
    m = int(m_match.group(1)) if m_match else 0
    s_match = re.search(r'(\d+)\s*s', time_str, re.IGNORECASE)
    s = int(s_match.group(1)) if s_match else 0
    return round(h + (m / 60.0) + (s / 3600.0), 4)

def calculate_printer_hourly_rate(printer_data):
    try:
        total_cost = printer_data['setup_cost'] + (printer_data['maintenance_cost'] * printer_data['lifetime_years'])
        total_hours = printer_data['lifetime_years'] * 365 * 24 * (printer_data.get('uptime_percent', 50) / 100)
        if total_hours == 0: return 0.0
        return (total_cost / total_hours) + ((printer_data['power_w'] / 1000) * printer_data['price_kwh'])
    except (KeyError, TypeError, ZeroDivisionError) as e:
        current_app.logger.warning(f"Could not calculate printer hourly rate: {e}")
        return 0.0

def calculate_cogs_values(form_data, printer_data, filament_data):
    try:
        filament_g = float(form_data.get("Filament (g)", 0))
        time_str = form_data.get("Time (e.g. 7h 30m)", "0h 0m")
        labour_time_min = float(form_data.get("Labour Time (min)", 0))
        labour_rate_user = float(form_data.get("Labour Rate (₹/hr)", 0))

        print_time_hours = parse_time_string(time_str)

        mat_cost = (filament_data.get('price', 0) / 1000) * filament_g * filament_data.get('efficiency_factor', 1.0)
        labour_cogs = (labour_rate_user / 60) * labour_time_min
        printer_cogs = calculate_printer_hourly_rate(printer_data) * printer_data.get('buffer_factor', 1.0) * print_time_hours
        total_cogs_user = mat_cost + labour_cogs + printer_cogs

        mat_cost_default = (filament_data.get('price', 0) / 1000) * filament_g
        labour_cogs_default = (100 / 60) * labour_time_min
        printer_cogs_default = calculate_printer_hourly_rate(printer_data) * print_time_hours
        total_cogs_default = mat_cost_default + labour_cogs_default + printer_cogs_default

        return {"user_cogs": total_cogs_user, "default_cogs": total_cogs_default}
    except (ValueError, TypeError, KeyError, ZeroDivisionError) as e:
        current_app.logger.warning(f"Could not calculate COGS values: {e}")
        return {"user_cogs": 0.0, "default_cogs": 0.0}