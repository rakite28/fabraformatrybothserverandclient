from flask import Blueprint, jsonify, request, g
from typing import List

from database import get_db_connection
from validators import PrinterModel
from decorators import validate_with, token_required

printers_bp = Blueprint('printers', __name__, url_prefix='/printers')

@printers_bp.route('', methods=['GET', 'POST'])
@token_required
def handle_printers():
    company_id = g.current_user['company_id']
    db = get_db_connection()

    if request.method == 'POST':
        @validate_with(List[PrinterModel])
        def handle_post():
            printers_data = g.validated_data
            try:
                cursor = db.cursor()
                cursor.execute("DELETE FROM printers WHERE company_id = ?", (company_id,))
                for p in printers_data:
                    cursor.execute("""
                        INSERT INTO printers (id, company_id, brand, model, setup_cost, maintenance_cost, lifetime_years, power_w, price_kwh, buffer_factor, uptime_percent)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (p.id, company_id, p.brand, p.model, p.setup_cost, p.maintenance_cost, p.lifetime_years, p.power_w, p.price_kwh, p.buffer_factor, p.uptime_percent))
                db.commit()
                return jsonify({"status": "saved"})
            except Exception as e:
                db.rollback()
                g.app.logger.error(f"Failed to save printers for company {company_id}: {e}")
                return jsonify({"status": "error", "message": "Failed to save printers."}), 500
        return handle_post()
    else: # GET
        printers_cur = db.execute("SELECT * FROM printers WHERE company_id = ?", (company_id,)).fetchall()
        return jsonify([dict(row) for row in printers_cur])