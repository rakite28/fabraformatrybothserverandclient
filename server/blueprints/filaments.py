from flask import Blueprint, jsonify, request, g
from typing import Dict

from database import get_db_connection
from validators import FilamentsPostModel
from decorators import validate_with, token_required

filaments_bp = Blueprint('filaments', __name__, url_prefix='/filaments')

@filaments_bp.route('', methods=['GET', 'POST'])
@token_required
def handle_filaments():
    company_id = g.current_user['company_id']
    db = get_db_connection()

    if request.method == 'POST':
        @validate_with(Dict[str, Dict[str, FilamentsPostModel]])
        def handle_post():
            data = g.validated_data
            try:
                cursor = db.cursor()
                cursor.execute("DELETE FROM filaments WHERE company_id = ?", (company_id,))
                for material, brands in data.items():
                    for brand, details in brands.items():
                        cursor.execute("INSERT INTO filaments (company_id, material, brand, price, stock_g, efficiency_factor) VALUES (?, ?, ?, ?, ?, ?)",
                                       (company_id, material, brand, details.price, details.stock_g, details.efficiency_factor))
                db.commit()
                return jsonify({"status": "saved"})
            except Exception as e:
                db.rollback()
                g.app.logger.error(f"Failed to save filaments for company {company_id}: {e}")
                return jsonify({"status": "error", "message": "Failed to save filaments."}), 500
        return handle_post()
    else: # GET
        filaments_cur = db.execute("SELECT * FROM filaments WHERE company_id = ?", (company_id,)).fetchall()
        filaments_dict = {}
        for row in filaments_cur:
            material = row['material']
            if material not in filaments_dict: filaments_dict[material] = {}
            filaments_dict[material][row['brand']] = {'price': row['price'], 'stock_g': row['stock_g'], 'efficiency_factor': row['efficiency_factor']}
        return jsonify(filaments_dict)