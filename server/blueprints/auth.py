from flask import Blueprint, jsonify, request, g, current_app
from werkzeug.security import check_password_hash, generate_password_hash
import jwt
import secrets
from datetime import datetime, timedelta
import uuid

from ..database import get_db_connection
from ..validators import LoginModel, RegisterCompanyModel, RefreshTokenModel
from ..decorators import validate_with

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/companies', methods=['GET'])
def get_companies():
    db = get_db_connection()
    companies_cur = db.execute("SELECT id, name FROM companies ORDER BY name").fetchall()
    return jsonify([dict(row) for row in companies_cur])

@auth_bp.route('/login', methods=['POST'])
@validate_with(LoginModel)
def login():
    data = g.validated_data
    db = get_db_connection()
    user_row = db.execute(
        "SELECT * FROM users WHERE lower(email) = lower(?) OR lower(username) = lower(?)",
        (data.identifier, data.identifier)
    ).fetchone()

    if not user_row:
        return jsonify({'message': 'User not found'}), 401

    user = dict(user_row)
    if check_password_hash(user['password_hash'], data.password):
        access_token = jwt.encode({
            'user_id': user['id'], 'username': user['username'], 'company_id': user['company_id'],
            'role': user['role'], 'exp': datetime.utcnow() + timedelta(hours=24)
        }, current_app.config['SECRET_KEY'], algorithm="HS256")

        response_data = {'token': access_token}

        if data.remember_me:
            remember_token = secrets.token_hex(32)
            token_hash = generate_password_hash(remember_token)
            expires_at = datetime.utcnow() + timedelta(days=30)

            try:
                db.execute(
                    "INSERT INTO auth_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
                    (user['id'], token_hash, expires_at)
                )
                db.commit()
                response_data['remember_token'] = remember_token
            except Exception as e:
                db.rollback()
                current_app.logger.error(f"Could not save remember token for user {user['id']}: {e}")

        return jsonify(response_data)

    return jsonify({'message': 'Invalid credentials'}), 401

@auth_bp.route('/refresh', methods=['POST'])
@validate_with(RefreshTokenModel)
def refresh():
    data = g.validated_data
    db = get_db_connection()
    all_tokens = db.execute("SELECT user_id, token_hash, expires_at FROM auth_tokens").fetchall()
    user_id = None

    for row in all_tokens:
        if check_password_hash(row['token_hash'], data.remember_token):
            if datetime.utcnow() < datetime.fromisoformat(row['expires_at'].replace(' ', 'T')):
                user_id = row['user_id']
                break
            else: # Token is expired, delete it
                db.execute("DELETE FROM auth_tokens WHERE token_hash = ?", (row['token_hash'],))
                db.commit()
                return jsonify({'message': 'Remember token has expired'}), 401

    if not user_id:
        return jsonify({'message': 'Invalid or expired remember token'}), 401

    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return jsonify({'message': 'User associated with token not found'}), 404

    access_token = jwt.encode({
        'user_id': user['id'], 'username': user['username'], 'company_id': user['company_id'],
        'role': user['role'], 'exp': datetime.utcnow() + timedelta(hours=24)
    }, current_app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({'token': access_token})

@auth_bp.route('/logout', methods=['POST'])
def logout():
    # This endpoint now relies on the token_required decorator from the app, which will be added later
    data = request.json
    remember_token = data.get('remember_token')
    if remember_token:
        db = get_db_connection()
        all_tokens = db.execute("SELECT token_hash FROM auth_tokens WHERE user_id = ?", (g.current_user['user_id'],)).fetchall()
        for row in all_tokens:
            if check_password_hash(row['token_hash'], remember_token):
                db.execute("DELETE FROM auth_tokens WHERE token_hash = ?", (row['token_hash'],))
                db.commit()
                break
    return jsonify({'message': 'Logout successful'}), 200

@auth_bp.route('/register_company', methods=['POST'])
@validate_with(RegisterCompanyModel)
def register_company():
    data = g.validated_data
    db = get_db_connection()
    if db.execute("SELECT id FROM companies WHERE lower(name) = lower(?)", (data.company_name,)).fetchone():
        return jsonify({'message': 'A company with this name already exists'}), 409
    if db.execute("SELECT id FROM users WHERE lower(email) = lower(?)", (data.admin_email,)).fetchone():
        return jsonify({'message': 'This email is already registered'}), 409

    try:
        new_company_id = str(uuid.uuid4())
        password_hash = generate_password_hash(data.admin_password)
        cursor = db.cursor()
        cursor.execute("INSERT INTO companies (id, name) VALUES (?, ?)", (new_company_id, data.company_name))
        cursor.execute("INSERT INTO users (id, username, email, password_hash, company_id, role) VALUES (?, ?, ?, ?, ?, ?)",
                         (str(uuid.uuid4()), data.admin_username, data.admin_email, password_hash, new_company_id, 'admin'))
        db.commit()
    except Exception as e:
        db.rollback()
        current_app.logger.error(f"Company registration failed: {e}")
        return jsonify({'message': 'An error occurred during registration.'}), 500

    return jsonify({'message': f"Company '{data.company_name}' created successfully."}), 201