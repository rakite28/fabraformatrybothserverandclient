from flask import Blueprint, jsonify, request, g, current_app, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import uuid
import time
import os

from ..database import get_db_connection
from ..validators import CreateUserModel, ChangePasswordModel, UpdateProfileModel
from ..decorators import validate_with, token_required, admin_required
from ..helpers import get_company_data_path
from ..moderator import NSFWDetector

users_bp = Blueprint('users', __name__, url_prefix='/user')

@users_bp.route('/profile', methods=['GET', 'POST'])
@token_required
def user_profile():
    user_id = g.current_user['user_id']
    db = get_db_connection()

    if request.method == 'GET':
        user_row = db.execute(
            "SELECT username, email, phone_number, dob, profile_picture_path FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if not user_row:
            return jsonify({'message': 'User not found'}), 404

        profile_data = dict(user_row)
        if profile_data.get('profile_picture_path'):
            profile_data['profile_picture_url'] = f"{request.url_root.rstrip('/')}/user/profile_picture/{profile_data['profile_picture_path']}"
        return jsonify(profile_data)

    if request.method == 'POST':
        @validate_with(UpdateProfileModel)
        def handle_post():
            data = g.validated_data
            update_fields = data.dict(exclude_unset=True)

            if not update_fields:
                return jsonify({'message': 'No update information provided'}), 400

            set_clause = ", ".join([f"{key} = ?" for key in update_fields.keys()])
            params = list(update_fields.values()) + [user_id]

            try:
                db.execute(f"UPDATE users SET {set_clause} WHERE id = ?", tuple(params))
                db.commit()
                return jsonify({'message': 'Profile updated successfully'})
            except Exception as e:
                db.rollback()
                current_app.logger.error(f"Profile update failed for user {user_id}: {e}")
                return jsonify({'message': 'Failed to update profile.'}), 500
        return handle_post()

@users_bp.route('/change_password', methods=['POST'])
@token_required
@validate_with(ChangePasswordModel)
def change_password():
    data = g.validated_data
    user_id = g.current_user['user_id']
    db = get_db_connection()

    user = db.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    if not check_password_hash(user['password_hash'], data.current_password):
        return jsonify({'message': 'Current password is not correct'}), 403

    new_password_hash = generate_password_hash(data.new_password)
    try:
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_password_hash, user_id))
        db.commit()
        return jsonify({'message': 'Password updated successfully'})
    except Exception as e:
        db.rollback()
        current_app.logger.error(f"Password change failed for user {user_id}: {e}")
        return jsonify({'message': 'Failed to update password.'}), 500

@users_bp.route('/profile_picture', methods=['POST'])
@token_required
def upload_profile_picture():
    user_id = g.current_user['user_id']
    company_id = g.current_user['company_id']
    db = get_db_connection()

    if 'file' not in request.files or not request.files['file'].filename:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']

    detector = NSFWDetector()
    file_bytes = file.read()
    file.seek(0)
    is_safe, reason = detector.is_image_safe(file_bytes)
    if not is_safe:
        current_app.logger.warning(f"User {user_id} tried to upload NSFW profile picture. Reason: {reason}")
        return jsonify({'error': 'Image was flagged as inappropriate and was rejected.'}), 400

    filename = secure_filename(f"{user_id}_{int(time.time())}{os.path.splitext(file.filename)[1]}")
    upload_folder = get_company_data_path(company_id, "profile_pictures")
    file_path = os.path.join(upload_folder, filename)
    file.save(file_path)

    try:
        db.execute("UPDATE users SET profile_picture_path = ? WHERE id = ?", (filename, user_id))
        db.commit()
        new_url = f"{request.url_root.rstrip('/')}/user/profile_picture/{filename}"
        return jsonify({'message': 'Profile picture updated', 'filepath': filename, 'url': new_url})
    except Exception as e:
        db.rollback()
        current_app.logger.error(f"Failed to update profile picture path in DB for user {user_id}: {e}")
        return jsonify({'message': 'Failed to update database.'}), 500

@users_bp.route('/profile_picture/<path:filename>')
@token_required
def serve_profile_picture(filename):
    company_id = g.current_user['company_id']
    directory = get_company_data_path(company_id, "profile_pictures")
    return send_from_directory(directory, filename)

@users_bp.route('/create_user', methods=['POST'])
@admin_required
@validate_with(CreateUserModel)
def create_user():
    data = g.validated_data
    company_id = g.current_user['company_id']
    db = get_db_connection()
    if db.execute("SELECT id FROM users WHERE lower(email) = lower(?)", (data.email,)).fetchone():
        return jsonify({'message': 'This email is already registered'}), 409
    if db.execute("SELECT id FROM users WHERE lower(username) = lower(?) AND company_id = ?", (data.username, company_id)).fetchone():
        return jsonify({'message': 'This username already exists in your company'}), 409

    try:
        password_hash = generate_password_hash(data.password)
        db.execute("INSERT INTO users (id, username, email, password_hash, company_id, role) VALUES (?, ?, ?, ?, ?, ?)",
                       (str(uuid.uuid4()), data.username, data.email, password_hash, company_id, data.role))
        db.commit()
    except Exception as e:
        db.rollback()
        current_app.logger.error(f"User creation failed for company {company_id}: {e}")
        return jsonify({'message': 'Failed to create user.'}), 500

    return jsonify({'message': f"User '{data.username}' created successfully."}), 201