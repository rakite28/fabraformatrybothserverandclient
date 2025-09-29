from functools import wraps
from flask import request, jsonify, g, current_app
import jwt
from pydantic import ValidationError, parse_obj_as
import json

def validate_with(model: any):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                if request.is_json:
                    json_data = request.get_json()
                elif request.form:
                    json_data = json.loads(request.form.get('json', '{}'))
                else:
                    return jsonify({"error": "Unsupported Media Type. Expected JSON or multipart/form-data."}), 415

                if isinstance(json_data, list):
                    g.validated_data = parse_obj_as(model, json_data)
                else:
                    g.validated_data = model.parse_obj(json_data)

                return f(*args, **kwargs)
            except ValidationError as e:
                # Let the global error handler catch this
                raise e
            except (json.JSONDecodeError, TypeError):
                return jsonify({"error": "Invalid JSON in request body or form data."}), 400
            except Exception as e:
                current_app.logger.error(f"Error parsing request: {e}", exc_info=True)
                return jsonify({"error": "Invalid request format."}), 400
        return decorated_function
    return decorator

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Malformed token header!'}), 401

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            g.current_user = {
                'user_id': data['user_id'],
                'username': data['username'],
                'company_id': data['company_id'],
                'role': data['role']
            }
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except Exception as e:
            current_app.logger.warning(f"Invalid token received: {e}")
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if g.current_user.get('role') != 'admin':
            return jsonify({'message': 'Admin privileges required!'}), 403
        return f(*args, **kwargs)
    return decorated