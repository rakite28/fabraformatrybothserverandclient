import os
import json
from tkinter import messagebox
import requests
import jwt
from jwt import PyJWTError

# --- [CONFIG] SERVER CONFIGURATION ---
SERVER_URL = "http://localhost:5000" # Updated to localhost for development
# ------------------------------------

class APIClient:
    """Handles all communication with the Flask server with JWT authentication."""
    def __init__(self):
        self.token = None
        self.user_info = {}

    def _get_auth_header(self):
        if not self.token:
            print("Auth Error: No authentication token found.")
            return None
        return {'Authorization': f'Bearer {self.token}'}

    def _handle_error(self, error, response=None):
        title = "API Error"
        message = str(error)
        if response is not None:
            if response.status_code in [401, 403]:
                message = "Your session has expired or you lack permissions. Please log in again."
            else:
                try:
                    server_error = response.json()
                    if 'details' in server_error and isinstance(server_error['details'], dict):
                        formatted_details = "\n".join([f"- {key.replace('_', ' ').title()}: {val}" for key, val in server_error['details'].items()])
                        message = f"{server_error.get('message', 'Validation Error')}\n\n{formatted_details}"
                    elif 'message' in server_error:
                        message = server_error['message']
                    elif 'error' in server_error:
                        message = server_error['error']
                except (json.JSONDecodeError, AttributeError):
                    message = response.text
        print(f"API Error: {message}")
        messagebox.showerror(title, f"An error occurred:\n\n{message}")

    def login(self, identifier, password, remember_me=False):
        try:
            payload = {'identifier': identifier, 'password': password, 'remember_me': remember_me}
            response = requests.post(f"{SERVER_URL}/auth/login", json=payload)
            response.raise_for_status()
            data = response.json()
            if data and 'token' in data:
                self.token = data['token']
                try:
                    self.user_info = jwt.decode(self.token, options={"verify_signature": False})
                except PyJWTError as e:
                    messagebox.showerror("Token Error", f"Could not decode user info: {e}")
                    self.logout()
                    return None
                return data
            return None
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return None

    def refresh_token(self, remember_token):
        try:
            payload = {'remember_token': remember_token}
            response = requests.post(f"{SERVER_URL}/auth/refresh", json=payload)
            response.raise_for_status()
            data = response.json()
            if data and 'token' in data:
                self.token = data['token']
                try:
                    self.user_info = jwt.decode(self.token, options={"verify_signature": False})
                except PyJWTError as e:
                    messagebox.showerror("Token Error", f"Could not decode user info: {e}")
                    self.logout()
                    return False
                return True
            return False
        except requests.exceptions.RequestException:
            return False

    def logout(self, remember_token=None):
        headers = self._get_auth_header()
        if headers and remember_token:
            try:
                requests.post(f"{SERVER_URL}/auth/logout", json={'remember_token': remember_token}, headers=headers)
            except requests.exceptions.RequestException:
                pass
        self.token = None
        self.user_info = {}

    def register_company(self, company_name, admin_username, admin_email, admin_password):
        try:
            payload = {'company_name': company_name, 'admin_username': admin_username, 'admin_email': admin_email, 'admin_password': admin_password}
            response = requests.post(f"{SERVER_URL}/auth/register_company", json=payload)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return None

    def create_user(self, username, email, password, role):
        headers = self._get_auth_header()
        if not headers: return None
        try:
            payload = {'username': username, 'email': email, 'password': password, 'role': role}
            response = requests.post(f"{SERVER_URL}/user/create_user", json=payload, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return None

    def get_profile(self):
        headers = self._get_auth_header()
        if not headers: return None
        try:
            response = requests.get(f"{SERVER_URL}/user/profile", headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return None

    def update_profile(self, profile_data):
        headers = self._get_auth_header()
        if not headers: return None
        try:
            response = requests.post(f"{SERVER_URL}/user/profile", json=profile_data, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return None

    def change_password(self, current_password, new_password):
        headers = self._get_auth_header()
        if not headers: return None
        try:
            payload = {'current_password': current_password, 'new_password': new_password}
            response = requests.post(f"{SERVER_URL}/user/change_password", json=payload, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return None

    def upload_profile_picture(self, file_path):
        headers = self._get_auth_header()
        if not headers: return None
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                response = requests.post(f"{SERVER_URL}/user/profile_picture", files=files, headers=headers)
                response.raise_for_status()
                return response.json()
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return None
        except FileNotFoundError:
            messagebox.showerror("File Error", f"File not found: {file_path}")
            return None

    def get_server_settings(self):
        headers = self._get_auth_header()
        if not headers: return {}
        try:
            response = requests.get(f"{SERVER_URL}/server/settings", headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return {}

    def save_server_settings(self, data):
        headers = self._get_auth_header()
        if not headers: return None
        try:
            response = requests.post(f"{SERVER_URL}/server/settings", json=data, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return None

    def list_server_files(self, path):
        headers = self._get_auth_header()
        if not headers: return []
        try:
            response = requests.get(f"{SERVER_URL}/server/files/{path}", headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return []

    def upload_file_to_server(self, local_path, server_subpath):
        headers = self._get_auth_header()
        if not headers: return None
        try:
            with open(local_path, 'rb') as f:
                files = {'file': (os.path.basename(local_path), f)}
                response = requests.post(f"{SERVER_URL}/server/upload/{server_subpath}", files=files, headers=headers)
                response.raise_for_status()
                return response.json()
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return None
        except FileNotFoundError:
            messagebox.showerror("File Error", f"File not found: {local_path}")
            return None

    def download_server_file(self, server_filepath, local_save_path):
        headers = self._get_auth_header()
        if not headers: return False
        try:
            with requests.get(f"{SERVER_URL}/server/download/{server_filepath}", stream=True, headers=headers) as r:
                r.raise_for_status()
                with open(local_save_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192): f.write(chunk)
            return True
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return False

    def get_printers(self):
        headers = self._get_auth_header()
        if not headers: return []
        try:
            response = requests.get(f"{SERVER_URL}/printers", headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return []

    def save_printers(self, data):
        headers = self._get_auth_header()
        if not headers: return False
        try:
            response = requests.post(f"{SERVER_URL}/printers", json=data, headers=headers)
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return False

    def get_filaments(self):
        headers = self._get_auth_header()
        if not headers: return {}
        try:
            response = requests.get(f"{SERVER_URL}/filaments", headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return {}

    def save_filaments(self, data):
        headers = self._get_auth_header()
        if not headers: return False
        try:
            response = requests.post(f"{SERVER_URL}/filaments", json=data, headers=headers)
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return False

    def get_logs(self):
        headers = self._get_auth_header()
        if not headers: return []
        try:
            response = requests.get(f"{SERVER_URL}/logs", headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return []

    def get_processed_log(self):
        headers = self._get_auth_header()
        if not headers: return {}
        try:
            response = requests.get(f"{SERVER_URL}/processed_log", headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Could not fetch processed log: {e}")
            return {}

    def process_image(self, file_path, verification_data):
        headers = self._get_auth_header()
        if not headers: return {"status": "error"}
        try:
            with open(file_path, 'rb') as f:
                files = {'image': (os.path.basename(file_path), f)}
                data = {'json': json.dumps(verification_data)}
                response = requests.post(f"{SERVER_URL}/process_image", files=files, data=data, headers=headers)
                response.raise_for_status()
                return response.json()
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return {"status": "error", "message": "Network error"}
        except FileNotFoundError:
            return {"status": "error", "message": f"File not found: {file_path}"}

    def generate_quotation(self, data, save_path):
        headers = self._get_auth_header()
        if not headers: return False
        try:
            logo_path = data.get("company_details", {}).get("logo_path")
            files = {'logo': (os.path.basename(logo_path), open(logo_path, 'rb'))} if logo_path and os.path.exists(logo_path) else None
            payload = {'json': json.dumps(data)}

            with requests.post(f"{SERVER_URL}/generate_quotation", data=payload, files=files, headers=headers, stream=True) as r:
                r.raise_for_status()
                with open(save_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
            return True
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return False
        except FileNotFoundError as e:
            messagebox.showerror("File Error", f"Logo file not found: {e}")
            return False

    def upload_for_ocr(self, file_path):
        headers = self._get_auth_header()
        if not headers: return {}
        try:
            with open(file_path, 'rb') as f:
                files = {'image': (os.path.basename(file_path), f)}
                response = requests.post(f"{SERVER_URL}/ocr_upload", files=files, headers=headers)
                response.raise_for_status()
                return response.json()
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return {}
        except FileNotFoundError:
            messagebox.showerror("File Error", f"File not found: {file_path}")
            return {}

    def download_file(self, endpoint, save_path):
        headers = self._get_auth_header()
        if not headers: return False
        try:
            with requests.get(f"{SERVER_URL}/{endpoint}", stream=True, headers=headers) as r:
                r.raise_for_status()
                with open(save_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
            return True
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return False

    def get_slicer_profiles(self):
        headers = self._get_auth_header()
        if not headers: return None
        try:
            response = requests.get(f"{SERVER_URL}/slicer/profiles", headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return None

    def upload_slicer_profile(self, profile_type, file_path):
        headers = self._get_auth_header()
        if not headers: return None
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f, 'application/json')}
                response = requests.post(f"{SERVER_URL}/slicer/profiles/{profile_type}", files=files, headers=headers)
                response.raise_for_status()
                return response.json()
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return None
        except FileNotFoundError:
            messagebox.showerror("File Error", f"File not found: {file_path}")
            return None

    def delete_slicer_profile(self, profile_type, filename):
        headers = self._get_auth_header()
        if not headers: return None
        try:
            response = requests.delete(f"{SERVER_URL}/slicer/profiles/{profile_type}/{filename}", headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return None

    def slice_and_calculate(self, stl_file_path, machine_profile, filament_profile, process_profile):
        headers = self._get_auth_header()
        if not headers: return None

        json_data = json.dumps({
            "machine_profile": machine_profile,
            "filament_profile": filament_profile,
            "process_profile": process_profile
        })

        try:
            with open(stl_file_path, 'rb') as f:
                files = {'stl_file': (os.path.basename(stl_file_path), f, 'application/octet-stream')}
                data = {'json_data': json_data}
                response = requests.post(f"{SERVER_URL}/quote/slice-and-calculate", files=files, data=data, headers=headers)
                response.raise_for_status()
                return response.json()
        except requests.exceptions.RequestException as e:
            self._handle_error(e, e.response)
            return None
        except FileNotFoundError:
            messagebox.showerror("File Error", f"STL file not found: {stl_file_path}")
            return None