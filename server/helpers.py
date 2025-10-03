import os
from flask import current_app

def get_company_data_path(company_id, *args):
    """
    Constructs a path to a file or directory within a company's specific data folder.
    Creates the necessary directory structure if it doesn't exist.
    """
    # current_app.root_path will be the 'server' directory. The 'data' directory is at the root level.
    base_path = os.path.join(current_app.root_path, '..', 'data', str(company_id))
    full_path = os.path.abspath(os.path.join(base_path, *args))

    # Check if the path seems to be for a file or a directory
    if os.path.splitext(full_path)[1]:  # If there's a file extension
        # It's a file path, so create the parent directory
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
    else:
        # It's a directory path, so create the directory itself
        os.makedirs(full_path, exist_ok=True)

    return full_path

def get_safe_path(subpath):
    """
    Safely joins a subpath to the server's shared directory, preventing directory traversal attacks.
    """
    share_dir = os.path.abspath(current_app.config.get("APP_CONFIG", {}).get("SERVER_SHARE_DIR", "server_share"))
    # The share dir path should be relative to the root, not the server folder
    share_dir_abs = os.path.join(current_app.root_path, '..', share_dir)

    target_path = os.path.abspath(os.path.join(share_dir_abs, subpath))

    if not target_path.startswith(os.path.abspath(share_dir_abs)):
        return None
    return target_path