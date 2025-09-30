import sys
import os

# Add the 'server' directory to the Python path
# This allows us to import modules from the 'server' package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'server')))

from app import create_app

if __name__ == '__main__':
    app = create_app()
    # Note: For production, use a proper WSGI server like Gunicorn or Waitress
    app.run(host='0.0.0.0', port=5000, debug=True)