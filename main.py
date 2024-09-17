from flask import Flask, request, jsonify
import subprocess
import shlex

app = Flask(__name__)

# Define the API key
API_KEY = 'randomc2'

# Middleware to check for API key
@app.before_request
def check_api_key():
    # Define routes that don't require API key
    exempt_routes = {'/'}

    # Get the request path
    path = request.path

    if path not in exempt_routes:
        # Get the API key from headers
        api_key = request.headers.get('Authorization')
        if api_key != API_KEY:
            return jsonify({'error': 'Unauthorized'}), 401

@app.route('/', methods=['GET'])
def home():
    return "API server is running. Use POST /execute to run commands."

@app.route('/execute', methods=['POST'])
def execute_command():
    # Get the command from the JSON request body
    data = request.json
    command = data.get('command')

    if not command:
        return jsonify({'error': 'No command provided'}), 400

    try:
        # Use shlex to safely split the command string into arguments
        args = shlex.split(command)
        result = subprocess.run(args, capture_output=True, text=True, check=True)
        return jsonify({
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        }), 200
    except subprocess.CalledProcessError as e:
        return jsonify({
            'stdout': e.stdout,
            'stderr': e.stderr,
            'returncode': e.returncode
        }), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(port=3000, debug=True)
