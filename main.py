import base64
import json
import hashlib
import secrets
import requests
import webbrowser
from flask import Flask, request, redirect, jsonify

app = Flask(__name__)

def load_config():
    with open("config.json", "r") as config_file:
        return json.load(config_file)

config = load_config()

def generate_code_verifier():
    """Generates a random code verifier using secrets module."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode('utf-8')

def generate_code_challenge(verifier):
    """Generates a code challenge using SHA256 of the code verifier."""
    sha256_hash = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(sha256_hash).rstrip(b'=').decode('utf-8')

@app.route('/oauth/kick/', methods=['GET'])
def oauth_kick():
    """Redirects user to the OAuth authorization URL."""
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)

    state = base64.urlsafe_b64encode(json.dumps({"codeVerifier": code_verifier}).encode()).rstrip(b'=').decode('utf-8')

    auth_params = {
        "client_id": config["KICK_CLIENT_ID"],
        "redirect_uri": config["REDIRECT_URL"],
        "response_type": "code",
        "scope": " ".join(config["KICK_SCOPES"]),
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    auth_url = config["ENDPOINT"]["authURL"] + "?" + "&".join(f"{key}={value}" for key, value in auth_params.items())
    return redirect(auth_url)

@app.route('/oauth/kick/callback', methods=['GET'])
def oauth_callback():
    """Handles the OAuth callback to exchange authorization code for access token."""
    code = request.args.get('code')
    state = request.args.get('state')

    if not code:
        return jsonify({"error": "Missing authorization code"}), 400

    try:
        state_data = json.loads(base64.urlsafe_b64decode(state + "==").decode())
        code_verifier = state_data["codeVerifier"]

        token_params = {
            "grant_type": "authorization_code",
            "client_id": config["KICK_CLIENT_ID"],
            "client_secret": config["KICK_CLIENT_SECRET"],
            "code": code,
            "redirect_uri": config["REDIRECT_URL"],
            "code_verifier": code_verifier,
        }

        response = requests.post(config["ENDPOINT"]["tokenURL"], data=token_params)

        token = response.json()
        return jsonify(token)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    webbrowser.open("http://localhost:3000/oauth/kick/")

    app.run(debug=True, port=3000, use_reloader=False)
