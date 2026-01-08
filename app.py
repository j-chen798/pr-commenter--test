from asyncio import DatagramProtocol
import os
import hmac
import hashlib
import time
import jwt
import requests
from flask import Flask, request, abort

app = Flask(__name__)

WEBHOOK_SECRET = os.environ["GITHUB_WEBHOOK_SECRET"]
APP_ID = os.environ["GITHUB_APP_ID"]
with open("private-key.pem", "r") as f:
    PRIVATE_KEY = f.read()


def verify_signature(payload, signature):
    mac = hmac.new(WEBHOOK_SECRET.encode(), payload, hashlib.sha256)
    expected = "sha256=" + mac.hexdigest()
    return hmac.compare_digest(signature, expected)

def get_jwt():
    payload = {
        "iat": int(time.time()) - 60,
        "exp": int(time.time()) + 600,
        "iss": APP_ID,
    }
    return jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")

def get_installation_token(installation_id):
    jwt = get_jwt()
    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    headers = {
        "Authorization": f"Bearer {jwt}",
        "Accept": "application/vnd.github+json",
    }
    response = requests.post(url, headers=headers)
    return response.json()["token"]

def comment_on_pr(repo, pr_number, token, message):
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    data = {
        "body": message,
    }
    response = requests.post(url, headers=headers, json=data)
    
def handle_pull_request(data):
    action = data["action"]
    if action not in ["opened", "synchronize"]:
        return
    
    installation_id = data["installation"]["id"]
    token = get_installation_token(installation_id)
    repo = data["repository"]["full_name"]
    pr_number = data["number"]
    comment_on_pr(repo, pr_number, token, "Thanks for the PR!")


@app.route("/webhook", methods=["POST"])
def webhook():
    signature = request.headers.get("X-Hub-Signature-256")
    payload = request.get_data()
    if not verify_signature(payload, signature):
        abort(400)
    event = request.headers.get("X-GitHub-Event")
    data = request.json

    print("Event type:", event)
    print("Data:", data)
    if event == "pull_request":
        handle_pull_request(data)
    return "OK", 204
