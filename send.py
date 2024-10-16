import requests
import json
import logging

# Configurar logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Base URL of the API
BASE_URL = "http://127.0.0.1:8080/api"

def login(username, password):
    """Log in and get an authentication token."""
    url = f"{BASE_URL}/login"
    data = {
        "username": username,
        "password": password,
        "peerId": "your_peer_id",
        "photo": "your_photo_url"
    }
    try:
        logging.info(f"Attempting to login with username: {username}")
        response = requests.post(url, json=data)
        response.raise_for_status()
        token = response.json().get("token")
        if not token:
            raise ValueError("Token not found in response")
        logging.info("Login successful")
        return token
    except requests.exceptions.RequestException as e:
        logging.error(f"Login request failed: {e}")
        logging.error(f"Response status code: {response.status_code}")
        logging.error(f"Response content: {response.text}")
        raise Exception("Login failed")

def send_message(token, title, message, subtitle="Sistema"):
    """Send a message using the API."""
    url = f"{BASE_URL}/send"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    params = {
        "title": title,
        "message": message,
        "subtitle": subtitle
    }
    try:
        logging.info(f"Attempting to send message: {message}")
        response = requests.post(url, headers=headers, params=params)
        response.raise_for_status()
        logging.info("Message sent successfully")
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Send message request failed: {e}")
        logging.error(f"Response status code: {response.status_code}")
        logging.error(f"Response content: {response.text}")
        raise Exception("Failed to send message")

def main():
    username = "admin"
    password = "123"
    
    try:
        token = login(username, password)
        logging.info(f"Obtained token: {token[:10]}...")  # Log first 10 characters of token

        title = "Fontanero"
        message = "24H PEPE tlf: 654321456" # cambia esto es el mensaje
        response = send_message(token, title, message)
        logging.info(f"Message sent response: {response}")
    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()