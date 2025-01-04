import requests
import json
import time
from urllib.parse import urlencode, quote_plus
import threading

BASE_URL = "http://127.0.0.1:8080"
token = None
filtered_tablones = []
current_page = 1
items_per_page = 5
auto_refresh_enabled = True
current_refresh_interval = 5  # Check for new messages every 5 seconds
refresh_interval_id = None
previous_tablones_data = {}  # To store previously fetched tablones

def login(username, password, peer_id, photo):
    global token
    url = f"{BASE_URL}/api/login"
    headers = {'Content-Type': 'application/json'}
    data = {'username': username, 'password': password, 'peerId': peer_id, 'photo': photo}
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        data = response.json()
        token = data.get('token')
        # print(f"\nsesión exitoso. Token recibido: {token}")
        return True
    except requests.exceptions.RequestException as e:
        print(f'Error al iniciar sesión: {e}')
        return False

def create_tablon(name, message, geo):
    global token
    if not token:
        print("Error: No estás autenticado. Inicia sesión primero.")
        return None
    url = f"{BASE_URL}/api/createTablon?name={quote_plus(name)}&mensaje={quote_plus(message)}&geo={quote_plus(geo)}"
    headers = {'Authorization': token}
    try:
        response = requests.post(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f'Error al crear tablón: {e}')
        return None

def add_message(tablon_id, message):
    global token
    if not token:
        print("Error: No estás autenticado. Inicia sesión primero.")
        return None
    url = f"{BASE_URL}/api/addMessage?tablon_id={tablon_id}&message={quote_plus(message)}"
    headers = {'Authorization': token}  # Add Authorization header
    try:
        response = requests.post(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f'Error al añadir mensaje: {e}')
        return None

def get_tablones():
    global token
    url = f"{BASE_URL}/api/readTablon"
    try:
        response = requests.get(url, headers={'Authorization': token} if token else None)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f'Error al obtener tablones: {e}')
        return []

def fetch_new_messages():
    global previous_tablones_data
    current_tablones = get_tablones()
    new_tablones_data = {tablon['id']: tablon for tablon in current_tablones}

    for tablon_id, tablon in new_tablones_data.items():
        previous_messages = previous_tablones_data.get(tablon_id, {}).get('messages', [])
        current_messages = tablon.get('messages', [])

        previous_message_ids = {msg['id'] for msg in previous_messages}
        current_message_ids = {msg['id'] for msg in current_messages}

        new_messages = [msg for msg in current_messages if msg['id'] not in previous_message_ids]

        if new_messages:
            print(f"\nCANAL: '{tablon['name']}':")
            for message in new_messages:
                print(f"  - {message['content']['message']}")

    previous_tablones_data = new_tablones_data

def continuous_check():
    while True:
        if token:
            fetch_new_messages()
        time.sleep(current_refresh_interval)

def remove_token():
    global token
    token = None
    print('Token eliminado.')

def set_interval(func, interval):
    def wrapper():
        while True:
            func()
            time.sleep(interval)
    thread = threading.Thread(target=wrapper, daemon=True)
    thread.start()

def get_tablon_by_name(name):
    tablones = get_tablones()
    for tablon in tablones:
        if tablon['name'] == name:
            return tablon
    return None

def list_messages_from_tablon(tablon_name):
    tablon = get_tablon_by_name(tablon_name)
    if tablon:
        print(f"\nMensajes en el canal '{tablon_name}':")
        if 'messages' in tablon:
            for message in tablon['messages']:
                print(f"  - {message['content']['message']}")
        else:
            print("  No hay mensajes en este canal.")
    else:
        print(f"No se encontró el canal '{tablon_name}'.")

def create_tablon_and_add_message(tablon_name, message_content, geo=""):
    """
    Crea un tablón si no existe y añade un mensaje.

    Args:
        tablon_name (str): El nombre del tablón.
        message_content (str): El contenido del mensaje a añadir.
        geo (str, optional): La geolocalización del tablón si se crea uno nuevo. Defaults to "".
    """
    tablon = get_tablon_by_name(tablon_name)
    if not tablon:
        print(f"El tablón '{tablon_name}' no existe. Creando...")
        create_result = create_tablon(tablon_name, "Tablón creado automáticamente", geo)
        if create_result:
            print(f"Tablón '{tablon_name}' creado exitosamente.")
            tablon_id = create_result.get('id')  # Assuming the API returns the ID upon creation
            if tablon_id:
                message_result = add_message(tablon_id, message_content)
                if message_result:
                    print(f"Mensaje '{message_content}' enviado al tablón '{tablon_name}'.")
                else:
                    print(f"Error al enviar mensaje al tablón '{tablon_name}'.")
            else:
                print(f"No se pudo obtener el ID del tablón '{tablon_name}'.")
        else:
            print(f"Error al crear el tablón '{tablon_name}'.")
    else:
        print(f"El tablón '{tablon_name}' ya existe. Añadiendo mensaje...")
        message_result = add_message(tablon['id'], message_content)
        if message_result:
            print(f"Mensaje '{message_content}' enviado al tablón '{tablon_name}'.")
        else:
            print(f"Error al enviar mensaje al tablón '{tablon_name}'.")

if __name__ == "__main__":
    print(f"\nNo se encontró token. Necesitas iniciar sesión.")
    username = "admin"
    password = "123"
    peer_id = ""
    photo = ""

    if login(username, password, peer_id, photo):
        print("\nIniciando la verificación continua de nuevos mensajes...")
        continuous_thread = threading.Thread(target=continuous_check, daemon=True)
        continuous_thread.start()

        # Usando la nueva función para crear o añadir mensaje
        tablon_para_mensaje = "noticias"
        mensaje_para_tablon = "Última hora: ¡Algo emocionante ha pasado!"
        create_tablon_and_add_message(tablon_para_mensaje, mensaje_para_tablon, geo="Lugar del evento")
        create_tablon_and_add_message(tablon_para_mensaje, mensaje_para_tablon, geo="Lugar del evento")
        tablon_existente = "madrid" # Asumiendo que ya existe o se creará con el código anterior
        mensaje_al_existente = "Otro mensaje para Madrid."
        create_tablon_and_add_message(tablon_existente, mensaje_al_existente)

        # Listar todos los mensajes del tablón "noticias"
        list_messages_from_tablon(tablon_para_mensaje)

        # Listar todos los mensajes del tablón "madrid"
        list_messages_from_tablon(tablon_existente)

        try:
            while True:
                time.sleep(1) # Keep the main thread alive
        except KeyboardInterrupt:
            print("\nDeteniendo la verificación continua de mensajes.")
    else:
        print("No se pudo iniciar sesión.")
