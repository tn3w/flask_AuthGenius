import sys

if __name__ == "__main__":
    sys.exit(2)

import pkg_resources
import os
from typing import Optional, Union
from base64 import b64encode, b64decode
import mimetypes
import random
from io import BytesIO
from urllib.parse import urlparse
import threading
import json
import re
import secrets
import hashlib
from time import time
from PIL import Image, ImageDraw, ImageFont
from flask import request
import ipaddress
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import requests

DATA_DIR = pkg_resources.resource_filename('flask_AuthGenius', 'data')
ASSETS_DIR = pkg_resources.resource_filename('flask_AuthGenius', 'assets')
FONTS = [
    os.path.join(ASSETS_DIR, "Comic_Sans_MS.ttf"),
    os.path.join(ASSETS_DIR, "Droid_Sans_Mono.ttf"),
    os.path.join(ASSETS_DIR, "Helvetica.ttf")
]

USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.3", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.1", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.3", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.2 Safari/605.1.1", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.1", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.1"]
IP_API_CACHE_PATH = os.path.join(DATA_DIR, "ipapi-cache.json")
IP_INFO_KEYS = ['continent', 'continentCode', 'country', 'countryCode', 'region', 'regionName', 'city', 'district', 'zip', 'lat', 'lon', 'timezone', 'offset', 'currency', 'isp', 'org', 'as', 'asname', 'reverse', 'mobile', 'proxy', 'hosting', 'time']

does_support_ansi_color = None

def error(error_message: str) -> None:
    """
    Prints an error in the console

    :param error_message: The error message
    """

    global does_support_ansi_color

    def supports_ansi_color() -> bool:
        "Function for caching the result of check_for_ansi_colors"

        def check_for_ansi_colors():
            "Function to check whether Ansi Color Escape Codes can be used in the console"

            if sys.platform == 'win32' or sys.platform == 'cygwin':
                return False

            term_program = os.environ.get('TERM_PROGRAM', '')
            if term_program.lower() == 'vscode':
                return False

            try:
                return sys.stdout.isatty() and os.name == 'posix'
            except AttributeError:
                return False

        if does_support_ansi_color is None:
            does_support_ansi_color = check_for_ansi_colors()

        return does_support_ansi_color
    
    if does_support_ansi_color is None:
        print()
    
    error_message = "[flask_AuthGenius Error] " + error_message
    print("\033[91m" + error_message + "\033[0m") if supports_ansi_color() else print(error_message)

def convert_image_to_base64(file_path: str) -> Optional[str]:
    """
    Converts an image file into Base64 Web Format

    :param file_path: The path to the image file
    """

    if not os.path.isfile(file_path):
        return

    try:
        with open(file_path, 'rb', encoding = "utf-8") as image_file:
            encoded_image = b64encode(image_file.read()).decode('utf-8')

            mime_type, _ = mimetypes.guess_type(file_path)
            if not mime_type:
                mime_type = 'application/octet-stream'

            data_url = f'data:{mime_type};base64,{encoded_image}'

            return data_url
    except Exception as e:
        error("Error loading image file or converting to Base64 format: " + e)

def generate_website_logo(name: str) -> str:
    """
    Generates a website logo matching the name

    :param name: Name whose first two letters appear on the logo
    """

    size = 200
    background_color = tuple(random.randint(0, 255) for _ in range(3))

    image = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.ellipse([(0, 0), (size, size)], fill=background_color)

    brightness = 0.299 * background_color[0] + 0.587 * background_color[1] + 0.114 * background_color[2]
    text_color = (255, 255, 255) if brightness < 128 else (0, 0, 0)

    font = ImageFont.truetype(random.choice(FONTS), 80)

    initials = name[:2].upper()

    text_bbox = draw.textbbox((0, 0), initials, font=font)
    text_width = text_bbox[2] - text_bbox[0]
    text_height = text_bbox[3] - text_bbox[1]
    text_position = ((size - text_width) // 2, (size - text_height) // 2)

    draw.text(text_position, initials, font=font, fill=text_color)

    image_buffer = BytesIO()
    image.save(image_buffer, format="PNG")

    image_base64 = b64encode(image_buffer.getvalue()).decode("utf-8")
    return "data:image/png;base64," + image_base64

def is_current_route(path: str):
    """
    Helper function to determine if the provided path matches the current route or endpoint.

    :param path: The path to check against the current route or endpoint
    """

    url_path = urlparse(request.url).path
    url_endpoint = request.endpoint

    url = url_path
    if not "/" in path:
        url = url_endpoint

    if '*' in path:
        real_path = path.replace("*", "")
        if (path.startswith("*") and path.endswith("*") and real_path in url) or \
            (path.startswith("*") and url.endswith(real_path)) or \
                (path.endswith("*") and url.startswith(real_path)):
            return True
        first_part, second_part = path.split("*")[0], path.split("*")[1]

        if url.startswith(first_part) and url.endswith(second_part):
            return True

    else:
        if path == url_endpoint:
            return True
    
    return False

def shorten_ipv6(ip_address: str) -> str:
    """
    Minimizes each ipv6 Ip address to be able to compare it with others
    
    :param ip_address: An ipv4 or ipv6 Ip address
    """

    try:
        return str(ipaddress.IPv6Address(ip_address).compressed)
    except:
        return ip_address

def is_valid_ip(ip_address: Optional[str] = None) -> bool:
    """
    Checks whether the current Ip is valid
    
    :param ip_address: Ipv4 or Ipv6 address (Optional)
    """

    if ip_address == "127.0.0.1" or ip_address is None:
        return False

    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    ipv6_pattern = r'^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|:|::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}::([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,2}:([0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,3}:([0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,4}:([0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}:([0-9a-fA-F]{1,4}:){0,1}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}|:((:[0-9a-fA-F]{1,4}){1,7}|:)|([0-9a-fA-F]{1,4}:)(:[0-9a-fA-F]{1,4}){1,7}|([0-9a-fA-F]{1,4}:){2}(:[0-9a-fA-F]{1,4}){1,6}|([0-9a-fA-F]{1,4}:){3}(:[0-9a-fA-F]{1,4}){1,5}|([0-9a-fA-F]{1,4}:){4}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){5}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){6}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){7}(:[0-9a-fA-F]{1,4}):)$'

    ipv4_regex = re.compile(ipv4_pattern)
    ipv6_regex = re.compile(ipv6_pattern)

    if ipv4_regex.match(ip_address):
        octets = ip_address.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            return True
    elif ipv6_regex.match(ip_address):
        return True

    return False

def get_client_ip() -> Optional[str]:
    "Get the client IP in v4 or v6"

    client_ip = request.remote_addr
    if is_valid_ip(client_ip):
        client_ip = shorten_ipv6(client_ip)
        return client_ip

    other_client_ips = [
        request.environ.get('HTTP_X_REAL_IP', None),
        request.environ.get('REMOTE_ADDR', None),
        request.environ.get('HTTP_X_FORWARDED_FOR', None),
    ]

    for client_ip in other_client_ips:
        if is_valid_ip(client_ip):
            client_ip = shorten_ipv6(client_ip)
            return client_ip
    
    try:
        client_ip = request.headers.getlist("X-Forwarded-For")[0].rpartition(' ')[-1]
    except:
        pass
    else:
        if is_valid_ip(client_ip):
            client_ip = shorten_ipv6(client_ip)
            return client_ip
    
    headers_to_check = [
        'X-Forwarded-For',
        'X-Real-Ip',
        'CF-Connecting-IP',
        'True-Client-Ip',
    ]

    for header in headers_to_check:
        if header in request.headers:
            client_ip = request.headers[header]
            client_ip = client_ip.split(',')[0].strip()
            if is_valid_ip(client_ip):
                client_ip = shorten_ipv6(client_ip)
                return client_ip
    
    return None

def random_user_agent() -> str:
    "Generates a random user agent to bypass Python blockades"

    return secrets.choice(USER_AGENTS)

def get_ip_info(ip_address: str) -> dict:
    """
    Function to query IP information with cache con ip-api.com

    :param ip_address: The client IP
    """

    ip_api_cache = JSON.load(IP_API_CACHE_PATH)

    for hashed_ip, crypted_data in ip_api_cache.items():
        comparison = FastHashing().compare(ip_address, hashed_ip)
        if comparison:
            data = SymmetricCrypto(ip_address).decrypt(crypted_data)

            data_json = {}
            for i in range(23):
                data_json[IP_INFO_KEYS[i]] = {"True": True, "False": False}.get(data.split("-&%-")[i], data.split("-&%-")[i])

            if int(time()) - int(data_json["time"]) > 518400:
                del ip_api_cache[hashed_ip]
                break

            return data_json
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip_address}?fields=66846719",
            headers = {"User-Agent": random_user_agent()},
            timeout = 3
        )
        response.raise_for_status()
    except Exception as e:
        error("ip-api.com could not be requested or did not provide a correct answer: " + e)
        return

    if response.ok:
        response_json = response.json()
        if response_json["status"] == "success":
            del response_json["status"], response_json["query"]
            response_json["time"] = int(time())
            response_string = '-&%-'.join([str(value) for value in response_json.values()])
            
            crypted_response = SymmetricCrypto(ip_address).encrypt(response_string)
            hashed_ip = FastHashing().hash(ip_address)

            ip_api_cache[hashed_ip] = crypted_response
            JSON.dump(ip_api_cache, IP_API_CACHE_PATH)

            return response_json

    error("ip-api.com could not be requested or did not provide a correct answer")
    return None

file_locks = dict()

class JSON:
    "Class for loading / saving JavaScript Object Notation (= JSON)"

    @staticmethod
    def load(file_name: str, default: Union[dict, list] = None) -> Union[dict, list]:
        """
        Function to load a JSON file securely.

        :param file_name: The JSON file you want to load
        :param default: Returned if no data was found
        """

        if not os.path.isfile(file_name):
            if default is None:
                return []
            return default
        
        if not file_name in file_locks:
            file_locks[file_name] = threading.Lock()

        with file_locks[file_name]:
            with open(file_name, "r", encoding = "utf-8") as file:
                data = json.load(file)
            return data
    
    @staticmethod
    def dump(data: Union[dict, list], file_name: str) -> None:
        """
        Function to save a JSON file securely.
        
        :param data: The data to be stored should be either dict or list
        :param file_name: The file to save to
        """

        file_directory = os.path.dirname(file_name)
        if not os.path.isdir(file_directory):
            error("JSON: Directory '" + file_directory + "' does not exist.")
            return
        
        if not file_name in file_locks:
            file_locks[file_name] = threading.Lock()

        with file_locks[file_name]:
            with open(file_name, "w", encoding = "utf-8") as file:
                json.dump(data, file)

class FastHashing:
    "Implementation for fast hashing"

    def __init__(self, salt: Optional[str] = None):
        ":param salt: The salt, makes the hashing process more secure (Optional)"

        self.salt = salt

    def hash(self, plain_text: str, hash_length: int = 8) -> str:
        """
        Function to hash a plaintext

        :param plain_text: The text to be hashed
        :param hash_length: The length of the returned hashed value
        """

        salt = self.salt
        if salt is None:
            salt = secrets.token_hex(hash_length)
        plain_text = salt + plain_text

        hash_object = hashlib.sha256(plain_text.encode())
        hex_dig = hash_object.hexdigest()

        return hex_dig + "//" + salt

    def compare(self, plain_text: str, hash: str) -> bool:
        """
        Compares a plaintext with a hashed value

        :param plain_text: The text that was hashed
        :param hash: The hashed value
        """

        salt = self.salt
        if "//" in hash:
            hash, salt = hash.split("//")

        hash_length = len(hash)

        comparison_hash = FastHashing(salt=salt).hash(plain_text, hash_length = hash_length).split("//")[0]

        return comparison_hash == hash

class SymmetricCrypto:
    """
    Implementation of symmetric encryption with AES
    """

    def __init__(self, password: Optional[str] = None, salt_length: int = 32):
        """
        :param password: A secure encryption password, should be at least 32 characters long
        :param salt_length: The length of the salt, should be at least 16
        """

        if password is None:
            password = secrets.token_urlsafe(64)

        self.password = password.encode()
        self.salt_length = salt_length

    def encrypt(self, plain_text: str) -> str:
        """
        Encrypts a text

        :param plaintext: The text to be encrypted
        """

        salt = secrets.token_bytes(self.salt_length)

        kdf_ = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf_.derive(self.password)

        iv = secrets.token_bytes(16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plain_text.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return b64encode(salt + iv + ciphertext).decode()

    def decrypt(self, cipher_text: str) -> str:
        """
        Decrypts a text

        :param ciphertext: The encrypted text
        """

        cipher_text = b64decode(cipher_text.encode())

        salt, iv, cipher_text = cipher_text[:self.salt_length], cipher_text[self.salt_length:self.salt_length + 16], cipher_text[self.salt_length + 16:]

        kdf_ = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf_.derive(self.password)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = decryptor.update(cipher_text) + decryptor.finalize()
        plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

        return plaintext.decode()