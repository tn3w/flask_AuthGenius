import os
from threading import Thread
from typing import Optional, Tuple, Any
from time import time
from pkg_resources import resource_filename
from werkzeug import Request
from .utils import WebPage, JSON, Hashing, SymmetricEncryption, generate_random_string


try:
    CURRENT_DIR_PATH = resource_filename('flask_AuthGenius', '')
except ModuleNotFoundError:
    CURRENT_DIR_PATH = os.path.dirname(os.path.abspath(__file__))

DATA_DIR_PATH = os.path.join(CURRENT_DIR_PATH, 'data')

class User(dict):

    def __init__(self, users_file_path: Optional[str] = None) -> None:
        if users_file_path is None:
            users_file_path = os.path.join(DATA_DIR_PATH, 'users.json')
        self.users_file_path = users_file_path
        self.users = self._load
        self.reserved_user_ids = []
        self.reserved_session_ids = []

        super().__init__()

    @property
    def _load(self) -> dict:
        return JSON.load(self.users_file_path, {})

    def _dump(self, new_users: dict) -> None:
        self.users = new_users

        dump_thread = Thread(target = JSON.dump, args = (new_users, self.users_file_path))
        dump_thread.start()

    def __setitem__(self, user_id: Any, user_data: Any) -> None:
        users = self.users.copy()
        users[user_id] = user_data
        self._dump(users)

    def __getitem__(self, user_id: str) -> Optional[dict]:
        for index in range(2):
            for hashed_user_id, user_data in self.users:
                if user_id == hashed_user_id:
                    return user_data

                if index == 1:
                    if Hashing().compare(user_id, hashed_user_id):
                        return user_data

        return None

    def get(self, user_id: Optional[str] = None,
            user_name: Optional[str] = None,
            user_email: Optional[str] = None) -> dict:

        raise NotImplementedError()

        # FIXME: Implemention

        if not user_id is None:
            for hashed_user_id, user_data in self.users:
                ...

    def is_password_correct(self, user_id: str, password_inp: str,
                            encrypted_fields: Optional[list] = None) -> bool:
        user = self[user_id]
        if user is None:
            return False

        hashed_password = user.get('hpwd')
        if hashed_password is not None:
            return Hashing(iterations = 150000).compare(password_inp, hashed_password)

        user_data: dict = user.get('data')
        if None in [encrypted_fields, user_data]:
            return False

        for key, value in user_data.items():
            if key not in encrypted_fields:
                continue

            decrypted_value = SymmetricEncryption(password_inp).decrypt(value)
            if decrypted_value is None:
                return False
            return True

        return False

    def create(self, password: str, user_name: Optional[str] = None,
               user_email: Optional[str] = None,
               other_user_data: Optional[dict] = None,
               encrypted_fields: Optional[list] = None) -> str:

        if other_user_data is None:
            other_user_data = {}
        if encrypted_fields is None:
            encrypted_fields = []

        user = {}

        hashed_password = Hashing(iterations = 150000).hash(password)
        user['hpwd'] = hashed_password

        if not user_name is None:
            user['name'] = Hashing().hash(user_name)
            other_user_data['name'] = user_name
        if not user_email is None:
            user['email'] = Hashing().hash(user_email)
            other_user_data['email'] = user_email

        encryptor = SymmetricEncryption(password).encrypt

        user_data = {}
        for key, value in other_user_data.items():
            if key in encrypted_fields:
                value = encryptor(value)
            user_data[key] = value

        user['data'] = user_data

        user_id = generate_random_string(12, False)
        while self[user_id] is not None or user_id in self.reserved_user_ids:
            user_id = generate_random_string(12, False)

        self.reserved_user_ids.append(user_id)

        try:
            hashed_user_id = Hashing().hash(user_id)

            self[hashed_user_id] = user
            return user_id
        finally:
            self.reserved_user_ids.remove(user_id)

    # FIXME: Sessions must be deleted after a while

    def get_session(self, user_id: str, session_id: Optional[str] = None,
                    session_token: Optional[str] = None,
                    password: Optional[str] = None) -> Optional[dict]:
        user = self[user_id]
        if user is None:
            return None

        user_sessions: dict = user.get('sessions', {})

        session_data = None

        if session_id is not None:
            for hashed_session_id, stored_session_data in user_sessions.items():
                if Hashing().compare(session_id, hashed_session_id):
                    if session_token is not None:
                        hashed_session_token = stored_session_data.get('htoken')
                        if hashed_session_token is None:
                            return None

                        if not Hashing(iterations = 100000).compare(
                            session_token, hashed_session_token):
                            return None

                    session_data: dict = stored_session_data
                    break
        elif session_token is not None:
            for _, stored_session_data in user_sessions.items():
                hashed_session_token = stored_session_data.get('htoken')
                if hashed_session_token is None:
                    continue

                if Hashing(iterations = 100000).compare(session_token, hashed_session_token):
                    encrypted_session_id = stored_session_data.get('eid')
                    if encrypted_session_id is not None:
                        stored_session_data['id'] = SymmetricEncryption(session_token)\
                                                        .decrypt(encrypted_session_id)

                    session_data: dict = stored_session_data
                    break

        if None in [password, session_data]:
            return session_data

        encrypted_data = session_data.get('data', {})
        if not isinstance(encrypted_data, dict) or len(encrypted_data) == 0:
            return session_data

        decryptor = SymmetricEncryption(password).decrypt

        decrypted_data = {}
        for key, value in encrypted_data.items():
            decrypted_data[key] = decryptor(value)

        session_data['data'] = decrypted_data
        return session_data

    def create_session(self, user_id: str, password: str,
                       data: Optional[dict] = None)\
                        -> Tuple[Optional[str], Optional[str]]:
        if not isinstance(data, dict):
            data = {}

        user = self[user_id]
        if user is None:
            return None

        session = {}

        session_token = generate_random_string(14, False)
        hashed_session_token = Hashing(iterations = 100000).hash(session_token)
        session['htoken'] = hashed_session_token

        encryptor = SymmetricEncryption(password).encrypt

        encrypted_data = {}
        for key, value in data.items():
            encrypted_data[key] = encryptor(value)
        session['data'] = encrypted_data

        session_id = generate_random_string(6, False)
        while self.get_session(user_id, session_id) is not None\
            or session_id in self.reserved_session_ids:
            session_id = generate_random_string(6, False)

        self.reserved_session_ids.append(session_id)

        try:
            encrypted_session_id = SymmetricEncryption(session_token).encrypt(session_id)
            session['eid'] = encrypted_session_id

            user = self[user_id]
            if user is None:
                return None

            user_sessions: dict = user.get('sessions', {})

            hashed_session_id = Hashing().hash(session_id)
            while any(session_id == hashed_session_id for session_id in list(user_sessions.keys())):
                hashed_session_id = Hashing().hash(session_id)

            user = self[user_id]
            if user is None:
                return None

            user_sessions = user.get('sessions', {})
            user_sessions[hashed_session_id] = session
            user['sessions'] = user_sessions

            self[user_id] = user_sessions
            return session_id, session_token
        finally:
            self.reserved_session_ids.remove(session_id)

class Validation:

    @staticmethod
    def validate_login(request: Request) -> Optional[dict]:
        data = request.form
        if request.is_json and request.method.lower() == 'post':
            data = request.get_json()

        name = data.get('name')
        password = data.get('password')
        captcha_code = data.get('captcha_code')
        captcha_secret = data.get('captcha_secret')

        stay = data.get('stay', '0')
        stay = '1' if stay == '1' else '0'

        response = {"error": None, "error_fields": [], "content": {}}

        language = WebPage.client_language(request, 'en')

        if not name or not password:
            response['error'] = WebPage.translate_text(
                'Please fill in all fields.', 'en', language
            )
            error_fields = []
            if name is None and not password is None:
                error_fields.append('name')
            elif password is None and not name is None:
                error_fields.append('password')
            response['error_fields'] = error_fields
            return response

        # testcreds: tn3w / tn3w@duck.com + password: HelloWorld1234
        # FIXME: Proper user system
        if name not in ['tn3w', 'tn3w@duck.com']:
            response['error'] = WebPage.translate_text(
                'The username / email was not found.', 'en', language
            )
            response['error_fields'] = ['name']
            return response

        new_failed_accounts = self.failed_accounts.copy()
        for account_id, account_failed in self.failed_accounts.items():
            new_account_failed = []
            for failed_time in account_failed:
                if int(time() - failed_time) <= 3600:
                    new_account_failed.append(failed_time)

            if len(new_failed_accounts) == 0:
                del new_failed_accounts[account_id]
                continue

            new_failed_accounts[account_id] = new_account_failed

        self.failed_accounts = new_failed_accounts

        account_id = '1'
        failed_passwords = len(self.failed_accounts.get(account_id, []))

        if self.use_captchas and failed_passwords > 2:
            failed_captcha = False
            if not captcha_code or not captcha_secret:
                response['error'] = WebPage.translate_text(
                    'Please solve the captcha.', 'en', language
                )
                failed_captcha = True
            else:
                error_reason = self.captcha.verify(
                    captcha_code, captcha_secret,
                    {'name': name, 'password': password}
                )

                if error_reason == 'code':
                    response['error'] = WebPage.translate_text(
                        'The captcha was not correct, try again.', 'en', language
                    )
                    failed_captcha = True
                elif error_reason == 'data':
                    response['error'] = WebPage.translate_text(
                        'Data has changed, re-enter the captcha.', 'en', language
                    )
                    failed_captcha = True
                elif error_reason == 'time':
                    response['error'] = WebPage.translate_text(
                        'The captcha has expired, try again.', 'en', language
                    )
                    failed_captcha = True

            if failed_captcha:
                response['error_fields'] = ['captcha']

                captcha_img, captcha_secret = self.captcha.generate(
                    {'name': name, 'password': password}
                )

                response['content']['captcha_img'] = captcha_img
                response['content']['captcha_secret'] = captcha_secret
                return response

        # testcreds: tn3w / tn3w@duck.com + password: HelloWorld1234
        # FIXME: Proper password system
        if password != 'HelloWorld1234':
            failed_times = self.failed_accounts.get(account_id, [])
            failed_times.append(time())
            self.failed_accounts[account_id] = failed_times

            response['error'] = WebPage.translate_text(
                'The password is not correct.', 'en', language
            )
            response['error_fields'] = ['password']
            return response

        return None
