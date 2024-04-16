from typing import Optional
from time import time
from werkzeug import Request
from .auth import UserSystem
from .utils import WebPage, Captcha, is_email

class Validation:

    @staticmethod
    def validate_login(request: Request, user_system: UserSystem,
                       captcha: Captcha, use_captchas: bool = True) -> Optional[dict]:
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

        user = None
        if is_email(name):
            user = user_system.get_user(user_email = name, return_id = True)

        if user is None:
            user = user_system.get_user(
                user_name = name, user_email = name, return_id = True
            )

        if user is None:
            response['error'] = WebPage.translate_text(
                'The username / email was not found.', 'en', language
            )
            response['error_fields'] = ['name']
            return response

        user_id = user.get('hid') if user.get('id') is None else user.get('id')

        if use_captchas and user_system.should_captcha_be_used(user_id):
            failed_captcha = False
            if not captcha_code or not captcha_secret:
                response['error'] = WebPage.translate_text(
                    'Please solve the captcha.', 'en', language
                )
                failed_captcha = True
            else:
                error_reason = captcha.verify(
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

                captcha_img, captcha_secret = captcha.generate(
                    {'name': name, 'password': password}
                )

                response['content']['captcha_img'] = captcha_img
                response['content']['captcha_secret'] = captcha_secret
                return response

        if not user_system.is_password_correct(user_id, password):
            user_system.add_failed_attempt(user_id)

            response['error'] = WebPage.translate_text(
                'The password is not correct.', 'en', language
            )
            response['error_fields'] = ['password']
            return response

        return None
