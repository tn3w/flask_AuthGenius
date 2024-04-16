import pkg_resources
import os
from time import time
import re
from typing import Optional, Tuple
from flask import Flask, g, request, redirect, make_response, abort
from .utils import JSON, error, convert_image_to_base64, generate_website_logo, is_current_route,\
                   get_client_ip, get_ip_info, render_template, get_random_item, get_url_from_request,\
                   remove_args_from_url, Captcha, generate_random_string, WebPage, SymmetricData, TOTP
from .auth import UserSystem
from .validation import Validation

try:
    CURRENT_DIR_PATH = pkg_resources.resource_filename('flask_AuthGenius', '')
except ModuleNotFoundError:
    CURRENT_DIR_PATH = os.path.dirname(os.path.abspath(__file__))


DATA_DIR = os.path.join(CURRENT_DIR_PATH, 'data')
ASSETS_DIR = os.path.join(CURRENT_DIR_PATH, 'assets')

if not os.path.isdir(DATA_DIR):
    os.mkdir(DATA_DIR)

THEMES = ["light", "dark"]

LANGUAGES = JSON.load(os.path.join(ASSETS_DIR, "languages.json"))
LANGUAGE_CODES = [language["code"] for language in LANGUAGES]

GENERATED_LOGO_PATH = os.path.join(DATA_DIR, "generated-logo.txt")

SIGNATURES = [
    "To use everything we have to offer.",
    "Unlock a world of possibilities with your account.",
    "Your gateway to personalized experiences.",
    "Seamlessly access your account resources.",
    "Elevate your digital journey with us.",
    "Discover more with every log in.",
    "Your access point to exclusive content.",
    "Empowering you with secure connections.",
    "Begin your journey with a single click.",
    "Your secure portal to our services.",
    "Where convenience meets security.",
    "Explore, connect, and engage.",
    "Simplifying your online interactions.",
    "Unleash the full potential of our platform.",
    "Your trusted partner in the digital landscape.",
    "Enhancing your online experience.",
    "Opening doors to innovation and collaboration.",
    "Your key to a tailored user experience.",
    "Seamlessly connecting you to what matters.",
    "Dive deeper into our community."
]

class AuthGenius:
    "Shows the user a login prompt on certain routes"

    def __init__(
            self, app: Flask,
            website_name: str, website_logo_path: Optional[str] = None,
            authentication_routes: Optional[list] = None,
            popup_routes: Optional[list] = None,
            use_captchas: bool = True) -> None:
        """
        :param website_name: The name of your website
        :param website_logo_path: A path to a file that contains a small logo which is
                                  displayed on all pages next to the website name (Optional)
        :param authentication_routes: Routes or paths where authorization is required. (Optional)
        :param popup_routes: Routes or paths where a popup login window is shown. (Optional)
        """

        error('++ flask_AuthGenius is still under development,'+
              ' and does not yet work, it should only be used for testing ++')

        if app is None:
            error('The Flask app cannot be None.')
            return

        self.app = app
        self.website_name = website_name
        self.use_captchas = use_captchas
        self.totp = TOTP()
        self.user_system = UserSystem()
        self.enc = SymmetricData(generate_random_string(30))

        if use_captchas:
            self.captcha = Captcha(generate_random_string(30))

        website_logo = None
        if isinstance(website_logo_path, str):
            website_logo = convert_image_to_base64(website_logo_path)

        if website_logo is None:
            if not os.path.isfile(GENERATED_LOGO_PATH):
                website_logo = generate_website_logo(website_name)
                with open(GENERATED_LOGO_PATH, "w", encoding = "utf-8") as writeable_file:
                    writeable_file.write(website_logo)
            else:
                with open(GENERATED_LOGO_PATH, "r", encoding = "utf-8") as readable_file:
                    website_logo = readable_file.read()

        self.website_logo = website_logo
        self.authentication_routes = authentication_routes\
            if isinstance(authentication_routes, list) else []
        self.popup_routes = popup_routes if isinstance(popup_routes, list) else []

        self.failed_accounts = {}

        app.before_request(self._set_client_information)
        app.before_request(self._authenticate)

        @app.route('/login', methods = ['GET', 'POST'])
        def login():
            return self._login_route()

        @app.route('/login/api', methods = ['POST'])
        def login_api():
            return self._login_api_route()

        @app.route('/login/2fa', methods = ['GET', 'POST'])
        def login_2fa():
            return self._login_2fa_route()

        @app.route('/login/2fa/api', methods = ['POST'])
        def login_2fa_api():
            return self._login_2fa_api_route()

        @app.route('/login/tmp_api', methods = ['POST'])
        def template_api():
            response = {"error": None, "error_fields": [], "content": {}}

            if not request.is_json:
                return abort(400)

            template = request.args.get('template', 'login.html')
            args = dict(request.args)
            print(args)
            print(template)
            return template

    @property
    def _need_authentication(self) -> bool:
        "Whether authorization is required on the current route"

        # FIXME: Session check
        if request.cookies.get('Session') == 'yeah!' or request.args.get('session') == 'yeah!':
            return False

        if request.args.get("ag_login", "0") == "1"\
            or request.args.get("ag_register", "0") == "1"\
                or (request.method.upper() == "POST"\
                    and (request.form.get("ag_login") == "1" or\
                         request.form.get("ag_register") == "1")):
            return True

        for route in self.authentication_routes:
            if is_current_route(request, route):
                return True
        return False

    @property
    def _add_popup(self) -> bool:
        "Whether a pop-up window should be inserted on the current page"

        if self._need_authentication:
            return False

        for route in self.popup_routes:
            if is_current_route(request, route):
                return True
        return False

    @property
    def _is_own_page(self) -> bool:
        "Whether the current page is a page of flask_AuthGenius"

        is_own_page = hasattr(g, "authgenius_site", False)
        if isinstance(is_own_page, bool):
            return is_own_page
        return False

    @property
    def _client_language(self) -> Tuple[str, bool]:
        """
        Which language the client prefers

        :return language: The client languge
        :return is_default: Is Default Value
        """

        language_from_args = request.args.get("language")
        language_from_cookies = request.cookies.get("language")

        chosen_language = (
            language_from_args
            if language_from_args in LANGUAGE_CODES
            else (
                language_from_cookies
                if language_from_cookies in LANGUAGE_CODES
                else None
            )
        )

        if chosen_language is None:
            preferred_language = request.accept_languages.best_match(LANGUAGE_CODES)

            if preferred_language is not None:
                return preferred_language, False
        else:
            return chosen_language, False

        return "en", True

    @property
    def _client_theme(self) -> Tuple[str, bool]:
        """
        Which color theme the user prefers
        
        :return theme: The client theme
        :return is_default: Is default Value
        """

        theme_from_args = request.args.get("theme")
        theme_from_cookies = request.cookies.get("theme")

        theme = (
            theme_from_args
            if theme_from_args in THEMES
            else (
                theme_from_cookies
                if theme_from_cookies in THEMES
                else None
            )
        )

        if theme is None:
            return "light", True

        return theme, False

    def _set_client_information(self) -> None:
        "Sets the client information for certain requests"

        client_ip = get_client_ip(request)
        client_user_agent = request.user_agent.string

        client_ip_info = None
        if client_ip is not None:
            client_ip_info = get_ip_info(client_ip)

        g.client_ip = client_ip
        g.client_ip_info = client_ip_info
        g.client_user_agent = client_user_agent

    def _authenticate(self) -> None:
        if self._need_authentication:
            current_url = get_url_from_request(request)
            current_url_without_args = remove_args_from_url(current_url)
            current_args = current_url.replace(current_url_without_args, "")

            special_char = '?' if not '?' in current_args else '&'
            return redirect('/login' + current_args + special_char + 'return=' + request.path)

    def _login_route(self):
        signature = get_random_item(SIGNATURES, 60)

        return_url = '/'
        if request.args.get('return') is not None:
            if re.match(r'^/[^?]*\??[^?]*$', request.args.get('return')):
                return_url = request.args.get('return')

        response = {"error": None, "error_fields": [], "content": {}}

        name, password, stay = None, None, "0"

        if request.method.lower() == 'post':
            if return_url == '/' and request.form.get('return') is not None:
                if re.match(r'^/[^?]*\??[^?]*$', request.form.get('return')):
                    return_url = request.form.get('return')

            name = request.form.get('name')
            password = request.form.get('password')
            stay = request.form.get('stay', '0')
            stay = '1' if stay == '1' else '0'

            response = Validation.validate_login(
                request, self.user_system, self.captcha, self.use_captchas
            )
            if response is None:
                enc_data = self.enc.encode(
                    {'name': name, 'password': password,
                     'stay': stay, "return": return_url}
                )

                return render_template(
                    'twofactor-app.html', request, website_logo = self.website_logo,
                    website_name = self.website_name, data = enc_data,
                    response = {"error": None, "error_fields": [], "content": {}}
                )

        if not request.args.get('data') is None:
            dec_data = self.enc.decode(request.args.get('data'))
            if dec_data is not None:
                name, password, stay = dec_data.get('name'),\
                    dec_data.get('password'), dec_data.get('stay', '0')

            return_url = dec_data['return']

        return render_template(
            'login.html', request, website_logo = self.website_logo,
            website_name = self.website_name, signature = signature,
            return_url = return_url, response = response, name = name,
            password = password, stay = stay
        )

    def _login_api_route(self):
        response = {"error": None, "error_fields": [], "content": {}}

        if not request.is_json:
            return abort(400)
        if not isinstance(request.get_json(), dict):
            return abort(400)

        data = request.get_json()

        new_response = Validation.validate_login(
            request, self.user_system, self.captcha, self.use_captchas
        )

        if new_response is not None:
            return new_response

        return_url = "/"
        if data.get('return') is not None:
            if re.match(r'^/[^?]*\??[^?]*$', data.get('return')):
                return_url = data.get('return')

        name = data.get('name')
        password = data.get('password')
        stay = data.get('stay', '0')
        stay = '1' if stay == '1' else '0'

        enc_data = self.enc.encode(
            {"name": name, "password": password,
             "stay": stay, "return": return_url}
        )

        response['content']['new_html'] = render_template(
            'twofactor-app.html', request, website_logo = self.website_logo,
            website_name = self.website_name, data = enc_data, response = response
        )
        return response

    def _login_2fa_route(self):
        is_invalid_data = False
        if request.args.get('data') is None and request.form.get('data') is None:
            is_invalid_data = True
        else:
            dec_data = None
            data = None
            if request.args.get('data') is not None:
                data = request.args.get('data')
                dec_data = self.enc.decode(request.args.get('data'))
            if request.form.get('data') is not None and dec_data is None:
                data = request.form.get('data')
                dec_data = self.enc.decode(request.form.get('data'))

            if dec_data is None:
                is_invalid_data = True

        if is_invalid_data:
            current_url = get_url_from_request(request)
            current_url_without_args = remove_args_from_url(current_url)
            current_args = current_url.replace(current_url_without_args, "")
            return redirect('/login' + current_args)

        response = {"error": None, "error_fields": [], "content": {}}
        totp = None

        if request.method.lower() == 'post':
            user_data = request.form.get('data')
            totp = request.form.get('totp')

            response = Validation.validate_login_2fa(
                request, self.user_system, self.captcha, self.enc,
                self.totp, self.use_captchas
            )

            if response is None:
                dec_data = self.enc.decode(user_data)

                # FIXME: Create Session
                special_char = '?' if not '?' in dec_data['return'] else '&'
                redirection_url = dec_data['return'] + special_char + 'session=yeah!'

                response = make_response(redirect(redirection_url))
                if dec_data['stay'] == '1':
                    response.set_cookie('Session', 'yeah!', max_age = 31536000)
                return response

        return render_template(
            'twofactor-app.html', request, website_logo = self.website_logo,
            website_name = self.website_name, data = data, response = response,
            totp = totp
        )

    def _login_2fa_api_route(self):
        response = {"error": None, "error_fields": [], "content": {}}

        if not request.is_json:
            return abort(400)
        if not isinstance(request.get_json(), dict):
            return abort(400)

        data: dict = request.get_json()
        user_data = data.get('data')

        new_response = Validation.validate_login_2fa(
            request, self.user_system, self.captcha, self.enc,
            self.totp, self.use_captchas
        )
        if new_response is not None:
            return new_response

        dec_data = self.enc.decode(user_data)

        # FIXME: Create Session
        response['content']['session'] = 'yeah!'
        response['content']['stay'] = dec_data['stay']
        special_char = '?' if not '?' in dec_data['return'] else '&'
        response['content']['redirection_url'] =\
            dec_data['return'] + special_char + 'session=yeah!'
        return response
