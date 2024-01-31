import pkg_resources
import os
from typing import Optional
from flask import Flask, g, request
from .utils import JSON, error, convert_image_to_base64, generate_website_logo, is_current_route,\
                   get_client_ip, get_ip_info

DATA_DIR = pkg_resources.resource_filename('flask_AuthGenius', 'data')
ASSETS_DIR = pkg_resources.resource_filename('flask_AuthGenius', 'assets')

if not os.path.isdir(DATA_DIR):
    os.mkdir(DATA_DIR)

LANGUAGES = JSON.load(os.path.join(ASSETS_DIR, "languages.json"))
LANGUAGE_CODES = [language["code"] for language in LANGUAGES]

GENERATED_LOGO_PATH = os.path.join(DATA_DIR, "generated-logo.txt")

class flask_AuthGenius:
    "Shows the user a login prompt on certain routes"

    def __init__(
            self, app: Flask,
            website_name: str, website_logo_path: Optional[str] = None,
            authentication_routes: Optional[list] = None, popup_routes: Optional[list] = None) -> None:
        """
        :param website_name: The name of your website
        :param website_logo_path: A path to a file that contains a small logo which is displayed on all pages next to the website name (Optional)
        :param authentication_routes: Routes or paths where authorization is required. (Optional)
        :param popup_routes: Routes or paths where a popup login window is shown. (Optional)
        """

        if app is None:
            error("The Flask app cannot be None.")
            return

        self.app = app
        self.website_name = website_name

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
        self.authentication_routes = authentication_routes if isinstance(authentication_routes, list) else []
        self.popup_routes = popup_routes if isinstance(popup_routes, list) else []
    
    @property
    def _need_authentication(self) -> bool:
        "Whether authorization is required on the current route"

        for route in self.authentication_routes:
            if is_current_route(route):
                return True
        return False
    
    @property
    def _add_popup(self) -> bool:
        "Whether a pop-up window should be inserted on the current page"
        
        if self._need_authentication:
            return False
        
        for route in self.popup_routes:
            if is_current_route(route):
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
    def _client_language(self) -> bool:
        "Which language the client prefers"

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

            if preferred_language != None:
                return preferred_language

        return "en"
    
    @property
    def _client_theme(self) -> bool:
        "Which color theme the user prefers"

        THEMES = ["light", "dark"]

        theme_from_args = request.args.get("theme")
        theme_from_cookies = request.cookies.get("theme")

        theme = (
            theme_from_args
            if theme_from_args in THEMES
            else (
                theme_from_cookies
                if theme_from_cookies in THEMES
                else "light"
            )
        )

        return theme
    
    def _set_client_information(self) -> None:
        "Sets the client information for certain requests"

        client_ip = get_client_ip()
        client_user_agent = request.user_agent.string

        client_ip_info = None
        if client_ip is not None:
            client_ip_info = get_ip_info(client_ip)

        g.client_ip = client_ip
        g.client_ip_info = client_ip_info
        g.client_user_agent = client_user_agent