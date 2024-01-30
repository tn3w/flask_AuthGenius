import pkg_resources
import os
from typing import Optional
from .utils import convert_image_to_base64, generate_website_logo

DATA_DIR = pkg_resources.resource_filename('flask_AuthGenius', 'data')

if not os.path.isdir(DATA_DIR):
    os.mkdir(DATA_DIR)

GENERATED_LOGO_PATH = os.path.join(DATA_DIR, "generated-logo.txt")

class flask_AuthGenius:
    "Shows the user a login prompt on certain routes"

    def __init__(self, website_name: str, website_logo_path: Optional[str] = None) -> None:
        """
        :param website_name: The name of your website
        :param website_logo_path: A path to a file that contains a small logo which is displayed on all pages next to the website name (Optional)
        """

        self.website_name = website_name

        website_logo = None
        if website_logo_path is not None:
            if os.path.isfile(website_logo_path):
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