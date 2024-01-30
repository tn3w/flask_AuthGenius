import sys

if __name__ == "__main__":
    sys.exit(2)

import pkg_resources
import os
from typing import Optional
from base64 import b64encode
import mimetypes
import random
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont

ASSETS_DIR = pkg_resources.resource_filename('flask_AuthGenius', 'assets')
FONTS = [
    os.path.join(ASSETS_DIR, "Comic_Sans_MS.ttf"),
    os.path.join(ASSETS_DIR, "Droid_Sans_Mono.ttf"),
    os.path.join(ASSETS_DIR, "Helvetica.ttf")
]

def convert_image_to_base64(file_path: str) -> Optional[str]:
    """
    Converts an image file into Base64 Web Format

    :param file_path: The path to the image file
    """
    try:
        with open(file_path, 'rb', encoding = "utf-8") as image_file:
            encoded_image = b64encode(image_file.read()).decode('utf-8')

            mime_type, _ = mimetypes.guess_type(file_path)
            if not mime_type:
                mime_type = 'application/octet-stream'

            data_url = f'data:{mime_type};base64,{encoded_image}'

            return data_url
    except:
        return None # FIXME: Error Handler

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
