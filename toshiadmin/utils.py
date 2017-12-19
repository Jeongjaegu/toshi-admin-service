import io
from PIL import Image, ExifTags
from PIL.JpegImagePlugin import get_sampling
import hashlib

assert ExifTags.TAGS[0x0112] == "Orientation"
EXIF_ORIENTATION = 0x0112

def process_image(data, mime_type):
    stream = io.BytesIO(data)
    try:
        img = Image.open(stream)
    except OSError:
        raise ValueError('Invalid image data')

    if mime_type == 'image/jpeg' and img.format == 'JPEG':
        format = "JPEG"
        subsampling = 'keep'
        # check exif information for orientation
        if hasattr(img, '_getexif'):
            x = img._getexif()
            if x and EXIF_ORIENTATION in x and x[EXIF_ORIENTATION] > 1 and x[EXIF_ORIENTATION] < 9:
                orientation = x[EXIF_ORIENTATION]
                subsampling = get_sampling(img)
                if orientation == 2:
                    # Vertical Mirror
                    img = img.transpose(Image.FLIP_LEFT_RIGHT)
                elif orientation == 3:
                    # Rotation 180°
                    img = img.transpose(Image.ROTATE_180)
                elif orientation == 4:
                    # Horizontal Im
                    img = img.transpose(Image.FLIP_TOP_BOTTOM)
                elif orientation == 5:
                    # Horizontal Im + Rotation 90° CCW
                    img = img.transpose(Image.FLIP_TOP_BOTTOM).transpose(Image.ROTATE_90)
                elif orientation == 6:
                    # Rotation 270°
                    img = img.transpose(Image.ROTATE_270)
                elif orientation == 7:
                    # Horizontal Im + Rotation 270°
                    img = img.transpose(Image.FLIP_TOP_BOTTOM).transpose(Image.ROTATE_270)
                elif orientation == 8:
                    # Rotation 90°
                    img = img.transpose(Image.ROTATE_90)
        save_kwargs = {'subsampling': subsampling, 'quality': 85}
    elif mime_type == 'image/png' and img.format == 'PNG':
        format = "PNG"
        save_kwargs = {'icc_profile': img.info.get("icc_profile")}
    else:
        raise ValueError('Unsupported image format')

    if img.size[0] > 512 or img.size[1] > 512:
        img.thumbnail((512, 512))

    stream = io.BytesIO()
    img.save(stream, format=format, optimize=True, **save_kwargs)

    data = stream.getbuffer().tobytes()
    hasher = hashlib.md5()
    hasher.update(data)
    cache_hash = hasher.hexdigest()

    return data, cache_hash, format
