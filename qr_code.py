import cv2
from pyzbar.pyzbar import decode

def scan_qr_code(image_path):
    """Scans a QR code from an image file and extracts the URL."""
    image = cv2.imread(image_path)
    if image is None:
        print("❌ Unable to read the image. Please check the file path.")
        return None

    decoded_objects = decode(image)
    if not decoded_objects:
        print("❌ No QR code detected in the image.")
        return None
    
    for obj in decoded_objects:
        url = obj.data.decode("utf-8")
        print(f"Extracted URL: {url}")
        return url

# Example usage
if __name__ == "__main__":
    extracted_url = scan_qr_code("image.png")  # Specify your image file path here
    if extracted_url:
        print(f"Extracted URL: {extracted_url}")
    else:
        print("No QR code detected.")
