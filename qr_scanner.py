import cv2
from pyzbar.pyzbar import decode

def scan_qr_code(image_path):
    """
    Scans a QR code from an image file or webcam and extracts the URL.
    """
    if image_path:
      
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
        
    else:
        # Open webcam to scan QR code
        cap = cv2.VideoCapture(0)
        print("Show the QR code to the camera...")
        while True:
            ret, frame = cap.read()
            if not ret:
                print("Failed to capture image")
                break

            decoded_objects = decode(frame)
            for obj in decoded_objects:
                url = obj.data.decode("utf-8")
                print(f"Extracted URL: {url}")
                cap.release()
                cv2.destroyAllWindows()
                return url
            
            cv2.imshow("QR Scanner", frame)

            # Press 'q' to exit scanning
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break

        cap.release()
        cv2.destroyAllWindows()
        return None

# Example usage
if __name__ == "__main__":
    #extracted_url = scan_qr_code()  # Use webcam
    extracted_url = scan_qr_code("image.png")  # Use an image file
    
    if extracted_url:
        print(f"Extracted URL: {extracted_url}")
    else:
        print("No QR code detected.")
