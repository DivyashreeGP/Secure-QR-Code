import cv2
import numpy as np
from pyzbar.pyzbar import decode
from huggingface_hub import hf_hub_download
import onnxruntime as ort
from tkinter import Tk, filedialog, messagebox, Button, Label
import webbrowser

# Load ONNX model
REPO_ID = "pirocheto/phishing-url-detection"
FILENAME = "model.onnx"
model_path = hf_hub_download(repo_id=REPO_ID, filename=FILENAME)
sess = ort.InferenceSession(model_path, providers=["CPUExecutionProvider"])

# Predict function
def predict_url(url):
    inputs = np.array([url], dtype="str")
    results = sess.run(None, {"inputs": inputs})[1]
    score = results[0][1] * 100
    return score

# Handle result
def handle_result(url, score):
    if score > 80:
        messagebox.showerror("Blocked - Highly Malicious URL",
            f"❌ The scanned URL is **very likely** malicious!\n\nURL: {url}\nLikelihood: {score:.2f}%\n\nAccess blocked.")
    elif score > 50:
        choice = messagebox.askyesno("⚠️ Warning - Possibly Malicious",
            f"This URL **may be unsafe**!\n\nURL: {url}\nLikelihood: {score:.2f}%\n\nDo you want to continue?")
        if choice:
            webbrowser.open(url)
        else:
            messagebox.showinfo("Aborted", "You chose not to proceed.")
    elif score > 20:
        messagebox.showwarning("Caution - Suspicious URL",
            f"This URL is **somewhat suspicious**.\n\nURL: {url}\nLikelihood: {score:.2f}%\n\nProceeding with caution...")
        webbrowser.open(url)
    else:
        webbrowser.open(url)

# Scan from webcam
def scan_from_camera():
    cap = cv2.VideoCapture(0)
    scanned_urls = set()

    while True:
        ret, frame = cap.read()
        if not ret:
            continue

        decoded_objects = decode(frame)
        for qr in decoded_objects:
            url = qr.data.decode('utf-8')
            if url not in scanned_urls:
                scanned_urls.add(url)
                cap.release()
                cv2.destroyAllWindows()
                score = predict_url(url)
                handle_result(url, score)
                return

        cv2.imshow("Camera - Press 'q' to quit", frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    cap.release()
    cv2.destroyAllWindows()

# Scan from uploaded image
def scan_from_image():
    filepath = filedialog.askopenfilename(title="Select an Image",
                                          filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp")])
    if not filepath:
        return

    image = cv2.imread(filepath)
    decoded_objects = decode(image)

    if not decoded_objects:
        messagebox.showerror("Error", "No QR code found in the image.")
        return

    url = decoded_objects[0].data.decode('utf-8')
    score = predict_url(url)
    handle_result(url, score)

# GUI with choice
def launch_gui():
    root = Tk()
    root.title("Secure QR Code Scanner")
    root.geometry("400x200")

    Label(root, text="Choose input method:", font=("Helvetica", 14)).pack(pady=20)

    Button(root, text="📷 Scan from Camera", font=("Helvetica", 12), command=lambda: [root.destroy(), scan_from_camera(), launch_gui()]).pack(pady=10)
    Button(root, text="🖼️ Upload QR Image", font=("Helvetica", 12), command=lambda: [root.destroy(), scan_from_image(), launch_gui()]).pack(pady=10)

    root.mainloop()

# Entry point
if __name__ == "__main__":
    launch_gui()
