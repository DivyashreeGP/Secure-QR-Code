from flask import Flask, request, jsonify, render_template
import numpy as np
import cv2
from pyzbar.pyzbar import decode
from huggingface_hub import hf_hub_download
import onnxruntime as ort

app = Flask(__name__)

# Load ONNX model once globally
REPO_ID = "pirocheto/phishing-url-detection"
FILENAME = "model.onnx"
model_path = hf_hub_download(repo_id=REPO_ID, filename=FILENAME)
sess = ort.InferenceSession(model_path, providers=["CPUExecutionProvider"])

def predict_url(url):
    # ONNX model expects an array of strings input
    inputs = np.array([url], dtype="str")
    results = sess.run(None, {"inputs": inputs})
    # Extract malicious score and convert to native float for JSON serialization
    score = float(results[1][0][1] * 100)
    return score

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files.get('file')
    if not file:
        return jsonify({"error": "No file uploaded"}), 400

    img_bytes = file.read()
    np_arr = np.frombuffer(img_bytes, np.uint8)
    image = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

    if image is None:
        return jsonify({"error": "Invalid image file"}), 400

    decoded = decode(image)
    if not decoded:
        return jsonify({"error": "No QR code found in image"}), 400

    url = decoded[0].data.decode("utf-8")
    try:
        score = predict_url(url)
    except Exception as e:
        return jsonify({"error": f"Prediction failed: {str(e)}"}), 500

    return jsonify({"url": url, "score": score})

@app.route('/predict-url', methods=['POST'])
def predict_url_route():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "No URL provided"}), 400

    url = data["url"]

    try:
        score = predict_url(url)
        return jsonify({"url": url, "score": score})
    except Exception as e:
        return jsonify({"error": "Prediction failed: " + str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
