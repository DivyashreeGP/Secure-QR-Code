# 🔐 Secure QR Code Scanner

[![Python](https://img.shields.io/badge/Python-3.10-blue?logo=python)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![GUI](https://img.shields.io/badge/GUI-Tkinter-orange)]()
[![ML Integration](https://img.shields.io/badge/Model-HuggingFace-purple?logo=huggingface)](https://huggingface.co/)

The Secure QR Code Scanner project aims to provide a reliable and efficient solution to detect malicious or unsafe QR codes, enhancing user security when scanning QR codes in everyday life. The core machine learning model, responsible for analyzing and classifying QR codes, was developed collaboratively by the team, involving data collection, feature engineering, and model training to ensure high accuracy and robustness. To make the model easily accessible and scalable, we integrated it with Hugging Face’s model hosting platform, allowing seamless deployment and inference through their API. The application combines this powerful backend with a user-friendly interface, providing a secure and smooth scanning experience
## 📌 Features

- ✅ Real-time QR Code scanning using webcam
- ✅ Extracts and validates embedded URLs
- ✅ Uses ML-based phishing detection model
- ✅ Model hosted on Hugging Face
- ✅ User-friendly desktop GUI using **Tkinter**
- ✅ Alerts users for **malicious** or **suspicious** links

---

## 🧠 Tech Stack

| Component       | Technology         |
|----------------|--------------------|
| Language        | Python             |
| ML Model        | Scikit-learn       |
| Inference Host  | Hugging Face Hub   |
| GUI             | Tkinter            |
| QR Scanning     | OpenCV, pyzbar     |
| Data Handling   | Pandas, NumPy      |

---

## 📸 Screenshots

### 🔍 QR Scanner Window
`(Insert image: screenshots/qr_scanner.png)`

### 🛑 Malicious URL Warning
`(Insert image: screenshots/warning_popup.png)`

---

## 🚀 Getting Started

### 1. Clone the repository

git clone https://github.com/DivyashreeGP/Secure-QR-code-Scanner.git
cd Secure-QR-code-Scanner

### 2. Set up a virtual environment

python -m venv venv
venv\Scripts\activate # On Windows
source venv/bin/activate # On Linux/Mac

### 3. Install dependencies

pip install -r requirements.txt

### 4. Run the application

python qr_scanner.py

---

## 🧪 How It Works

1. The app scans QR codes using your webcam.
2. Extracted URL is sent to a **phishing detection model** hosted on Hugging Face.
3. The model returns the prediction (safe or malicious).
4. The user is notified instantly via popup alerts.

> 🔒 This ensures better security when scanning unknown QR codes.

---

## 🤖 Model Info

- **Dataset:** URLs labeled as safe or phishing  
- **Features:** IP usage, URL length, suspicious keywords, etc.  
- **Algorithm:** Random Forest / SVM  
- **Model Host:** [Hugging Face Model Link](https://huggingface.co/your-model-name) ← *(Replace with actual model link)*

---

## 📁 Project Structure

Secure-QR-code-Scanner/
├── model/ # Model files and training scripts
├── screenshots/ # UI screenshots
├── qr_scanner.py # Main app
├── requirements.txt
└── README.md

---

## 🔐 Security Notes

- Secrets and credentials removed using `git filter-repo`
- Model securely hosted on Hugging Face
- Followed GitHub's push protection rules

---
---

## 🌐 Web Application

The **Secure QR Code Scanner** is also available as a responsive **Web Application**, built using **HTML**, **Bootstrap**, **JavaScript**, and **Flask**. It enables users to **scan QR codes directly using their camera** or **upload images** to check the safety of embedded URLs using a trained machine learning model.

---

### 🚀 Features

- 📸 **Live Camera Scan** using ZXing
- 🖼️ **Image Upload Mode** for scanning QR codes from files
- ⚠️ **Smart Threat Detection & Redirection**:
  - 🔴 Blocks redirection for highly malicious URLs
  - 🟠 Asks user confirmation for suspicious links
  - 🟡 Warns and redirects for moderately risky URLs
  - 🟢 Directly redirects safe URLs
- 🧠 Powered by an **ONNX phishing URL detection model**
- 💡 Clean and responsive UI with **Dark Mode**

---

### 🖼️ Screenshots

<!-- Add screenshots in the 'screenshots/' directory and link them here -->
![Web App - Camera Scan Mode](screenshots/webapp-camera.png)
![Web App - Upload Image Mode](screenshots/webapp-upload.png)
![Web App - Threat Detection](screenshots/webapp-threat.png)

---

### ⚙️ How to Run Locally

```bash
git clone https://github.com/DivyashreeGP/Secure-QR-Code.git
cd Secure-QR-Code/Web-app
Activate virtual environment
python app.py
``` 
### 📈 Future Improvements

- [ ] Add QR code generation
- [ ] Logging of suspicious scans
- [ ] Firebase or MongoDB integration
- [ ] Build web version using Flask or React

---

## 👥 Contributors

| Name               | Role                                                   |
| ------------------ | ------------------------------------------------------ |
| **Divyashree G P** | Lead Developer, Model Builder, HuggingFace Integration |
| **Bhavani**        | Model Building, Data Collection                        |
| **Lakshmi B M**    | Idea Discussion, Initial Research                      |
| **Thanmai Nutheti**| Documentation Review, Testing Feedback                 |


## 📜 License

Licensed under the [MIT License](LICENSE).
