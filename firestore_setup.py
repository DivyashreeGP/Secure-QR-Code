import firebase_admin
from firebase_admin import credentials, firestore

# Initialize Firebase
cred = credentials.Certificate(r"C:/Users/Divyashree G P/OneDrive/Documents/keys/serviceAccountKey.json")  # Update the path!
firebase_admin.initialize_app(cred)

# Initialize Firestore
db = firestore.client()
print("Firestore initialized successfully!")
