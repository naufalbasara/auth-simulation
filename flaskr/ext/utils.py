import logging, tensorflow as tf, cv2, numpy as np

from datetime import datetime

def load_model(model_path):
    return tf.keras.models.load_model(model_path)

def get_field(req):
    """Handle data input from client."""
    obj = {}

    try:
        if str(req.content_type).lower() == 'application/json':
            """Handle raw JSON data"""
            obj=req.get_json()
            return obj
        else:
            """Handle raw FORM data"""
            obj = {**req.form}
            return obj
    except Exception as error:
        print(error)

    return obj

def detect_faces(img):
    """Detect faces using haarcascade classifier from OpenCV, returning coordinates for bounding box"""
    face_cascade = cv2.CascadeClassifier('flaskr/public/haarcascade_frontalface_default.xml')
    faces = face_cascade.detectMultiScale(img, scaleFactor=1.3, minNeighbors=5)
    for (x,y,w,h) in faces:
        return x,y,w,h


def get_vector(image_dir, classifier, detect_faces):
    img = cv2.imread(image_dir, cv2.IMREAD_COLOR)
    try:
        x,y,w,h = detect_faces(img)
        cropped = img[y-125:y+h+75, x-125:x+w+75]
    except:
        logging.warning(f"Face not found in {image_dir}")
        cropped = img

    resized = cv2.resize(cropped, (224, 224), interpolation=cv2.INTER_AREA)
    preprocessed = np.expand_dims(resized, 0)
    user_vector = classifier.predict(preprocessed, verbose=0)

    return user_vector