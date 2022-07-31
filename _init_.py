from flask import Flask, render_template, request, redirect, url_for, send_from_directory,jsonify
import os
import reddit

import tensorflow as tf
import cv2
import numpy as np

app = Flask(__name__)
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
cnn = tf.keras.models.load_model('waste_classifier.h5')

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/videos')
def video():
    return render_template('videos.html')


@app.route('/photos')
def photos():
    return render_template('photos.html')


@app.route('/blogs')
def blogs():
    my_reddit_instance = reddit.create_reddit_instance()
    my_ten_hot_list = reddit.ten_top_titles(my_reddit_instance, 'ALBA_Ewaste')
    return render_template('blogs.html', posts=my_ten_hot_list, subreddit='ALBA_Ewaste')

@app.route('/classify_waste',methods=['POST'])
def classifywaste():
    filestream = request.files["file"].read()
    imgbytes = np.fromstring(filestream,np.uint8)
    img = cv2.imdecode(imgbytes,cv2.IMREAD_COLOR)

    img = cv2.resize(img, (224, 224))
    img = tf.keras.applications.cnn.preprocess_input(img)
    img = img.reshape(1, 224, 224, 3)

    predictions = cnn.predict(img)
    result = tf.keras.applications.cnn.decode_predictions(predictions, top=3)

    return jsonify({
        "result":[
            {"name":result[0][0][1], "score": float(result[0][0][2])},
            {"name": result[0][1][1], "score": float(result[0][1][2])},
            {"name": result[0][2][1], "score": float(result[0][2][2])},
        ]
    })





if __name__ == '__main__':
    app.run(port="5002", debug=True)
