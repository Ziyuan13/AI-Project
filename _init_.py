from django.shortcuts import render
from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import urllib.request
import os
import reddit

import tensorflow as tf
import cv2
from PIL import Image, ImageOps
import numpy as np



app = Flask(__name__)
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    #if form.validate_on_submit():
    user = User.query.filter_by(username=form.username.data).first()
    print(user)
    print(form.username.data)
    print(form.username)
    print(form)
    if user:
        if bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('home2'))
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/')
def home():
    return render_template('login.html')


@app.route('/home')
def home2():
    return render_template('home.html')


@app.route('/blog')
def blog():
    my_reddit_instance = reddit.create_reddit_instance()
    my_ten_hot_list = reddit.ten_top_titles(my_reddit_instance, 'ALBA_Ewaste')
    return render_template('blog.html', posts=my_ten_hot_list, subreddit='ALBA E-Waste')


ALLOWED_EXTENSIONS = set({'png', 'jpg', 'jpeg', 'gif', 'bmp'})
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/predictImage', methods=['GET'])
def getImage():
    return render_template('prediction.html')

@app.route('/predictImage', methods=['POST'])
def predictImage():
    imagefile = request.files['imagefile']
    image_path = "./prediction/" + imagefile.filename
    imagefile.save(image_path)
    print(image_path)

    np.set_printoptions(suppress=True)
    model = tf.keras.models.load_model('waste_classifier.h5')
    data = np.ndarray(shape=(1, 128, 128, 3), dtype=np.float32)

    image_filename = image_path
    image = Image.open(image_filename)
    size = (128, 128)
    image = ImageOps.fit(image, size, Image.ANTIALIAS)
    image_array = np.asarray(image)
    
    normalized_image_array = (image_array.astype(np.float32) / 127.0) - 1
    data[0] = normalized_image_array
    prediction = model.predict(data)
    classification = ["batteries", "clothes", "e-waste", "glass", "light bulbs", "metal", "organic", "paper", "plastic"]
    i = 0
    for pos in prediction[0]:
        if max(prediction[0]) == pos:
            classified = classification[i]
            break
        else:
            i += 1
    return render_template('prediction.html', prediction=classified)


if __name__ == '__main__':
    app.run(port="5002", debug=True)
