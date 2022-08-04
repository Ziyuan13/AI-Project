from mimetypes import init
import pathlib
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session, abort, g, jsonify 
#from flask import Flask, jsonify, render_template, request, redirect, session, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from google_auth_oauthlib.flow import Flow
from authlib.integrations.flask_client import OAuth

from google.oauth2 import id_token


import os
import reddit
import requests
import tensorflow as tf
import cv2
from PIL import Image, ImageOps
import numpy as np

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

app = Flask(__name__)
app.secret_key= "0934gj3ng403nb"
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'


app.config['GOOGLE_CLIENT_ID'] = "685939880249-1qsaqotjhscu1b2ig7aipckma4b9vkou.apps.googleusercontent.com"
app.config['GOOGLE_CLIENT_SECRET'] = "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"

oauth = OAuth(app)
google = oauth.register(
    name = 'google',
    client_id = app.config["GOOGLE_CLIENT_ID"],
    client_secret = app.config["GOOGLE_CLIENT_SECRET"],
    access_token_url = 'https://accounts.google.com/o/oauth2/token',
    access_token_params = None,
    authorize_url = 'https://accounts.google.com/o/oauth2/auth',
    authorize_params = None,
    api_base_url = 'https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint = 'https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using openId to fetch user info
    client_kwargs = {'scope': 'openid email profile'},
    jwks_uri = "https://www.googleapis.com/oauth2/v3/certs",
)




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
 
 

@app.route('/login/google')
def google_login():
    google = oauth.create_client('google')  # create the google oauth client
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)    
            
            
x = ""
# Google authorize route
@app.route('/login/google/authorize')
def google_authorize():
    google = oauth.create_client('google')
    token = google.authorize_access_token()
    resp = google.get('userinfo').json()
    x = resp
    print(f"\n{resp}\n")
    return redirect(url_for('home4'))
   
   
    

   
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    
    form = LoginForm(request.form)
    if request.method == 'POST':
        session.pop('user', None)
        print("hello")
        user = User.query.filter_by(username=form.username.data).first()
        print(request.form['password'])
        print(user.password)
        if request.form['password'] == user.password :
            session['user'] = request.form['username']
            print("hi")
    
            
                #if form.validate_on_submit():
           # user = User.query.filter_by(username=form.username.data).first()
                
            if user:
                print("bye")
                #if bcrypt.check_password_hash(user.password, form.password.data):
                print("ok")
                login_user(user)
                return redirect(url_for('home3'))
            
    return render_template('login.html', form=form)




@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)

    #if form.validate_on_submit():
    hashed_password = (form.password.data)
    new_user = User(username=form.username.data, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('login'))

    #return render_template('register.html', form=form)

    return render_template('register.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    session.pop('user', None)
    logout_user()
    return redirect(url_for('login'))







@app.route('/')
def home():
    return render_template('login.html')

@app.route('/home')
def home3():
   
    return render_template('home.html', user=session['user'])
    
    return redirect(url_for('login'))

@app.route('/home')
def home4():
   
    return render_template('home.html')
    
    return redirect(url_for('login'))


@app.before_request
def before_request():
    g.user = None
    if 'user' in session:
        g.user = session['user']


@app.route('/blog')
def blog():
    my_reddit_instance = reddit.create_reddit_instance()
    my_ten_hot_list = reddit.ten_top_titles(my_reddit_instance, 'ALBA_Ewaste')
    return render_template('blog.html', posts=my_ten_hot_list, subreddit='ALBA E-Waste')


model = tf.keras.models.load_model('waste_classifier.h5')
@app.route('/predictImage', methods=['GET','POST'])
def predictImage():
    if request.method == 'POST':
        imagefile = request.files['imagefile']
        image_path = "./prediction/" + imagefile.filename
        imagefile.save(image_path)
        print(image_path)

        np.set_printoptions(suppress=True)
        data = np.ndarray(shape=(1, 128, 128, 3), dtype=np.float32)

        image_filename = image_path
        image = Image.open(image_filename)
        size = (128, 128)
        image = ImageOps.fit(image, size, Image.ANTIALIAS)
        image_array = np.asarray(image)
        
        normalized_image_array = (image_array.astype(np.float32) / 127.0) - 1
        data[0] = normalized_image_array
        prediction = model.predict(data)
        target = ["batteries", "clothes", "e-waste", "glass", "light bulbs", "metal", "organic", "paper", "plastic"]
        i = 0
        for pos in prediction[0]:
            if max(prediction[0]) == pos:
                result = target[i]
                break
            else:
                i += 1
        return render_template('prediction.html', prediction=result)
    else:
        return render_template('prediction.html')

# @app.route('/predictImage', methods=['POST'])
# def predictImage():
#     # Load image from file
#     filestream = request.files['file'].read()
#     imgbytes = np.fromstring(filestream, np.unit8)
#     img = cv2.imdecode(imgbytes, cv2.IMREAD_COLOR)

#     # Preprocess the image
#     img = cv2.resize(img, (128, 128))
#     img = tf.keras.applications.vgg16.preprocess_input(img)
#     img = img.reshape(1, 128, 128, 3)

#     # Predict and return result
#     prediction = model.predict(img)
#     result = tf.keras.applications.vgg16.decode_predictions(prediction, top=3)
        
#     return jsonify({"result": [
#         {"name": result[0][0][1], "score" : float(result[0][0][2])},
#         {"name": result[0][1][1], "score": float(result[0][1][2])},
#         {"name": result[0][2][1], "score" : float(result[0][2][2])}
#     ]})

if __name__ == '__main__':
    app.run(port="5002", debug=False)
