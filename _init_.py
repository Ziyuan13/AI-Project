from cgitb import reset
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
    return render_template('home.html')



# @app.route('/')
# def home():
#     return render_template('login.html')

# @app.route('/home')
# def home3():
   
#     return render_template('home.html', user=session['user'])
    
#     return redirect(url_for('login'))

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

# ziyuan model
model1 = tf.keras.models.load_model('ewaste_model.h5')

# patrick model
model2 = tf.keras.models.load_model('mymodel.hdf5')

@app.route('/predictImage', methods=['GET'])
def predictImage():
    return render_template('prediction.html')


user = {'point': 0}
@app.route('/predict', methods=['POST'])
def predict():

    #load Image to be predicted
    imagefile = request.files['imagefile']
    image_path = "./prediction/" + imagefile.filename
    imagefile.save(image_path)
    print(image_path)

    # Disable scientific notation for clarity
    np.set_printoptions(suppress=True)

    # Create the array of the right shape to feed into the keras model
    # The 'length' or number of images you can put into the array is determined by the first position in the shape tuple, in this case 1.
    data = np.ndarray(shape=(1, 256, 256, 3), dtype=np.float32)

    # path to your image
    image_filename = image_path
    image = Image.open(image_filename)

    # resize the image to a 256x256 with the same strategy as in TM2:
    # resizing the image to be at least 256x256 and then cropping from the center
    size = (256, 256)
    image = ImageOps.fit(image, size, Image.ANTIALIAS)

    # turn the image into a numpy array
    image_array = np.asarray(image)

    # Load the image into the array
    data[0] = image_array

    # run the inference
    prediction1 = model1.predict(data)
    prediction2 = model2.predict(data)

    # points system
    target1 = ["Aircon", "Hairdryer", "Network Hub",
              "Television", "Washing Machine"]
    target2 = ["Battery", "Light Bulb", "PC Monitor",
               "Personal Mobility Device"]
    object_dict = {"Aircon": 400, "Hairdryer": 100,
                   "Network Hub": 150, "Television": 300, "Washing Machine": 500, "Battery": 25, "Light Bulb": 50, "PC Monitor": 125,
                   "Personal Mobility Device": 250}
    
    i = 0
    if max(prediction1[0]) > max(prediction2[0]):
        print(max(prediction1[0]))
        pred_thres = max(prediction1[0])
        if pred_thres > 0.85:
            for pos in prediction1[0]:
                if pred_thres == pos:
                    regulated = "True"
                    result = target1[i]
                    print(result)
                    getpoints = object_dict[result]

                    user_points = user.get('points')
                    if user_points == None:
                        user_points = getpoints
                        user.update({"points": user_points})
                    else:
                        user_points = user.get('points') + getpoints
                        user.update({"points": user_points})
                    break
                else:
                    i += 1
        else:
            regulated = "False"
            result = ''
            getpoints = 0
            user_points = user.get('points')


    elif max(prediction1[0]) < max(prediction2[0]):
        print(max(prediction2[0]))
        pred_thres = max(prediction2[0])
        if pred_thres > 0.85:
            for pos in prediction1[0]:
                if pred_thres == pos:
                    regulated = "True"
                    result = target2[i]
                    print(result)
                    getpoints = object_dict[result]

                    user_points = user.get('points')
                    if user_points == None:
                        user_points = getpoints
                        user.update({"points": user_points})
                    else:
                        user_points = user.get('points') + getpoints
                        user.update({"points": user_points})
                    break
                else:
                    i += 1
        else:
            regulated = "False"
            result = ''
            getpoints = 0
            user_points = user.get('points')
        
    return render_template('prediction.html', regulated=regulated, prediction=result, given=getpoints, points=user_points)

if __name__ == '__main__':
    app.run(port="5002", debug=True)
