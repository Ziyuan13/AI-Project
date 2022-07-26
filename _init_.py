from flask import Flask, render_template, request, redirect, url_for, send_from_directory
import os

app = Flask(__name__)
APP_ROOT = os.path.dirname(os.path.abspath(__file__))


@app.route('/')
def home():
    return render_template('home.html')


if __name__ == '__main__':
    app.run(port="5001", debug=True)