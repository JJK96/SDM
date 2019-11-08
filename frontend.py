from flask import Flask, redirect, request
from werkzeug.utils import secure_filename
from client import client
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route("/upload", methods=['POST'])
def upload():
    f = request.files['file']
    filename = secure_filename(f.filename)
    f.save(os.path.join(UPLOAD_FOLDER, filename)) 
    client.upload_file(filename)
    return 'upload successful'

@app.route("/search", methods=['GET'])
def search():
    query = request.args['q']
    query = query.split(' ')
    try:
        result = client.get_files_by_keywords(query)
    except Exception as e:
        result = str(e)
    return str(result)

@app.route("/")
def home():
    return redirect('/static/index.html')

if __name__ == "__main__":
    app.run(debug=True)
