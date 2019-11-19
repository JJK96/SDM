from flask import Flask, redirect, request
from werkzeug.utils import secure_filename
from consultant import ConsultantServer
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
consultant_server = ConsultantServer()


@app.route("/upload", methods=['POST'])
def upload():
    f = request.files.get('file')
    keywords = request.form['keywords']
    filename = secure_filename(f.filename)
    fullname = os.path.join(UPLOAD_FOLDER, filename)
    f.save(fullname)
    consultant_server.consultant.upload_file(fullname)
    return 'upload successful'


@app.route("/search", methods=['GET'])
def search():
    query = request.args['q']
    query = query.split(' ')
    try:
        result = consultant_server.consultant.get_files_by_keywords(query)
    except KeyError as k:
        result = "Search word {} is not a keyword".format(str(k))
    except Exception as e:
        result = str(e)
    return str(result)


@app.route("/")
def home():
    return redirect('/static/index.html')


if __name__ == "__main__":
    app.run(debug=True)
