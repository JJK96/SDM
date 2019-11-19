from flask import Flask, redirect, request
from werkzeug.utils import secure_filename
from consultant import ConsultantServer
import os

app = Flask(__name__)
consultant_server = ConsultantServer()


@app.route("/upload", methods=['POST'])
def upload():
    f = request.files.get('file')
    keywords = request.form['keywords']
    client = request.form['client']
    consultant_server.consultant.upload_file(f.read(), None) #TODO should throw an error if no client id.
    return 'upload successful'


@app.route("/search", methods=['GET'])
def search():
    query = request.args['q']
    query = query.split(' ')
    try:
        result = consultant_server.consultant.get_files_by_keywords(query) # TODO make search for client.id
    except KeyError as k:
        result = "Search word {} is not a keyword".format(str(k))
    except Exception as e:
        result = str(e)
    return str(result)


@app.route("/")
def home():
    return redirect('static/consultant.html')


if __name__ == "__main__":
    app.run(debug=False)
