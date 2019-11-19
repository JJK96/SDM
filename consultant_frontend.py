from flask import Flask, redirect, request, render_template
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
    print(request.args)
    query = request.args['query']
    query = query.split(' ')
    client_id = request.args['clientID']
    try:
        result = consultant_server.consultant.get_files_by_keywords(query) # TODO make search for client.id
    except KeyError as k:
        result = "Search word {} is not a keyword".format(str(k))
    except Exception as e:
        result = str(e)
    return str(result)


@app.route("/")
def home():
    return render_template('consultant.html', clients=consultant_server.get_clients())


if __name__ == "__main__":
    app.run(debug=False)
