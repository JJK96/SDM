import os

from flask import Flask, redirect, request

from client import Client

app = Flask(__name__)
client = Client()


@app.route("/upload", methods=['POST'])
def upload():
    f = request.files.get('file')
    keywords = request.form['keywords']
    client.upload_file(f.read(), keywords)
    return 'upload successful'


@app.route("/search", methods=['GET'])
def search():
    query = request.args['q']
    query = query.split(' ')
    try:
        result = client.get_files_by_keywords(query)
    except KeyError as k:
        result = "Search word {} is not a keyword".format(str(k))
    except Exception as e:
        result = str(e)
        print(result)
    return str(result)


@app.route("/")
def home():
    return redirect('/static/client.html')


if __name__ == "__main__":
    app.run(debug=False, port=5001)
