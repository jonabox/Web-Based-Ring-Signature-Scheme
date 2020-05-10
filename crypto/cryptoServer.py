import os
from sign_main import sign

from flask import Flask, request, redirect, url_for
from flask_cors import CORS

# configure file uploads
if not os.path.exists('../uploads'):
    os.makedirs('../uploads')
UPLOAD_FOLDER = '../uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'pem'}

# set debug; setting to true allows for hot reload (automatic code deployment)
DEBUG = True

# instantiate app
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# enable CORS, used to communicate with UI server
# allows cross-origin requests on all routes, from any domain, protocol, or port
# TODO: secure for production!!
CORS(app, resources={r'/*': {'origins': '*'}})


@app.route('/')
def hello_world():
    return 'Hello, World!'

# key route
@app.route('/key')
def key():
    return 'key from crypto server: 12343432'


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/signature', methods=['POST'])
def signature():
    if request.method == 'POST':
        print(request.form)
        # check if the post request has the file part
        if 'index' not in request.form:
            return 'No valid index', 400
        if 'message' not in request.form:
            return 'No valid message', 400
        if 'password' not in request.form:
            return 'No valid password', 400
        index = request.form['index']
        message = request.form['message']
        password = request.form['password']
        sign(message, "../uploads/public_keys.pem", index, "../uploads/secret_key.pem", "testOutput.txt", password )
        print("done")
        return "message has been signed!"
        

@app.route('/secret_key', methods=['GET', 'POST'])
def upload_sk():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'files' not in request.files:
            return 'No valid file', 400
        file = request.files['files']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            return 'No selected file', 400
        if file and allowed_file(file.filename):
            filename = file.filename
            file.save(os.path.join(
                app.config['UPLOAD_FOLDER'], "secret_key.pem"))
            return redirect(url_for('upload_file',
                                    filename=filename))
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''


@app.route('/public_keys', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'files' not in request.files:
            return 'Not a valid file', 400
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            return 'No selected file', 400
        if file and allowed_file(file.filename):
            filename = file.filename
            file.save(os.path.join(
                app.config['UPLOAD_FOLDER'], "public_keys.pem"))
            return redirect(url_for('upload_file',
                                    filename=filename))
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''


if __name__ == '__main__':
    # runs the server
    app.run(debug=DEBUG)
