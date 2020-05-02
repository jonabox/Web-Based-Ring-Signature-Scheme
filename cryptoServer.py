from flask import Flask
from flask_cors import CORS

#set debug; setting to true allows for hot reload (automatic code deployment)
DEBUG = True

#instantiate app
app = Flask(__name__)

#enable CORS, used to communicate with UI server
#allows cross-origin requests on all routes, from any domain, protocol, or port
#TODO: secure for production!!
CORS(app, resources={r'/*': {'origins': '*'}})

@app.route('/')
def hello_world():
    return 'Hello, World!'

#key route
@app.route('/key')
def key():
    return 'key from crypto server: 12343432'

if __name__ == '__main__':
    #runs the server
    app.run(debug=DEBUG)