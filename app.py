from flask import Flask
import os

app = Flask(__name__)

app.secret_key     = os.environ.get('SECRET_KEY')

app.smsgate_server = os.environ.get('SMSGATE_SERVER')
app.smsgate_creds  = (os.environ.get('SMSGATE_USER'), os.environ.get('SMSGATE_PASS'))

app.app_name       = "TOTpy"
