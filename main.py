import os
import pickle
# Gmail API utils
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
# for encoding/decoding messages in base64
from base64 import urlsafe_b64decode, urlsafe_b64encode
# for dealing with attachement MIME types
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from mimetypes import guess_type as guess_mime_type

# Request all access (permission to read/send/receive emails, manage the inbox, and more)
SCOPES = ['https://mail.google.com/']
our_email = 'pentnat@gmail.com'

# loads the credentials.json, does the authentication with Gmail API and returns a service object
# that will be used in all upcoming functions
def gmail_authenticate():
    creds = None
    # the file token.pickle stores the user's access and refresh tokens, and is created
    # automatically when the authorization flow completes for the first time
    if os.path.exists('token.pickle'):
        with open("token.pickle", "rb") as token:
            creds = pickle.load(token)
    # if there are no (valid) credentials available, let the user log in
    if not creds or not creds.valid:
        # if the access token needs refreshed
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else: flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
        creds = flow.run_local_server(port=0)
        # save the credentials for the next run
        with open("token.pickle", "wb") as token:
            pickle.dump(creds, token)
    return build('gmail', 'v1', credentials=creds)

# get the Gmail API Service
service = gmail_authenticate()
