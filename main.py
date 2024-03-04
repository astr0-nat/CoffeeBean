from google.oauth2 import service_account
from googleapiclient.discovery import build
import base64
import re

SERVICE_ACCOUNT_FILE = "./m2m_digest_service_key.json"
SCOPES = ['https://www.googleapis.com/auth/gmail.send',
          'https://www.googleapis.com/auth/gmail.readonly',
          'https://www.googleapis.com/auth/admin.directory.group.readonly',
          'https://www.googleapis.com/auth/admin.directory.group']

credentials = service_account.Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE, scopes=SCOPES)
delegated_credentials = credentials.with_subject('summary@month2month.com')

# Build the service object for the gmail API using the authorized credentials
gmail_service = build('gmail', 'v1', credentials=delegated_credentials)

# Regex function to extract just the email address from the To: field
def extract_email_address(email_string):
    pattern = re.compile(r"<([^>]+)>")
    match = pattern.search(email_string)
    if match:
        return match.group(1)  # Return the first capturing group, which is the email address
    return email_string  # Return the original string if no match is found

def fetch_categorize_concatenate(service, query):
    # Fetch threads based on the query
    threads = service.users().threads().list(userId='me', q=query).execute().get('threads', [])

    grouped_messages = {}
    for thread in threads:
        t_data = service.users().threads().get(userId='me', id=thread['id']).execute()

        # Initialize concatenation string for the current thread
        concatenated_messages = ""
        for message in t_data['messages']:
            # Decode the message body
            payload = message['payload']
            headers = payload.get('headers', [])
            parts = payload.get('parts', [])

            # Extract sender
            from_header = next((header['value'] for header in headers if header['name'] == 'From'), None)

            # Extract message body
            body = ""
            if parts:  # multipart messages
                for part in parts:
                    if part['mimeType'] == 'text/plain':
                        body = base64.urlsafe_b64decode(part['body']['data']).decode("utf-8")
                        break
            else:  # simple message
                if 'data' in payload['body']:
                    body = base64.urlsafe_b64decode(payload['body']['data']).decode("utf-8")

            # Concatenate the message with the rest
            concatenated_messages += f"'from: {from_header}: {body}';"

        # Determine the group email based on the thread
        # Assuming 'To' header is used for group email; adjust as necessary
        to_header = next((header['value'] for header in message['payload']['headers'] if header['name'] == 'To'), None)
        if to_header:
            clean_email_address = extract_email_address(to_header)  # Extract just the email address
            # Store or append the concatenated messages in the dictionary
            if clean_email_address not in grouped_messages:
                grouped_messages[clean_email_address] = concatenated_messages
            else:
                grouped_messages[clean_email_address] += concatenated_messages

    return grouped_messages

# Define your query, for example, messages from the last 24 hours
query = 'newer_than:1d'

# Fetch, categorize, and concatenate messages
grouped_messages = fetch_categorize_concatenate(gmail_service, query)


for group_email, thread_messages in grouped_messages.items():
    print(f"Group Email: {group_email}\nMessages:\n{thread_messages}\n")
    print("------------------------------------------------\n")




