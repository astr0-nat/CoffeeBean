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


def decode_base64_url(data):
    """Decode base64, padding being optional."""
    padding_factor = (4 - len(data) % 4) % 4
    data += "="*padding_factor
    return base64.urlsafe_b64decode(data)

def get_text_from_payload(payload):
    """Recursively extract text from email payload."""
    text = ""
    if payload['mimeType'].startswith('text/plain'):
        text += decode_base64_url(payload['body']['data']).decode('utf-8')
    elif payload['mimeType'].startswith('multipart'):
        for part in payload.get('parts', []):
            text += get_text_from_payload(part)
    return text

# Regex function to extract just the email address from the To: field
def extract_email_address(email_string):
    pattern = re.compile(r"<([^>]+)>")
    match = pattern.search(email_string)
    if match:
        return match.group(1)  # Return the first capturing group, which is the email address
    return email_string  # Return the original string if no match is found

def fetch_categorize_concatenate(service, query):
    threads = service.users().threads().list(userId='me', q=query).execute().get('threads', [])
    grouped_messages = {}
    for thread in threads:
        t_data = service.users().threads().get(userId='me', id=thread['id'], format='full').execute()
        concatenated_messages = ""
        for message in t_data['messages']:
            payload = message['payload']
            body_text = get_text_from_payload(payload)
            headers = payload.get('headers', [])
            from_header = next((header['value'] for header in headers if header['name'] == 'From'), None)
            # Extract just the email address if necessary
            from_email = extract_email_address(from_header)
            concatenated_messages += f"'from: {from_email}: {body_text}';"
        # Determine the group email based on the thread
        to_header = next((header['value'] for header in message['payload']['headers'] if header['name'] == 'To'), None)
        clean_email_address = extract_email_address(to_header)
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




