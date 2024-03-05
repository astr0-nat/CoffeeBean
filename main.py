from google.oauth2 import service_account
from googleapiclient.discovery import build
from dotenv import load_dotenv
import base64
import re
import os
from openai import OpenAI

# Load environment variables
load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

MODEL="gpt-4"
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
            headers = payload.get('headers', [])
            from_header = next((header['value'] for header in headers if header['name'] == 'From'), None)
            date_header = next((header['value'] for header in headers if header['name'] == 'Date'), None)
            body_text = get_text_from_payload(payload)

            # Extract the clean email address from the From header
            from_email = extract_email_address(from_header)

            # Prepend the date and time to each message's content
            message_content = f' """ Date: {date_header}\n from: {from_email}: {body_text}""" '
            concatenated_messages += message_content

        # Extract the clean email address from the To header for the group email
        to_header = next((header['value'] for header in message['payload']['headers'] if header['name'] == 'To'), None)
        clean_email_address = extract_email_address(to_header)

        # Append or create new entry in the dictionary for this group email
        if clean_email_address not in grouped_messages:
            grouped_messages[clean_email_address] = concatenated_messages
        else:
            grouped_messages[clean_email_address] += concatenated_messages

    return grouped_messages


# Define your query, for example, messages from the last 24 hours
query = 'newer_than:1d'

# Fetch, categorize, and concatenate messages
grouped_messages = fetch_categorize_concatenate(gmail_service, query)

prompt = ("Could you analyze and condense the key information from a specific email conversation "  +
          "for me? I'm interested in understanding the core topics discussed, including the exact"+
          " dates of the correspondence, the individuals involved, and a concise summary of the "+
          "dialogue. Additionally, if there were any conclusions or decisions made, please "+
          "outline these outcomes or resolutions. Importantly, based on the discussion's content,"+
          " could you derive any concrete and actionable tasks or goals? These should be "+
          "clearly defined, emphasizing the actions required, the frequency of these actions, "+
          "and any specific timeframes involved. This analysis should also consider the "+
          "psychological aspects of goal setting and achievement, such as the importance "+
          "of specificity, measurability, and maintaining a positive outlook towards our daily"+
          " activities and overall objectives. Do not explicitly outline the 'psychological "+
          "apects', but rather include them implicilty and elegantly into the writing of your"+
          " synthesized actionable tasks. This request aims to ensure efficiency and"+
          " effectiveness in planning and goal realization. The forthcoming email thread will "+
          "be formatted with each message enclosed in triple quotes and identified by"+
          " Date: [Date email was sent] from: [sender] : [message body]. In your analysis, exclude any repetitive signatures"+
          " and irrelevant footnotes, and only consider reply chains that fall outside the "+
          "last 24 hours as needed")


# Function to send a thread to GPT for summarization
def summarize_with_gpt(thread_content):
    response = client.chat.completions.create(
    model=MODEL,
    messages=[{"role": "user", "content": f"{prompt}:\n\n{thread_content}"}])
    return response.choices[0].message.content.strip()

# Dictionary to store the summarization results
summary_responses = {}

# Iterate through grouped_messages and process each thread
for group_email, thread_content in grouped_messages.items():
    summary = summarize_with_gpt(thread_content)
    summary_responses[group_email] = summary

# At this point, summary_responses contains the group email as keys and the GPT-generated summaries as values


# for group_email, thread_messages in grouped_messages.items():
#     print(f"Group Email: {group_email}\nMessages:\n{thread_messages}\n")
#     print("------------------------------------------------\n")


print("\n\n\n\n------------------------------------------------\n")
print("AND NOW THE SUMMARIES: \n")
for group_email, summary in summary_responses.items():
    print(f"Group Email: {group_email}\nSummary:\n{summary}\n")
    print("------------------------------------------------\n")






