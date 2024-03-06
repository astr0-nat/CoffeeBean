from google.oauth2 import service_account
from googleapiclient.discovery import build
from dotenv import load_dotenv
import base64
import re
import os
from openai import OpenAI

class EmailThread:
    def __init__(self, thread_id):
        self.thread_id = thread_id
        self.content = ""
        self.groups = set()
        self.summary = ""

    def add_content(self, new_content, date_header, from_email):
        self.content += f"\nDate: {date_header}\nFrom: {from_email}\n{new_content}"

    def add_group(self, group_email):
        self.groups.add(group_email)

    def set_summary(self, summary):
        self.summary = summary

    # Load environment variables
load_dotenv()
MODEL="gpt-4"
SCOPES = os.getenv("SCOPES").split(',')


client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
credentials = service_account.Credentials.from_service_account_file(os.getenv("SERVICE_ACCOUNT_FILE"), scopes=SCOPES)
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
    """Extracts and cleans the email address by stripping whitespace and angle brackets."""
    email_string = email_string.strip()
    # Remove angle brackets if present
    match = re.search(r'<([^>]+)>', email_string)
    if match:
        return match.group(1)
    return email_string



def process_threads(service, query, all_company_google_groups):
    threads = service.users().threads().list(userId='me', q=query).execute().get('threads', [])
    threads_info = {}  # This will store thread_id: EmailThread object

    for thread in threads:
        thread_id = thread['id']
        email_thread = EmailThread(thread_id=thread_id)

        t_data = service.users().threads().get(userId='me', id=thread_id, format='full').execute()

        for message in t_data['messages']:
            payload = message['payload']
            headers = payload.get('headers', [])
            from_header = next((header['value'] for header in headers if header['name'] == 'From'), None)
            date_header = next((header['value'] for header in headers if header['name'] == 'Date'), None)
            body_text = get_text_from_payload(payload)

            from_email = extract_email_address(from_header)

            # Adding content, including date and sender
            email_thread.add_content(body_text, date_header, from_email)

        # Get 'To' and 'Cc' from the first message's headers
        if t_data['messages']:
            headers = t_data['messages'][0]['payload'].get('headers', [])
            to_header = next((header['value'] for header in headers if header['name'] == 'To'), "")
            cc_header = next((header['value'] for header in headers if header['name'] == 'Cc'), "")

            # Extract email addresses and filter by all_company_google_groups
            all_recipients = set(
                extract_email_address(email) for email in to_header.split(',') + cc_header.split(',') if email.strip())
            group_recipients = all_recipients.intersection(all_company_google_groups)

            # Add valid group emails to the EmailThread object
            for group_email in group_recipients:
                email_thread.add_group(group_email)

        # Store using the thread's ID
        threads_info[thread_id] = email_thread

    return threads_info


# Define your query, for example, messages from the last 24 hours
query = 'newer_than:1d'
ALL_COMPANY_GOOGLE_GROUPS = set(email.strip() for email in os.getenv("ALL_COMPANY_GOOGLE_GROUPS").split(','))

# Fetch, categorize, and concatenate today's emails
todays_digest = process_threads(gmail_service, query, ALL_COMPANY_GOOGLE_GROUPS)

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


# Iterate through each EmailThread in today's digest and process each summary
for thread_id, email_thread in todays_digest.items():
    summary = summarize_with_gpt(email_thread.content)
    email_thread.set_summary(summary)

# At this point, summary_responses contains the group email as keys and the GPT-generated summaries as values


# for group_email, thread_messages in grouped_messages.items():
#     print(f"Group Email: {group_email}\nMessages:\n{thread_messages}\n")
#     print("------------------------------------------------\n")




# print("\n\n\n\n------------------------------------------------\n")
# print("AND NOW THE SUMMARIES: \n")
# for thread_id, email_thread in todays_digest.items():
#     print(f"Thread ID: {thread_id}\n")
#     print("Summary: \n")
#     print(email_thread.summary)
#     print("\nAssociated Group Emails: \n")
#     for group_email in email_thread.groups:
#         print(group_email + "\n")
#     print("-" * 50)  # Just a separator for readability







