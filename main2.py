import base64
import re
import os
from google.oauth2 import service_account
from googleapiclient.discovery import build
from dotenv import load_dotenv
from openai import OpenAI
import redis


class SummaryGenerator:
    def __init__(self, openai_client):
        self.openai_client = openai_client
        self.summary_prompt = None

    def generate_summary(self, content):
        # Call the OpenAI API with the content to generate a summary
        # Simplified for illustration
        summary = self.openai_client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": f"{self.summary_prompt}:\n\n{content}"}])
        return summary.choices[0].text.strip()
class ThreadManager:
    def __init__(self, thread_id):
        self.thread_id = thread_id
        self.content = ""
        self.groups = set()
        self.summary = None

    def add_content(self, new_content, date_header, from_email, subject):
        self.content += f"\n Subject Header: {subject}\nDate: {date_header}\nFrom: {from_email}\n{new_content}"

    def add_group(self, group_email):
        self.groups.add(group_email)

    def set_summary(self, summary):
        self.summary = summary


class ThreadProcessor:
    def __init__(self, gmail_service, openai_client, redis_db):
        self.gmail_service = gmail_service
        self.openai_client = openai_client
        self.redis_db = redis_db
        self.expiration_time = 7200  # 2 hours
        self.summary_prompt = None

    def set_prompt(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                prompt = file.read()
            self.summary_prompt = prompt
        except FileNotFoundError:
            print(f"Error: The file {file_path} was not found.")
            return None
        except Exception as e:
            print(f"An error occurred: {e}")
            return None

    def _decode_base64_url(self, data):
        padding_factor = (4 - len(data) % 4) % 4
        data += "=" * padding_factor
        return base64.urlsafe_b64decode(data)

    def _get_text_from_payload(self, payload):
        text = ""
        if payload['mimeType'].startswith('text/plain'):
            text += self._decode_base64_url(payload['body']['data']).decode('utf-8')
        elif payload['mimeType'].startswith('multipart'):
            for part in payload.get('parts', []):
                text += self._get_text_from_payload(part)
        return text

    def _extract_email_address(self, email_string):
        email_string = email_string.strip()
        match = re.search(r'<([^>]+)>', email_string)
        return match.group(1).lower() if match else email_string.lower()

    def fetch_threads(self, query, google_groups):
        all_threads = self.gmail_service.users().threads().list(userId='me', q=query).execute().get('threads', [])
        thread_managers = {}  # Updated to use ThreadManager

        for thread in all_threads:
            thread_id = thread['id']
            thread_manager = ThreadManager(thread_id=thread_id)
            t_data = self.gmail_service.users().threads().get(userId='me', id=thread_id, format='full').execute()

            for message in t_data['messages']:
                payload = message['payload']
                headers = payload.get('headers', [])
                from_header = next((header['value'] for header in headers if header['name'] == 'From'), None)
                date_header = next((header['value'] for header in headers if header['name'] == 'Date'), None)
                subject_header = next((header['value'] for header in headers if header['name'] == 'Subject'),
                                      None)

                body_text = self._get_text_from_payload(payload)
                from_email = self._extract_email_address(from_header)
                thread_manager.add_content(body_text, date_header, from_email, subject_header)

            if t_data['messages']:
                recipients_headers = ['To', 'Cc', 'Bcc']
                all_recipients = set()
                for header_name in recipients_headers:
                    header_value = next(
                        (header['value'] for header in t_data['messages'][0]['payload'].get('headers', []) if
                         header['name'] == header_name), "")
                    all_recipients.update({self._extract_email_address(email) for email in header_value.split(',')})

                group_recipients = all_recipients.intersection(google_groups)
                for group_email in group_recipients:
                    thread_manager.add_group(group_email)

            thread_managers[thread_id] = thread_manager

        return thread_managers

    def summarize_thread(self, thread_manager, summary_generator):
        # Check Redis first to avoid re-summarization
        summary = self.redis_db.get(f"summary:{thread_manager.thread_id}")
        if summary:
            thread_manager.set_summary(summary)
            return summary

        # Summarize using OpenAI if not already summarized
        summary = summary_generator(thread_manager.content)
        thread_manager.set_summary(summary)

        # Store in Redis
        self.redis_db.setex(f"summary:{thread_manager.thread_id}", self.expiration_time, summary)
        return summary


def print_all_summaries(redis_db):
    """Used for testing to print all stored summaries."""
    pattern = 'summary:*'  # Adjust based on your key naming scheme
    for key in redis_db.scan_iter(pattern):
        summary = redis_db.get(key)
        thread_id = key.split(':')[1]  # Assuming key format is "summary:{thread_id}"
        print(f"Thread ID: {thread_id}, Summary: {summary}")
        print("\n---------------------------------------\n")


def delete_all_entries(db):
    """Deletes all the thread summaries. Used for testing upon changing prompt."""
    pattern = 'summary:*'
    for key in db.scan_iter(pattern):
        db.delete(key)


def main():
    load_dotenv()
    SCOPES = os.getenv("SCOPES").split(',')
    ALL_COMPANY_GOOGLE_GROUPS = set(email.strip() for email in os.getenv("ALL_COMPANY_GOOGLE_GROUPS").split(','))
    credentials = service_account.Credentials.from_service_account_file(os.getenv("SERVICE_ACCOUNT_FILE"),
                                                                        scopes=SCOPES)
    delegated_credentials = credentials.with_subject('summary@month2month.com')
    gmail_service = build('gmail', 'v1', credentials=delegated_credentials)
    query = 'newer_than:1d'
    openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    redis_db = redis.Redis(host='localhost', port=6379, decode_responses=True)
    thread_summary_prompt_file_path = 'thread_summary_prompt.txt'

    #remove
    delete_all_entries(redis_db)

    thread_processor = ThreadProcessor(gmail_service, openai_client, redis_db)
    thread_processor.set_prompt(thread_summary_prompt_file_path)
    thread_managers = thread_processor.fetch_threads(query, ALL_COMPANY_GOOGLE_GROUPS)
    for thread_manager in thread_managers.values():
        thread_processor.summarize_thread(thread_manager)

    # For testing
    print_all_summaries(redis_db)


if __name__ == "__main__":
    main()
