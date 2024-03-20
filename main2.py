import base64
from email.message import EmailMessage

import re
import os
from collections import defaultdict
import pickle

from google.oauth2 import service_account
from googleapiclient.discovery import build
from dotenv import load_dotenv
from openai import OpenAI
import redis
from datetime import date
from googleapiclient.errors import HttpError

load_dotenv()
SCOPES = os.getenv("SCOPES").split(',')
SUMMARY_EMAIL_ADDRESS = "summary@month2month.com"


class SummaryGenerator:
    def __init__(self, openai_client):
        self.openai_client = openai_client
        self.prompts = {
            'thread': None,
            'group': None
        }

    def load_prompt_from_file(self, prompt_type, file_path):
        """Load a custom prompt from a text file for a specified type."""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                prompt_text = file.read().strip()
                self._set_prompt(prompt_type, prompt_text)
                return prompt_text
        except FileNotFoundError:
            print(f"Error: The file at {file_path} was not found.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def _set_prompt(self, prompt_type, prompt_text):
        """Set a custom prompt for a specified type."""
        if prompt_type in self.prompts:
            self.prompts[prompt_type] = prompt_text
        else:
            raise ValueError("Unsupported prompt type.")

    def generate_summary(self, content, prompt_type):
        """Generate a summary using the appropriate prompt based on the prompt type."""
        if prompt_type not in self.prompts:
            raise ValueError("Unsupported prompt type.")
        prompt = self.prompts[prompt_type]
        summary = self.openai_client.chat.completions.create(
            model="gpt-4",
            messages=[
                {
                    "role": "system",
                    "content": f"{prompt}"
                },
                {
                    "role": "user",
                    "content": f"{content}"
                }
            ]
        )
        return summary.choices[0].message.content.strip()


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
    def __init__(self, gmail_service):
        self.gmail_service = gmail_service

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
                from_email = self._extract_email_address(from_header)

                # Should not include previous digest emails in current summary generation
                if from_email == "summary@month2month.com":
                    continue

                date_header = next((header['value'] for header in headers if header['name'] == 'Date'), None)
                subject_header = next((header['value'] for header in headers if header['name'] == 'Subject'),
                                      None)

                body_text = self._get_text_from_payload(payload)
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

                print(f" ThreadManager's content = {ThreadManager.content}\n")
                print(f"All recipients for this thread: {group_recipients}\n")
                print(f"Group recipients before in ThreadManager: {group_recipients}\n")
                for group_email in group_recipients:
                    thread_manager.add_group(group_email)
                print(f"Group recipients set inside ThreadManager: {thread_manager.groups}\n")
                print(f"Thread ID of this Thread manager = {thread_manager.thread_id}\n")
                print(f"Thread ID of this thread = {thread_id}\n")
                print('---' * 50)

            thread_managers[thread_id] = thread_manager

        return thread_managers

    def summarize_thread(self, thread_manager, summary_generator, redis_client):
        # Check Redis first to avoid re-summarization
        redis_key = f"Thread summary:{thread_manager.thread_id}"
        summary = redis_client.get_value(redis_key)
        if not summary:
            # Summarize using OpenAI if not already summarized
            summary = summary_generator.generate_summary(thread_manager.content, "thread")
            # Store in Redis
            redis_client.set_value(redis_key, summary)

        # Update thread_manager's summary regardless of source
        thread_manager.set_summary(summary)


class GroupSummaryManager:
    def __init__(self):
        self.group_to_threads = defaultdict(list)
        self.expiration_time = 28800  # 8 hours

    def add_summarized_thread(self, thread_manager):
        for group in thread_manager.groups:
            self.group_to_threads[group].append(thread_manager)

    def generate_group_summaries(self, summary_generator, redis_client):
        group_summaries = {}
        for group, threads in self.group_to_threads.items():
            combined_content = "\n ----- \n".join([t.content for t in threads])
            redis_key = f"Group summary: {group}"
            summary = redis_client.get_value(redis_key)
            if not summary:
                summary = summary_generator.generate_summary(combined_content, "group")
                redis_client.set_value(redis_key, summary)
            group_summaries[group] = summary
        return group_summaries


class EmailUtilities:
    def __init__(self, service):
        self.service = service

    @staticmethod
    def get_username_from_email(email_address):
        match = re.match(r'([^@]+)@', email_address)
        return match.group(1) if match else None

    def send_email(self, content, to, sender, subject):
        try:
            message = EmailMessage()
            message.set_content(content)
            message["To"] = to
            message["From"] = sender
            message["Subject"] = subject
            encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
            body = {"raw": encoded_message}
            sent_message = self.service.users().messages().send(userId="me", body=body).execute()
        except HttpError as error:
            print(f"An error occurred: {error}")
            sent_message = None
        return sent_message


class RedisClient:
    def __init__(self, host='localhost', port=6379, db=8, decode_responses=True):
        self.redis_db = redis.Redis(host=host, port=port, db=8, decode_responses=decode_responses)
        self.expiration_time = 7200  # 2 hours

    def set_value(self, key, value):
        self.redis_db.setex(key, self.expiration_time, value)

    def get_value(self, key):
        return self.redis_db.get(key)

    def print_all_entries(self):
        """Used for testing to print all stored summaries."""
        db = self.redis_db
        patterns = {
            "thread": "Thread summary:*",
            "group": "Group summary:*"
        }
        for pattern_type, pattern in patterns.items():
            for key in db.scan_iter(pattern):
                summary = db.get(key)
                if pattern_type == "thread":
                    thread_id = key.split(':')[1]  # Assuming key format is "Thread summary:{thread_id}"
                    print(f"Thread ID: {thread_id}, Summary: {summary}\n")
                    print("-" * 50)
                else:
                    group_id = key.split(':')[1]
                    print(f"Group ID: {group_id}, Summary: {summary}\n")

    def delete_all_entries(self):
        """Deletes all the thread and group summaries. Used for testing upon changing prompt."""
        db = self.redis_db
        thread_pattern = 'Thread summary:*'
        group_pattern = 'Group summary:*'
        for key in db.scan_iter(thread_pattern):
            db.delete(key)
        for key in db.scan_iter(group_pattern):
            db.delete(key)


def load_email_set_from_pickle(file_path):
    with open(file_path, 'rb') as file:  # Note the 'rb' mode for binary read
        email_set = pickle.load(file)
    return email_set


def test_send(group_to_digest_dict, sender, gmail_client):
    for group_address, digest in group_to_digest_dict.items():
        # this 'to' is for testing
        group_name = gmail_client.get_username_from_email(group_address)
        subject = f"{group_name} digest {date.today()}"
        test_digest = f"GROUP NAME: {group_name}\n\n {digest}"
        gmail_client.send_email(test_digest, "summary@month2month.com", sender, subject)


def main():
    pickle_path = "./group_extractor/google_groups_set.pkl"
    company_google_groups = load_email_set_from_pickle(pickle_path)
    print(f"Company Google Groups: {company_google_groups}\n")
    credentials = service_account.Credentials.from_service_account_file(os.getenv("SERVICE_ACCOUNT_FILE"),
                                                                        scopes=SCOPES)
    delegated_credentials = credentials.with_subject('summary@month2month.com')
    gmail_service = build('gmail', 'v1', credentials=delegated_credentials)
    query = 'newer_than:2d'
    openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    redis_client = RedisClient(host='localhost', port=6379, db=8, decode_responses=True)

    # # for testing, remove after:
    # RedisClient.delete_all_entries()

    thread_summary_prompt_file_path = 'thread_summary_prompt.txt'
    group_summary_prompt_file_path = 'group_summary_prompt.txt'

    thread_processor = ThreadProcessor(gmail_service)
    group_processor = GroupSummaryManager()
    summary_generator = SummaryGenerator(openai_client)
    gmail_client = EmailUtilities(gmail_service)

    summary_generator.load_prompt_from_file('thread', thread_summary_prompt_file_path)
    summary_generator.load_prompt_from_file('group', group_summary_prompt_file_path)

    thread_managers = thread_processor.fetch_threads(query, company_google_groups)
    for thread_manager in thread_managers.values():
        thread_processor.summarize_thread(thread_manager, summary_generator, redis_client)
        # Update Group Processor with newly summary threads
        group_processor.add_summarized_thread(thread_manager)
    groups_to_digest = group_processor.generate_group_summaries(summary_generator, redis_client)

    print(f"\n group processor's Group to Threads dict = {group_processor.group_to_threads}\n")
    print(f"\n groups_to_digest = {groups_to_digest}\n")

    sender = "summary@month2month.com"
    # test_send(groups_to_digest, sender, gmail_client)
    print("Digests sent!")
    # so this should send now to summary

    # this below would be for production
    # for group_address, digest in group_to_digest:
    #     to = group_address
    #     group_name = get_username_from_email(to)
    #     subject = f"{group_name} digest {date.today()}"
    #     gmail_send_email(gmail_service, digest, to, sender, subject)


if __name__ == "__main__":
    main()
