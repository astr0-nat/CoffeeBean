import base64
from email.message import EmailMessage
import json

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
from datetime import datetime, timedelta
import pytz

load_dotenv(),
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

    def get_content(self):
        return self.content


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
        def within_last_n_days(date_str, n=7):
            message_date = datetime.strptime(date_str, '%a, %d %b %Y %H:%M:%S %z')
            cutoff_date = datetime.now(pytz.utc) - timedelta(days=n)
            return message_date > cutoff_date

        def clean_message(message):
            # Define patterns for headers, footers, and quoted text without the (?is) flag
            header_footer_patterns = [
                r"(?is)The content of this email is confidential.*?occur in the future\.",  # Confidentiality notice
                r"^\-\-.*$",  # Common footer delimiter
                r"You received this message because.*$",  # Subscription information
                r"To unsubscribe from this group.*$",  # Unsubscribe information
                r"www\.Month2Month\.com\s*<http://www\.month2month\.com/>\s*\[image:"  # M2M signature information
                r"\s*Facebook icon\]\s*<https://www\.facebook\.com/pages/category/"
                r"Property-Management-Company/Month2Month-103560381823386/>\s*\[image:"
                r"\s*LinkedIn icon\]\s*<https://www\.linkedin\.com/company/holidale-inc->"
                r"\s*\[image:\s*Youtube icon\]\s*<https://www\.youtube\.com/channel/UCEfOoj6HQ"
                r"bgxSneN8fWFf8A>\s*\[image:\s*Instagram icon\]\s*<https://www\.instagram\.com/"
                r"month2monthdotcom/\?hl=en>",
                r"^On .*<.*?@.*?>\s*wrote:$",  # Quoted reply header
                r"^>.*$"  # Quoted reply pattern
            ]

            combined_pattern = "|".join(header_footer_patterns)
            cleaned_email = re.sub(combined_pattern, '', message, flags=re.DOTALL | re.IGNORECASE | re.MULTILINE)
            cleaned_email = re.sub(r'\n\s*\n', '\n\n', cleaned_email)

            return cleaned_email.strip()

        all_threads = self.gmail_service.users().threads().list(userId='me', q=query).execute().get('threads', [])
        thread_managers = {}  # Updated to use ThreadManager

        for thread in all_threads:
            thread_id = thread['id']
            thread_manager = ThreadManager(thread_id=thread_id)
            t_data = self.gmail_service.users().threads().get(userId='me', id=thread_id, format='full').execute()

            i = 0
            for message in t_data['messages']:
                payload = message['payload']
                headers = payload.get('headers', [])
                from_header = next((header['value'] for header in headers if header['name'] == 'From'), None)
                from_email = self._extract_email_address(from_header)

                # Should not include previous digest emails in current summary generation
                if from_email == "summary@month2month.com":
                    continue

                date_header = next((header['value'] for header in headers if header['name'] == 'Date'), None)

                # Consider our token usage for GPT and limit the amount of reply chains we include in the ThreadManager
                if date_header and not within_last_n_days(date_header, n=7):
                    continue

                subject_header = next((header['value'] for header in headers if header['name'] == 'Subject'),
                                      None)

                body_text = self._get_text_from_payload(payload)
                clean_body_text = clean_message(body_text)
                print(f" message number {i} in thread: {thread_id}\n")
                i = i + 1
                print(f"body text: {clean_body_text}\n")
                thread_manager.add_content(clean_body_text, date_header, from_email, subject_header)

            if t_data['messages']:
                recipients_headers = ['To', 'Cc', 'Bcc']
                all_recipients = set()
                for header_name in recipients_headers:
                    header_value = next(
                        (header['value'] for header in t_data['messages'][0]['payload'].get('headers', []) if
                         header['name'] == header_name), "")
                    # print(f"header_name: {header_name}, header_value: {header_value}")
                    all_recipients.update({self._extract_email_address(email) for email in header_value.split(',')})

                group_recipients = all_recipients.intersection(google_groups)

                # print(f" ThreadManager's content = {thread_manager.get_content()}\n")
                # print(f"All recipients for this thread: {group_recipients}\n")
                # print(f"Group recipients before in ThreadManager: {group_recipients}\n")
                for group_email in group_recipients:
                    thread_manager.add_group(group_email)
                # print(f"Group recipients set inside ThreadManager: {thread_manager.groups}\n")
                print(f"Thread ID of this Thread manager = {thread_manager.thread_id}\n")
                # print(f"Thread ID of this thread = {thread_id}\n")
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

    @staticmethod
    def generate_html_email(gpt_response):
        entries = json.loads(gpt_response.content)
        html_content = "<html><body>"
        for entry in entries:
            html_content += f"<h2 style='color: #333; font-family: Arial, sans-serif;'>{entry['header']}</h2>"
            html_content += f"<p style='color: #666; font-family: Arial, sans-serif;'>{entry['summary']}</p>"
        html_content += "</body></html>"
        return html_content

    @staticmethod
    def generate_plain_text_email(gpt_response):
        entries = json.loads(gpt_response)
        plain_text_content = ""
        for entry in entries:
            plain_text_content += f"{entry['header'].upper()}\n\n"  # Header in uppercase for emphasis
            plain_text_content += f"{entry['summary']}\n\n"  # Summary as provided
            plain_text_content += "-" * 50 + "\n\n"  # Divider for readability
        return plain_text_content

    def send_email(self, digest_json, to, sender, subject):
        message = EmailMessage()
        plain_text_content = EmailUtilities.generate_plain_text_email(digest_json)
        html_content = EmailUtilities.generate_html_email(digest_json)
        message.set_content(plain_text_content)
        message.add_alternative(html_content, subtype='html')

        message["To"] = to
        message["From"] = sender
        message["Subject"] = subject
        try:
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
                    print("---" * 50)
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
    for group_address, digest_json in group_to_digest_dict.items():
        group_name = gmail_client.get_username_from_email(group_address)
        yesterday = date.today() - timedelta(days=1)
        subject = f"{group_name} digest {yesterday}"
        gmail_client.send_email(digest_json, "summary@month2month.com", sender, subject)


def main():
    pickle_path = "./group_extractor/google_groups_set.pkl"
    company_google_groups = load_email_set_from_pickle(pickle_path)
    print(f"Company Google Groups: {company_google_groups}\n")
    credentials = service_account.Credentials.from_service_account_file(os.getenv("SERVICE_ACCOUNT_FILE"),
                                                                        scopes=SCOPES)
    delegated_credentials = credentials.with_subject('summary@month2month.com')
    gmail_service = build('gmail', 'v1', credentials=delegated_credentials)
    query = 'newer_than:1d'
    openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    redis_client = RedisClient(host='localhost', port=6379, db=8, decode_responses=True)

    # # # for testing, remove after:

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

    sender = "summary@month2month.com"

    test_send(groups_to_digest, sender, gmail_client)
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
