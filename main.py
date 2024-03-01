from google.oauth2 import service_account
from googleapiclient.discovery import build

SERVICE_ACCOUNT_FILE = "./m2m_digest_service_key.json"
SCOPES = ['https://www.googleapis.com/auth/gmail.send',
          'https://www.googleapis.com/auth/gmail.readonly',
          'https://www.googleapis.com/auth/admin.directory.group.readonly',
          'https://www.googleapis.com/auth/admin.directory.group']
DOMAINS = ['greenlandpropertycare.com', 'month2month.com', 'holidale.com']
credentials = service_account.Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE, scopes=SCOPES)
delegated_credentials = credentials.with_subject('summary@month2month.com')

def get_group_service():

# Build the service object for the Admin SDK Directory API using the authorized credentials
group_service = build('admin', 'directory_v1', credentials=delegated_credentials)

# Build the service object for the gmail API using the authorized credentials
gmail_service = build('gmail', 'v1', credentials=delegated_credentials)

# Make a request to list all groups in each domain
all_groups = []
for domain in DOMAINS:
    request = group_service.groups().list(domain=domain)
    while request is not None:
        response = request.execute()
        groups = response.get('groups', [])
        for group in groups:
            all_groups.append(group)
        request = group_service.groups().list_next(previous_request=request, previous_response=response)

# Now `all_groups` contains groups from all domains
for group in all_groups:
    print(f"Group Name: {group['name']}, Email: {group['email']}")



