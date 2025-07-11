CoffeeBean
CoffeeBean automates email digest creation using Python, Gmail API, and OpenAI's GPT. It fetches, summarizes, and circulates essential action items from gmail Groups, streamlining communication and enhancing productivity in corporate environments.

How Does it Work?
CoffeeBean relies on Google Workspace Admin privileges. The email address with the Admin SDK Scope is summary@month2month.com. CoffeeBean also utilizes the concept of a Google Service Account.

A Google Service Account is not a traditional email account used for email communication by individuals. It is a special kind of account used by applications, servers, and other non-human entities to interact with Google APIs and services programmatically. A service account can authenticate and authorize access to certain Google services without human intervention, allowing automated processes to securely work with Google APIs. Service accounts are associated with private/public key pairs for authentication and are provided with a unique email address that identifies the account within Google's infrastructure, primarily for setting permissions in Google Cloud Platform services.

summary@month2month.com is CoffeeBean's service account, which interacts with the Gmail API to retrieve threads associated with Google Groups within the company and sends summarized digest emails back to these groups. It also interacts with OpenAI to summarize thread content.

How to Run the Program
Note:
CoffeeBean is scheduled as a cron job and it runs every day at 7:30 AM. Here is how you can run CoffeeBean on your own:

From your terminal, connect via SSH:

ssh webuser@172.233.142.247 -p 20202
# Enter password when prompted.
# Run the following wrapper script to execute CoffeeBean:
/home/webuser/CoffeeBean/scripts/coffee_run.sh
How to Set Up a New Machine to Run This Program
Gather all the sensitive information from the secure shared folder.

Clone the repository into a directory called CoffeeBean:

git clone <url> CoffeeBean
cd CoffeeBean
mkdir logs
echo '<credentials.json contents>' > credentials.json
echo '<m2m_digest_service_key.json contents>' > m2m_digest_service_key.json
echo '<.env file contents>' > .env
Update the file paths within the .env file to the relevant absolute paths as necessary.
Gather the content from https://groups.google.com/my-groups while logged in as summary@month2month.com. Put all the text into a file named text_from_all_groups_website.txt.

cd group_extractor
python3 company_group_extractor.py
cd ..
Ensure you now have a .pkl file.
Create Virtual Environment
In the root directory of the project:

python3 -m venv venv
source venv/bin/activate
# This will need to be active to run CoffeeBean.
Install Requirements Install the necessary packages from requirements.txt:

pip3 install -r requirements.txt
Ensure Redis is Installed If the redis-server command is not recognized, install Redis:
sudo apt update
sudo apt install redis-server
Confirm Redis is running:
redis-cli ping  # Should return 'PONG'
Make sure coffee_run.sh is executable:
chmod +x /path/to/coffee_run.sh
