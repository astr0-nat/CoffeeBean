import re
import pickle


def extract_email_addresses_from_file(source_file, dest_file):
    """
    Extract unique Google group email addresses from a text file.

    Reads a provided text file, identifies all unique email addresses within, and outputs a pickle file of
    a Python set of these unique email addresses.

    Parameters:
        source_file (str): The path to the text file containing the input text.
        dest_file (str): The path to the output set pickle file.
        This file is ./text_from_all_groups_website.txt which is all the text copied and pasted
        from https://groups.google.com/my-groups.

    Example:
        >>> extract_email_addresses_from_file("text_from_all_groups_website.txt")
        '{"example@test.com"}'

    Purpose:
        PyGroupDigest Google group summarizer needs access to all current Google Group email addresses within the company. This script aims to
        provide an easy way to keep the PyGroupDigest updated with any new Group additions.

    Usage:
        When a new Google Group needs to be summarizes, summary@month2month.com will first be added as a group member. This will be refelected in
        the /my-groups page of the Google Groups website for user sumary@month2month.com.

        If ever summary@gmail.com is added to a new Google Group, simply add it to the ./text_from_all_groups_website.txt text file within this directory.

        In the event you are unsure which groups are new or not, simply delete all the text within the ./text_from_all_groups_website.txt text file,
        navigate to the https://groups.google.com/my-groups website, select all the text available, while making sure to include all email addresses,
        and paste it into the ./text_from_all_groups_website.txt text file within this directory. Navigate to any additional pages on the Groups website
        if necessary and continue to copy and paste that text to the same text file.

        Then run this script while in the home directory of this script and the text file, and copy the output to the ALL_COMPANY_GOOGLE_GROUPS variable in the .env
        file in ithe PyGroupDigest directory

        """
    with open(source_file, 'r') as file:
        text = file.read()

    # Regular expression to match email addresses
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

    # Find all matches in the text
    email_addresses = re.findall(email_pattern, text)

    # Convert the list of email addresses to a set to remove duplicates
    unique_email_addresses = set(email_addresses)

    with open(dest_file, 'wb') as dest_file:
        pickle.dump(unique_email_addresses, dest_file)


source_file_path = "text_from_all_groups_website.txt"
dest_file_path = "google_groups_set.pkl"
extract_email_addresses_from_file(source_file_path, dest_file_path)
