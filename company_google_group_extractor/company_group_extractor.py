import re


def extract_email_addresses_from_file(file_path):
    """
    Extract unique Google group email addresses from a text file.

    Reads a provided text file, identifies all unique email addresses within, and formats them into a
    string representation of a set, with each email address explicitly placed in double quotes and
    separated by commas.

    Parameters:
        file_path (str): The path to the text file containing the input text.
        This file is ./text_from_all_groups_website.txt which is all the text copied and pasted
        from https://groups.google.com/all-groups.

    Returns:
        str: A string representation of a set containing the unique company Google group email addresses extracted from the text.

    Example:
        >>> extract_email_addresses_from_file("text_from_all_groups_website.txt")
        '{"example@test.com"}'

    Purpose:
        PyGroupDigest Google group summarizer needs access to all current Google Group email addresses within the company. This script aims to
        provide an easy way to keep the PyGroupDigest updated with any new Group additions.

    Usage:
        If ever a new Google Group is added within the company, simply add it to the ./text_from_all_groups_website.txt text file within this directory.

        In the event you are unsure which groups are new or not, simply delete all the text within the ./text_from_all_groups_website.txt text file,
        navigate to the https://groups.google.com/all-groups website, select all the text available, while making sure to include all email addresses,
        and paste it into the ./text_from_all_groups_website.txt text file within this directory. Navigate to any additional pages on the Groups website
        if necessary and continue to copy and paste that text to the same text file.

        Then run this script while in the home directory of this script and the text file, and copy the output to the ALL_COMPANY_GOOGLE_GROUPS variable in the .env
        file in ithe PyGroupDigest directory

        """
    with open(file_path, 'r') as file:
        text = file.read()

    # Regular expression to match email addresses
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

    # Find all matches in the text
    email_addresses = re.findall(email_pattern, text)

    # Convert the list of email addresses to a set to remove duplicates
    unique_email_addresses = set(email_addresses)

    # Join the unique email addresses into a comma-separated string
    comma_separated_emails = ', '.join(unique_email_addresses)

    return comma_separated_emails


file_path = "text_from_all_groups_website.txt"
print(extract_email_addresses_from_file(file_path))
