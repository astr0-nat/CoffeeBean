import re
import pickle


def extract_email_addresses_from_file(source_file, dest_file):
    """
        Extracts and processes email addresses from a text file to create a set of unique, lowercase email addresses.

        This function is tailored for extracting email addresses from text content obtained from https://groups.google.com/
        using the summary@month2month.com account. It reads a provided text file, identifies all email addresses using a
        regex pattern, adds specific email addresses ('allstaff@month2month.com' and 'team-leads@month2month.com'),
        converts all email addresses to lowercase, and outputs a pickle file containing a Python set of these processed
        email addresses. The set includes unique email addresses in a normalized format, ready for use in applications
        requiring a list of email addresses, such as the CoffeeBean Gmail summarizer.

        Parameters:
            source_file (str): The path to the text file containing the input text. This file typically includes text
            copied from the Google Groups web interface for the summary@month2month.com account.
            dest_file (str): The path to the output file where the set of email addresses will be saved as a pickle file.

        Example Usage:
            >>> extract_email_addresses_from_file("text_from_all_groups_webpage.txt", "google_groups_set.pkl")

        Purpose:
            The script aids in keeping an up-to-date list of Google Group email addresses, plus additional specific
            email addresses, for applications like the CoffeeBean Gmail summarizer. It automates the extraction and
            normalization of email addresses from text files, facilitating the updating process of email lists.

        Note:
            The function explicitly includes 'allstaff@month2month.com' and 'team-leads@month2month.com' to the list
            of extracted emails as they are deemed crucial for summarization purposes but might not be present in the
            source file.

        When to Run:
            - Whenever a new Google Group needs to be summarized, summary@month2month.com must be added to the group. In
            this case, this script must be run according to the usage guide.

        Usage Guide:
            1. Log into https://groups.google.com/ with the summary@month2month.com account and copy the webpage text that
               contains the email addresses.
            2. Save this text into the source file.
            3. Run this script with the specified source and destination file paths to update the list of email addresses.
            4. This output pickle file is utilized by the company_google_groups set in CoffeeBean.
        """
    with open(source_file, 'r') as file:
        text = file.read()

    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    email_addresses = re.findall(email_pattern, text)
    # allstaff is not a Google Group, but it is good to summarize
    email_addresses.append("allstaff@month2month.com")
    email_addresses.append("team-leads@month2month.com")
    lowercase_emails = set(map(lambda email: email.lower(), email_addresses))

    with open(dest_file, 'wb') as dest_file:
        pickle.dump(lowercase_emails, dest_file)


source_file_path = "text_from_all_groups_webpage.txt"
dest_file_path = "google_groups_set.pkl"
extract_email_addresses_from_file(source_file_path, dest_file_path)
