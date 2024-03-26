import re
import pickle


def extract_email_addresses_from_file(source_file, dest_file):
    """
       Extracts and processes email addresses from a text file to create a set of unique, lowercase email addresses.

       This function is specifically designed for handling the extraction of email addresses from the text content
       typically obtained from https://groups.google.com/ using the summary@month2month.com account. It reads a
       provided text file, identifies all email addresses using a regex pattern, adds specific email addresses
       ('allstaff@month2month.com' and 'team-leads@month2month.com'), converts all email addresses to lowercase,
       and outputs a pickle file containing a Python set of these processed email addresses. This set includes unique
       email addresses in a normalized format, suitable for various applications that require a list of email addresses.

       Parameters:
           source_file (str): The path to the text file containing the input text. This file typically contains
           text copied from the Google Groups web interface for the summary@month2month.com account.
           dest_file (str): The path to the output file where the set of email addresses will be saved as a pickle file.

       Example Usage:
           >>> extract_email_addresses_from_file("text_from_all_groups_website.txt", "google_groups_set.pkl")

       Purpose:
           Designed to assist in maintaining an updated list of Google Group email addresses, including additional,
           specific email addresses for applications like PyGroupDigest. It streamlines the process of updating email
           lists by automating the extraction and normalization of email addresses from text files.

       Note:
           This function adds 'allstaff@month2month.com' and 'team-leads@month2month.com' to the extracted emails list
           as they are important for summarization but might not be listed in the source file.

       Usage Guide:
           1. Log in to https://groups.google.com/ with the summary@month2month.com account and copy the webpage text
              that contains the email addresses.
           2. Save this text to the source file.
           3. Run this function specifying the source and destination file paths.
           4. Use the output pickle file in your applications as needed, for instance, to update the
              ALL_COMPANY_GOOGLE_GROUPS variable in a configuration file for email-related processing.
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


source_file_path = "text_from_all_groups_website.txt"
dest_file_path = "google_groups_set.pkl"
extract_email_addresses_from_file(source_file_path, dest_file_path)
