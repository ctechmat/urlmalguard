import tldextract
import base64
import requests
import os
import re
import socket
import subprocess
import idna
import zipfile
import csv
import whois
import ssl
import OpenSSL
from datetime import datetime, timedelta
from dotenv import load_dotenv
from pymisp import PyMISP
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from chromedriver_py import binary_path

# Load environment variables from the .env file
load_dotenv()

# Read the API key directly from the environment
vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
otx_api_key = os.getenv("OTX_API_KEY")
misp_url = os.getenv("MISP_URL")
misp_api_key = os.getenv("MISP_API_KEY")
proxy = os.getenv("PROXY")

# Function to extract the domain name
def extract_domain(url):
    extract = tldextract.extract(url)
    return extract.registered_domain

# Function to extract the sub-domain name
def extract_subdomain(url):
    extract = tldextract.extract(url)
    subdomain = extract.subdomain
    domain = extract.registered_domain
    fqdn = extract.fqdn
    return fqdn if subdomain else domain

# Function to extract the domain name (without extension)
def extract_domain_name(url):
    extract = tldextract.extract(url)
    domain = extract.domain
    return domain

# Function to check whether the file is recent (less than a day old)
def is_file_recent(file_path):
    if os.path.exists(file_path):
        file_modif_time = datetime.fromtimestamp(os.path.getmtime(file_path))
        difference_time = datetime.now() - file_modif_time
        if difference_time < timedelta(days=1):
            return True
        else:
            return False
    else:
        return False

# Function to test if domain exists
def domain_exists(url):
    domain = extract_domain(url)
    subdomain = extract_subdomain(url)
    try:
        # uses nslookup with commandline
        result = subprocess.run(["nslookup", domain], capture_output=True, text=True, check=True)
        
        # check the full output of nslookup
        output = result.stdout
        
        # Search "Non-authoritative answer: "
        if "Non-authoritative answer:" in output:
            # Split output after "Non-authoritative answer: "
            part_after_answer = output.split("Non-authoritative answer:")[1]
            
            # Found all ip address
            addresses = [line.split("Address:")[1].strip() for line in part_after_answer.splitlines() if "Address:" in line]
        
            # If IP addresses are returned, take the first one
            if addresses:
                return True, addresses[0]
            else:
                # If no address is found, try the sub-domain
                if subdomain:
                    result = subprocess.run(["nslookup", subdomain], capture_output=True, text=True, check=True)
                    output = result.stdout
                    if "Non-authoritative answer:" in output:
                        part_after_answer = output.split("Non-authoritative answer:")[1]
                        addresses = [line.split("Address:")[1].strip() for line in part_after_answer.splitlines() if "Address:" in line]
                        if addresses:
                            return True, addresses[0]
                return False, None
        else:
            # No "Non-authoritative answer: " found in the output
            return False, None

    except (subprocess.CalledProcessError, IndexError) as e:
        # On error, return False and None
        print(f"{e}")
        return False, None

# Function to retrieve the creation and expiry date of the domain with WHOIS
def get_domain_whois_informations(domain):
    try:
        w = whois.whois(domain)

        # Check that the creation date and expiry date are present
        creation_date_domain = w.get('creation_date', None)
        expiration_date_domain = w.get('expiration_date', None)

        # If the creation date is not found, return False.
        if not creation_date_domain:
            print(f"The domain creation date is not entered")
            return False, False, False
        
        # If the creation date is a list, take the first value
        if isinstance(creation_date_domain, list):
            creation_date_domain = creation_date_domain[0]

        # If the expiry date is a list, take the first value
        if isinstance(expiration_date_domain, list):
            expiration_date_domain = expiration_date_domain[0]

        # Check whether the creation date is a datetime object
        if isinstance(creation_date_domain, datetime):
            today = datetime.now()
            difference = today - creation_date_domain

            # Check if the difference is less than or equal to 60 days
            if difference <= timedelta(days=60):
                print(f"The domain is less than 60 days old")
                return True, creation_date_domain, expiration_date_domain
            else:
                print(f"The domain is more than 60 days old")
                return False, creation_date_domain, expiration_date_domain

        # If the creation date is in an incorrect format
        print(f"The domain creation date is invalid")
        return False, False, False

    except Exception as e:
        print(f"Error retrieving Whois information : {e}")
        return False, False, False

# Function to retrieve the organisation and city associated with an ip address
def get_ip_informations(ip):
    url = f'https://ipinfo.io/{ip}/json'
    reponse = requests.get(url)
    
    if reponse.status_code == 200:
        informations = reponse.json()
        org = informations.get('org', False)
        country = informations.get('country', False)
        return org, country
    else:
        return False, False

# Function to check if the url starts with https
def start_with_https(url):
    if url.lower().startswith('https://'):
        return True
    else:
        return False

# Function for analysing the ssl certificate
def get_ssl_certificate_info(hostname):
    try:
        # Create an SSL connection without verifying the certificate
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # For self-signed certificate

        with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname) as connection:
            connection.connect((hostname, 443))

            # Obtain SSL certificate information
            cert = connection.getpeercert(True)

        # Convert the binary certificate into a format readable with OpenSSL
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)

        # Function for formatting name components
        def format_x509_name(x509_name):
            return ', '.join([f"{item[0].decode()}={item[1].decode()}" for item in x509_name.get_components()])

        # Function to convert the binary date into a readable format
        def format_notbefore_notafter(not_before_bytes):
            return datetime.strptime(not_before_bytes.decode(), "%Y%m%d%H%M%SZ")

        # Extract specific information from the certificate
        cert_info_subject = format_x509_name(x509.get_subject())
        cert_info_issuer = format_x509_name(x509.get_issuer())
        cert_info_notbefore = format_notbefore_notafter(x509.get_notBefore())
        cert_info_notafter = format_notbefore_notafter(x509.get_notAfter())
        cert_is_self_signed = x509.get_subject() == x509.get_issuer()

        # Certificate expiry check
        cert_is_expired = datetime.now() > cert_info_notafter

        print(f"A certificate was found and processed")
        return True, cert_info_subject, cert_info_issuer, cert_info_notbefore, cert_info_notafter, cert_is_self_signed, cert_is_expired

    except ssl.SSLError as e:
        print(f"SSL error : {e}")
        return False, str(e), None, None, None, None, None
    except socket.error as e:
        print(f"Network connection error : {e}")
        return False, str(e), None, None, None, None, None
    except Exception as e:
        print(f"Error when extracting the certificate: {e}")
        return False, str(e), None, None, None, None, None

# Function to detect a download and retrieve the file name
def detect_download_filename(url, file_path):
    try:
        # Perform a GET request, but stop downloading the file immediately
        response = requests.get(url, stream=True, allow_redirects=True, verify=False)
        
        # Check if the request was successful
        if response.status_code != 200:
            return False, None
        
        # Get the Content-Disposition header
        content_disposition = response.headers.get('Content-Disposition', '')
        
        # If Content-Disposition contains a file name, extract the file name
        if 'attachment' in content_disposition:
            print(f"A file tried to be downloaded")
            filename = content_disposition.split('filename=')[1].strip('"')
            return True, filename
        
        # Read the local file containing MIME types
        mime_types = set(line.strip() for line in open(file_path, "r") if line.strip())
        
        # Check the MIME type of the file
        content_type = response.headers.get('Content-Type', '')
        if any(mime in content_type for mime in mime_types):
            print(f"A file tried to be downloaded")
            # If the MIME type corresponds to a file, we assume that it is a file to be downloaded
            filename = url.split("/")[-1]
            return True, filename
        
        # If there is no indication in the headers
        return False, None
    
    except Exception as e:
        print(f"Error detecting download: {e}")
        return False, None

# Function to detect the punycode
def detect_and_decode_punycode(url, domain):
    
    # Check if the domain contains Punycode (prefix ‘xn--’)
    if 'xn--' in domain:
        print(f"Punycode detected")
        try:
            # Decode Punycode into Unicode text
            decoded_domain = idna.decode(domain)
            # Build the decoded url
            parsed_url = urlparse(url)
            scheme = parsed_url.scheme + "://"
            decoded_url = f"{scheme}{decoded_domain}"
            return True, decoded_url
        except idna.IDNAError:
            print(f"Error during punycode analysis")
    else:
        # No Punycode found
        print(f"No punycode detected")
        return False, False 

# Function to detect shortened urls
def detect_shortened_url(domain, url, file_path):
    try:
        # Load shortening domains from file
        with open(file_path, "r") as file:
            shortened_domains = {line.strip() for line in file.readlines() if line.strip()}

        # Check whether the URL domain is in the list of shorteners
        if domain in shortened_domains:
            print(f"{domain} is in the list of url shorteners")
            try:
                # Send an HTTP GET request to track redirects
                response = requests.get(url, allow_redirects=True)
                return True, response.url
            except requests.exceptions.RequestException as e:
                # If an error occurs during the request
                print(f"Error when retrieving URL: {e}")
                return True, False

        # If the domain does not correspond to any shortener in the list
        print(f"{domain} is not in the list of url shorteners")
        return False, False
    
    except Exception as e:
        print(f"Error when reading file: {e}")
        return False, False

# Function to detect non-ascii characters
def detect_non_ascii_caracters(domain):
    # Checks non-ASCII characters (beyond \x7F)
    pattern = r'[^\x00-\x7F]'
    is_ascii = bool(re.search(pattern, domain))
    if is_ascii:
        print(f"One or more non-ascii character(s) detected")
        return True
    else:
        print(f"No non-ascii character detected")
        return False

# Function to search for redirects
def check_redirection(url):
    try:
        # Make the request following the redirections
        response = requests.get(url, allow_redirects=True)

        # If the original URL differs from the final URL, this means that a redirect has taken place
        if response.url != url and response.url != url + "/":
            print(f"Redirection detected")
            return True, response.url
        else:
            print(f"No redirection detected")
            return False, False

    except requests.exceptions.RequestException as e:
        print(f"Error when detecting redirection: {e}")
        return False, False

# Function to load the dictionary of similar characters from the text file in the ‘data/dictionary’ folder
def load_char_similarities(file_path):
    char_similarities = {}
    try:
        # Checks whether the file exists before attempting to load it
        if os.path.exists(file_path):
            with open(file_path, "r") as file:
                for line in file:
                    # Ignore empty lines or comment lines
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # Split line into key and value
                        parts = line.split(":")
                        if len(parts) == 2:
                            base_char = parts[0].strip()  # Original character
                            similar_chars = [x.strip() for x in parts[1].split(",")]  # List of similar characters

                            # Add each similar character as a key in the dictionary
                            for similar_char in similar_chars:
                                char_similarities[similar_char] = base_char
            return char_similarities
        else:
            print(f"The file {file_path} does not exist")
            return {}
    except Exception as e:
        print(f"Error loading similar characters file: {e}")
        return {}

# Function for generating domain variations
def generate_domain_variations(domain, char_similarities):
    variations = set()
    
    # Separate the part before and after the extension
    if '.' in domain:
        base_domain, extension = domain.rsplit('.', 1)
        extension = '.' + extension
    else:
        base_domain = domain
        extension = ""

    # Replace similar characters in the domain base part
    for i, char in enumerate(base_domain):
        if char in char_similarities:
            # Replace with the potentially original character
            original_char = char_similarities[char]
            new_domain = base_domain[:i] + original_char + base_domain[i+1:] + extension
            variations.add(new_domain)

    # Add letters to the part before the extension
    alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789-'
    for i in range(len(base_domain) + 1):
        for char in alphabet:
            new_domain = base_domain[:i] + char + base_domain[i:] + extension
            variations.add(new_domain)
    
    # Deletion of letters in the area before the extension
    for i in range(len(base_domain)):
        new_domain = base_domain[:i] + base_domain[i+1:] + extension
        variations.add(new_domain)
    
    return variations

# Function to compare variations with the list of Top 1M domain from Umbrella
def compare_with_umbrella(domain, domain_variations, list_of_element, zip_file_path, file_path):
    found_domains = []

    try:
        # Download and extract the Umbrella CSV file if necessary
        top_domains = download_and_process_zip_file(list_of_element, zip_file_path, file_path)

        # Returns False if problem during download
        if top_domains is None:
            print(f"Error downloading or processing the list of umbrella domains")
            return False, None

        # Compare the variations with the list of domains of Umbrella
        if domain in top_domains:
            print(f"The domain {domain} is in the Umbrella list")
            return False, None
        else:
            for variation in domain_variations:
                if variation in top_domains:
                    found_domains.append(variation)

        # Return True if a variation is found
        if found_domains:
            return True, found_domains
        else:
            print("No variations found in the list of Umbrella domains")
            return False, None

    except Exception as e:
        print(f"Error when downloading or saving the list of umbrella domains: {e}")
        return False, None

# Function to compare variations with the list of French public organization
def compare_with_french_public_org(domain, domain_variations, list_of_element, file_path):
    found_domains = []

    try:
        list_lines = download_and_process_txt_file(list_of_element, file_path)

        # Compare the variations with the list of domains of French public organisation
        if domain in list_lines:
            print(f"The {domain} is on the list of domains of French public organisation")
            return False, None
        else:
            for variation in domain_variations:
                if variation in list_lines:
                    found_domains.append(variation)
        
        if found_domains:
            return True, found_domains
        else:
            print("No variations found in the list of French public organisation")
            return False, None
    
    except Exception as e:
        print(f"Error when downloading or saving the list of French public organisation: {e}")
        return False, None

# Function to configure Selenium with Chrome
def get_chrome_driver(binary_path):
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--disable-software-rasterizer")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-notifications")
    chrome_options.add_argument("--disable-plugins")
    chrome_options.add_argument("--disable-application-cache")
    chrome_options.add_argument("--disable-translate")
    chrome_options.add_argument("--disable-default-apps")
    chrome_options.add_argument("--incognito")
    chrome_options.add_argument("--disable-cache")
    chrome_options.add_argument("--remote-debugging-port=9222")

    if proxy:
        chrome_options.add_argument(f"--proxy-server={proxy}")

    prefs = {
        "profile.default_content_settings.popups": 0,
        "download.default_directory": "/dev/null",
        "directory_upgrade": True
    }

    chrome_options.add_experimental_option("prefs", prefs)

    driver = webdriver.Chrome(service=Service(executable_path=binary_path), options=chrome_options)
    return driver

# Function to search for potentially malicious elements in html code
def check_html_code(url):
    try:
        driver = get_chrome_driver(binary_path)
        driver.get(url)

        # Extracts domain from url
        base_domain_name = extract_domain_name(url)

        # Initialisation of results
        is_there_external_domain = False
        is_there_hidden_images = False
        is_there_hidden_links = False
        is_there_hidden_forms = False
        is_there_hidden_inputs = False
        is_there_hidden_iframes = False

        # Initialisation of the list of external domains
        external_domains = []

        # Function to check if an element is hidden
        def is_hidden(element):
            opacity = element.value_of_css_property('opacity')

            return opacity == '0'

        # Search for images
        images = driver.find_elements(By.XPATH, '//img')
        for image in images:
            if is_hidden(image):
                is_there_hidden_images = True
                break  # Exit the loop as soon as a hidden image is found

        # Search for links
        links = driver.find_elements(By.XPATH, '//a[@href] | //area[@href] | //button[@onclick] | //input[@onclick] | //meta[@http-equiv="refresh"]')
        for link in links:
            if is_hidden(link):
                is_there_hidden_links = True
                break  # Exit the loop as soon as a hidden link is found

        # Search for forms
        forms = driver.find_elements(By.XPATH, '//form')
        for form in forms:
            if is_hidden(form):
                is_there_hidden_forms = True
                break  # Exit the loop as soon as a hidden form is found

        # Search for inputs
        inputs = driver.find_elements(By.XPATH, '//input | //textarea')
        for input_field in inputs:
            if is_hidden(input_field):
                is_there_hidden_inputs = True
                break  # Exit the loop as soon as a hidden input field is found

        # Search for iframes
        iframes = driver.find_elements(By.XPATH, '//iframe')
        for iframe in iframes:
            if is_hidden(iframe):
                is_there_hidden_iframes = True
                break  # Exit the loop as soon as a hidden iframe is found

        # Verification of external links
        for link in links:
            href = link.get_attribute('href') or link.get_attribute('onclick') or link.get_attribute('content')

            # Ignore ‘chrome-error://’ links
            if href and href.startswith("chrome-error://"):
                continue 
        
            if href:
                link_domain_name = extract_domain_name(href)
                subdomain = extract_subdomain(href)
            
                # Compare domain names (without the extension)
                if link_domain_name != base_domain_name:
                    external_domains.append(subdomain)
                    is_there_external_domain = True

        return is_there_external_domain, external_domains, is_there_hidden_images, is_there_hidden_links, is_there_hidden_forms, is_there_hidden_inputs, is_there_hidden_iframes

    except Exception as e:
        print(f"Error during analysis with Selenium: {e}")
        return False, [], False, False, False, False, False

    finally:
        # Close the browser if the driver has been initialised
        if 'driver' in locals():
            driver.quit()  # Close the browser and free up resources

# Function to search for malicious JavaScript elements
def check_js_in_html(url):
    try:
        driver = get_chrome_driver(binary_path)
        driver.get(url)
        
        # Waiting for a visible element (the body here)
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, 'body')))

        # Find all <script> tags
        script_tags = driver.find_elements(By.TAG_NAME, 'script')

        # Initialisation of results
        js_detected, js_redirection, js_keylogging, js_dom_manipulation = False, False, False, False

        # Function to check for malicious redirects
        def check_js_redirection(js_code):
            return bool(re.search(r'window\.location\s*=\s*["\']([^"\']+)["\']', js_code))

        # Function to check keylogging
        def check_js_keylogging(js_code):
            return bool(re.search(r'document\.addEventListener\s*\(\s*["\']keydown["\']', js_code) or
                             re.search(r'document\.addEventListener\s*\(\s*["\']keyup["\']', js_code))

        # Function to check DOM manipulation
        def check_js_dom_manipulation(js_code):
            return bool(re.search(r'document\.write\s*\(', js_code) or
                        re.search(r'document\.getElementById\s*\(', js_code) or
                        re.search(r'document\.body\.innerHTML\s*=', js_code))

        # Analyse each <script> tag to detect suspicious behaviour
        for script in script_tags:
            js_code = script.get_attribute('innerHTML')  # Get the JavaScript code

            if js_code:
                js_detected = True
                if check_js_redirection(js_code):
                    js_redirection = True
                if check_js_keylogging(js_code):
                    js_keylogging = True
                if check_js_dom_manipulation(js_code):
                    js_dom_manipulation = True

        return js_detected, js_redirection, js_keylogging, js_dom_manipulation

    except Exception as e:
        print(f"Error during analysis with Selenium: {e}")
        return False, False, False, False

    finally:
        if 'driver' in locals():
            driver.quit()

# Utility function to read and save txt files
def download_and_process_txt_file(list_of_element, file_path):
    try:
        # If the file is recent, it is read
        if is_file_recent(file_path):
            print(f"The file {file_path} is recent, no download")
            with open(file_path, 'r') as file:
                list_lines = [line.strip() for line in file.readlines()]
        else:
            # Download the list of items
            response = requests.get(list_of_element)
            response.raise_for_status()
            print(f"The file {file_path} has been downloaded for data processing")

            # Read and process file contents
            list_lines = response.text.splitlines()
            # Adjust the adguard list
            if 'domain/adguard_filter' in file_path:
                list_lines = [line.lstrip("||").rstrip("^") for line in list_lines]
            # Adjust the french plublic organisation list
            elif 'domain/french_public_organism' in file_path:
                # Extracts domains and extensions
                extracted_domains = [
                    '.'.join([ext.domain, ext.suffix])
                    for line in list_lines
                    if (ext := tldextract.extract(line.strip())).domain
                ]
                # Delete duplicates
                in_list = set()
                list_lines = [
                    domain
                    for domain in extracted_domains
                    if domain not in in_list and not in_list.add(domain)
                ]
            else:
                list_lines = [line.strip() for line in list_lines]

            # Save the file for next time use
            with open(file_path, 'w') as file:
                for line in list_lines:
                    file.write(f"{line}\n")
            print(f"The file {file_path} was saved")
        
        return list_lines
    except requests.exceptions.RequestException as e:
        # Handle issues related to the download request
        print(f"Error downloading the file from {list_of_element}: {e}")
        return None
    except Exception as e:
        # Catch other unexpected errors
        print(f"Error when processing the file {file_path}: {e}")
        return None

# Utility function to read and save csv files
def download_and_process_zip_file(list_of_element, zip_file_path, file_path):
    try:
        list_lines = set()

        # If the file is recent, it is read
        if is_file_recent(file_path):
            print(f"The file {file_path} is recent, no download")
            with open(file_path, 'r') as file:
                list_lines = {line.strip() for line in file}
        else:
            # Download the list of items
            response = requests.get(list_of_element)
            response.raise_for_status()
            print(f"The file {file_path} has been downloaded for data processing")

            # Save the ZIP file locally
            with open(zip_file_path, "wb") as f:
                f.write(response.content)
                print(f"ZIP file downloaded : {zip_file_path}")

            # Unzip the ZIP file
            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                zip_ref.extractall("data/domain")
                print(f"File extraction {zip_file_path} completed")
            
            # Delete the ZIP file after extraction
            os.remove(zip_file_path)

            # Rename the extracted file to CSV
            extracted_file_path = "data/domain/top-1m.csv"
            os.rename(extracted_file_path, file_path)
            print(f"CSV file extracted and renamed: {file_path}")

            # Read the downloaded CSV file and extract the domains
            with open(file_path, "r") as file:
                next(file)  # Skip header
                for line in file:
                    parts = line.strip().split(",", 1)  # Divide each row into two columns
                    if len(parts) > 1:
                        domain = parts[1].strip()  # Retrieve the domain from the second column
                        ext = tldextract.extract(domain)
                        if ext.domain:  # If a valid domain is extracted
                            list_lines.add(f"{ext.domain}.{ext.suffix}")

            # Save domains in a text file
            with open(file_path, "w") as txt_file:
                for line in list_lines:
                    txt_file.write(f"{line}\n")
            print(f"The domains were extracted and saved in {file_path}")

        return list_lines

    except Exception as e:
        print(f"Error when downloading or saving the file: {e}")
        return None

# Function to check whether the URL, domain or IP is in a txt list
def check_attribute_in_txt_list(attribute, list_of_element, file_path):
    # Remove the ‘http://’ or ‘https://’ prefixes from the URL for the trcert list
    if 'url/trcert.txt' in file_path:
        if attribute.startswith("http://"):
            attribute = attribute[len("http://"):]
        elif attribute.startswith("https://"):
            attribute = attribute[len("https://"):]

    # Download and process the file if necessary
    list_lines = download_and_process_txt_file(list_of_element, file_path)
    if list_lines is None:
        return False

    # Check if the domain is in the list
    return attribute in list_lines

# General function for analysing the URL, domain or IP in VirusTotal
def search_in_virustotal(type_attr, attribute):
    url_virustotal = f"https://www.virustotal.com/api/v3/{type_attr}/{attribute}"
    headers = {"x-apikey": vt_api_key}

    try:
        response = requests.get(url_virustotal, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return None, str(e), None

    result = response.json()

    # Check the structure of the response and extract the analysis data
    if 'data' in result and 'malicious' in result['data']['attributes']['last_analysis_stats']:
        stats = result['data']['attributes']['last_analysis_stats']
        malicious = stats['malicious']
        suspicious = stats['suspicious']
        undetected = stats['undetected']
        harmless = stats['harmless']
        total = malicious + suspicious + undetected + harmless
        print(f"VirusTotal: At least one event was found")
        return malicious > 0, malicious, total
    elif 'error' in result:
        print(f"VirusTotal: An error has occurred ({result['error']['message']})")
        return None, result['error']['message'], None
    print(f"VirusTotal: No event found")
    return None, f"Unkown error", None

# Function to analyse the URL with VirusTotal
def check_url_vt(url):
    url_b64 = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")
    return search_in_virustotal("urls", url_b64)

# Function to analyse the domain with VirusTotal
def check_domain_vt(domain):
    return search_in_virustotal("domains", domain)

# Function to analyse the ip with VirusTotal
def check_ip_vt(ip):
    return search_in_virustotal("ip_addresses", ip)

# General function for analysing the URL, domain or IP in AlienVault OTX.
def search_in_otx(type_attr, attribute):
    url_otx = f"https://otx.alienvault.com/api/v1/indicators/{type_attr}/{attribute}/general"
    headers = {"X-OTX-API-KEY": otx_api_key}

    try:
        response = requests.get(url_otx, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return None, str(e)

    result = response.json()

    # Check the structure of the response and extract the analysis data
    if 'pulse_info' in result and 'count' in result['pulse_info']:
        print(f"OTX: At least one event was found")
        return True, result['pulse_info']['count']
    else:
        print(f"OTX: No event found")
        return False, 0

# Function to analyse the URL with AlienVault OTX
def check_url_otx(url):
    return search_in_otx("url", url)

# Function to analyse the domain with AlienVault OTX
def check_domain_otx(domain):
    return search_in_otx("domain", domain)

# Function to analyse the ip with AlienVault OTX
def check_ip_otx(ip):
    return search_in_otx("IPv4", ip)

# General function for analysing the URL, domain or IP in MISP
def search_in_misp(type_attr, attribute):
    try:
        # Connection to the MISP instance
        misp = PyMISP(misp_url, misp_api_key, ssl=False)

        # Calculate date 6 months ago
        six_months_ago = datetime.now() - timedelta(days=180)

        # Convert date to ISO 8601 format for MISP (with time)
        date_since = six_months_ago.strftime('%Y-%m-%dT%H:%M:%S')

        # Search for all events containing the attribute
        response = misp.search(controller='attributes', type='type_attr', value=attribute, timestamp=date_since)

        # If the response contains ‘Attribute’: [] (i.e. no event found)
        if 'Attribute' in response and response['Attribute']:
            print(f"MISP: At least one event was found")
            return True, False
        else:
            print(f"MISP: No event found")
            return False, False

    except Exception as e:
        print(f"MISP: An error has occurred ({e})")
        return None, str(e)

# Function to analyse the URL with MISP
def check_url_misp(url):
    return search_in_misp("url", url)

# Function to analyse the domain with MISP
def check_domain_misp(domain):
    return search_in_misp("domain", domain)

# Function to analyse the ip with MISP
def check_ipsrc_misp(ip):
    return search_in_misp("ip-src", ip)

# Function to analyse the ip with MISP
def check_ipdst_misp(ip):
    return search_in_misp("ip-dst", ip)

# Function to detect pop-up windows
def is_popup_present(driver):
    try:
        # Check for the presence of a 'div' or 'section' with a fixed or absolute position
        popups = driver.find_elements(By.CSS_SELECTOR, 'div[style*="position: fixed"], section[style*="position: fixed"], div[style*="position: absolute"], section[style*="position: absolute"], div[role="dialog"]')

        for popup in popups:
            # Check that the item is visible on the screen
            if popup.is_displayed():
                print("Pop-up is present")
                return True
        print("No pop-up present")
        return False
    except Exception as e:
        print(f"Error when detecting pop-up: {e}")
        return False

# Function for taking a screenshot of the site
def take_screenshot(url, domain):
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    screenshot_name = f"{domain}{timestamp}.png"
    screenshot_path = f"static/snapshots/{screenshot_name}"

    try:
        driver = get_chrome_driver(binary_path)
        driver.get(url)

        # Retrieving window sizes
        total_height = driver.execute_script("return document.body.scrollHeight")

        # Adjust the width
        driver.set_window_size(1366, total_height)

        # Save screenshot
        driver.save_screenshot(screenshot_path)

        # Delete cookies before exiting
        driver.delete_all_cookies()
        driver.quit()
        print(f"A screenshot was taken and saved in {screenshot_path}")
        return screenshot_name

    except Exception as e:
        print(f"Error when taking a screenshot: {e}")
        return None

# Function for taking a screenshot of the site without a pop-up windows
def take_screenshot_without_popup(url, domain, file_path):
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    screenshot_name = f"{domain}{timestamp}-wp.png"
    screenshot_path = f"static/snapshots/{screenshot_name}"
    
    # Load keywords from the text file
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            deny_button = [line.strip() for line in file.readlines()]
    except Exception as e:
        print(f"Error when reading the file {file_path}: {e}")
        return []

    try:
        driver = get_chrome_driver(binary_path)
        driver.get(url)

        # Check for pop-ups and close if present
        if is_popup_present(driver):
            try:
                # Search for a button containing one of these keywords
                for keyword in deny_button:
                    try:
                        button = WebDriverWait(driver, 3).until(
                            EC.element_to_be_clickable((By.XPATH, f"//button//*[contains(text(), '{keyword}')]"))
                        )
                        # Scroll to the bottom of the page to make the pop-up visible
                        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")

                        # Click on the button
                        driver.execute_script("arguments[0].click();", button)
                        print(f"Pop-up: {keyword} click performed")
                        break  # Exit the loop once the button has been found and clicked
                    except Exception as e:
                        # If the element is not found with this keyword, we move on to the next one
                        continue

            except Exception as e:
                print(f"Error when refusing pop-up: {e}")
                driver.quit()
                return None, None
        else:
            driver.quit()
            return False, None

        # Retrieving window sizes
        total_height = driver.execute_script("return document.body.scrollHeight")

        # Adjust the width
        driver.set_window_size(1366, total_height)

        # Save screenshot
        driver.save_screenshot(screenshot_path) 

        # Delete cookies before exiting
        driver.delete_all_cookies()
        driver.quit()
        print(f"A screenshot was taken and saved in {screenshot_path}")
        return True, screenshot_name

    except Exception as e:
        print(f"Error when taking a screenshot: {e}")
        return None, None

# Main function for URL analysis
def url_analysis(url):
    resultats = {}

    print(f"Analysed url: {url}")

    # Set date and time of analysis
    timestamp = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
    resultats['timestamp'] = timestamp

    # Check that the domain is valid and has an ip address
    domain_is_valid, domain_ip_address = domain_exists(url)
    resultats['domain_is_valid'] = domain_is_valid
    resultats['domain_ip_address'] = domain_ip_address

    # Extract the domain name
    domain_extracted = extract_domain(url)
    resultats['domain_extracted'] = domain_extracted
    # Extract the sub-domain name
    subdomain_extracted = extract_subdomain(url)
    resultats['subdomain_extracted'] = subdomain_extracted

    # Check whether the URL contains non-ASCII characters
    non_ascii_caracters = detect_non_ascii_caracters(domain_extracted)
    resultats['non_ascii_caracters'] = non_ascii_caracters

    # Check whether the domain is typosquatted
    char_similarities = load_char_similarities("data/dictionary/char_similarities.txt") 
    domain_variations = generate_domain_variations(domain_extracted, char_similarities)
    # Compare variations with Umbrella
    typosquat_found_domains, typosquat_list_domains = compare_with_umbrella(domain_extracted, domain_variations, "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip", "data/domain/top-1m.csv.zip", "data/domain/top_1m_umbrella.txt")
    if typosquat_found_domains:
        resultats['typosquat_found_domains'] = typosquat_found_domains
        resultats['typosquat_list_domains'] = typosquat_list_domains
    else:
        resultats['typosquat_found_domains'] = typosquat_found_domains
    # Compare variations with the list of French public organisation
    typosquat_fr_found_domains, typosquat_fr_list_domains = compare_with_french_public_org(domain_extracted, domain_variations, "https://raw.githubusercontent.com/etalab/noms-de-domaine-organismes-secteur-public/refs/heads/master/urls.txt", "data/domain/french_public_organism.txt")
    if typosquat_fr_found_domains:
        resultats['typosquat_fr_found_domains'] = typosquat_fr_found_domains
        resultats['typosquat_fr_list_domains'] = typosquat_fr_list_domains
    else:
        resultats['typosquat_fr_found_domains'] = typosquat_fr_found_domains

    if resultats['domain_is_valid']:

        ip = resultats['domain_ip_address']

        # Get WHOIS information
        domain_is_new, domain_creation_date, domain_expiration_date = get_domain_whois_informations(domain_extracted)
        resultats['domain_is_new'] = domain_is_new
        resultats['domain_creation_date'] = domain_creation_date
        resultats['domain_expiration_date'] = domain_expiration_date

        # Extract ip informations
        ip_organisation, ip_country = get_ip_informations(ip)
        resultats['ip_organisation'] = ip_organisation
        resultats['ip_country'] = ip_country

        # Check SSL certificate
        is_https = start_with_https(url)
        resultats['is_https'] = is_https
        if is_https:
            cert_info, cert_info_subject, cert_info_issuer, cert_info_notbefore, cert_info_notafter, cert_is_self_signed, cert_is_expired = get_ssl_certificate_info(subdomain_extracted)
            resultats['cert_info'] = cert_info
            resultats['cert_info_subject'] = cert_info_subject
            resultats['cert_info_issuer'] =  cert_info_issuer
            resultats['cert_info_notbefore'] = cert_info_notbefore
            resultats['cert_info_notafter'] = cert_info_notafter
            resultats['cert_is_self_signed'] = cert_is_self_signed
            resultats['cert_is_expired'] = cert_is_expired           
        else:
            cert_info_subject = ""
            resultats['cert_is_self_signed'] = None
            resultats['cert_is_expired'] = None

        # Check if the URL contains Punycode
        punycode_detected, punycode_url_decoded = detect_and_decode_punycode(url, domain_extracted)
        resultats['punycode_detected'] = punycode_detected
        resultats['punycode_url_decoded'] = punycode_url_decoded

        if punycode_detected:
            # Extract the domain name
            domain_extracted_after_punycode_decoded = extract_domain(punycode_url_decoded)
            resultats['domain_extracted_after_punycode_decoded'] = domain_extracted_after_punycode_decoded
            # Check whether the URL contains non-ASCII characters
            non_ascii_caracters_after_punycode_decoded = detect_non_ascii_caracters(domain_extracted_after_punycode_decoded)
            resultats['non_ascii_caracters_after_punycode_decoded'] = non_ascii_caracters_after_punycode_decoded

        # Detect shortened urls
        url_short_detected, url_long = detect_shortened_url(domain_extracted, url, "data/dictionary/url_shortener_domain.txt")
        resultats['url_short_detected'] = url_short_detected
        resultats['url_long'] = url_long

        if "ERROR" not in cert_info_subject:
            # Check if there is a file to download, if so with its name
            downloadable, downloadable_filename = detect_download_filename(url, "data/dictionary/mime_types.txt")
            resultats['downloadable'] = downloadable
            resultats['downloadable_filename'] = downloadable_filename

            # Check for redirections
            redirection, redirection_final_url = check_redirection(url)
            resultats['redirection'] = redirection
            resultats['redirection_final_url'] = redirection_final_url

            # Check the html code for suspicious elements
            html_is_there_external_domain, html_external_domains_list, html_is_there_hidden_images, html_is_there_hidden_links, html_is_there_hidden_forms, html_is_there_hidden_inputs, html_is_there_hidden_iframes = check_html_code(url)
            resultats['html_is_there_external_domain'] = html_is_there_external_domain
            resultats['html_external_domains_list'] = html_external_domains_list
            resultats['html_is_there_hidden_images'] = html_is_there_hidden_images
            resultats['html_is_there_hidden_links'] = html_is_there_hidden_links
            resultats['html_is_there_hidden_forms'] = html_is_there_hidden_forms
            resultats['html_is_there_hidden_inputs'] = html_is_there_hidden_inputs
            resultats['html_is_there_hidden_iframes'] = html_is_there_hidden_iframes

            # Check the javascript code for suspicious elements
            js_detected, js_redirection, js_keylogging, js_dom_manipulation = check_js_in_html(url)
            resultats['js_detected'] = js_detected
            resultats['js_redirection'] = js_redirection
            resultats['js_keylogging'] = js_keylogging
            resultats['js_dom_manipulation'] = js_dom_manipulation

            # Screenshot of the URL
            screenshot_name = take_screenshot(url, domain_extracted)
            if screenshot_name:
                resultats['screenshot_name'] = screenshot_name
            else:
                resultats['screenshot_name'] = None

            # Screenshot of URL without pop-up
            is_there_popup, screenshot_name_without_popup = take_screenshot_without_popup(url, domain_extracted, "data/dictionary/deny_button.txt")
            if is_there_popup:
                resultats['is_there_popup'] = is_there_popup
                resultats['screenshot_name_without_popup'] = screenshot_name_without_popup
            else:
                resultats['is_there_popup'] = False
                resultats['screenshot_name_without_popup'] = None

        else:
            resultats['downloadable'] = None
            resultats['redirection'] = None
            resultats['html_is_there_external_domain'] = None
            resultats['html_is_there_hidden_images'] = None
            resultats['html_is_there_hidden_links'] = None
            resultats['html_is_there_hidden_forms'] = None
            resultats['html_is_there_hidden_inputs'] = None
            resultats['html_is_there_hidden_iframes'] = None
            resultats['js_detected'] = None
            resultats['js_redirection'] = None
            resultats['js_keylogging'] = None
            resultats['js_dom_manipulation'] = None
            resultats['screenshot_name'] = None
            resultats['is_there_popup'] = False
            resultats['screenshot_name_without_popup'] = None

        # Check if url is present in the Openphish list
        known_url_by_openphish = check_attribute_in_txt_list(url, "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt", "data/url/openphish.txt")
        resultats['known_url_by_openphish'] = known_url_by_openphish

        # Check if url is present in the Urlhaus list
        known_url_by_urlhaus = check_attribute_in_txt_list(url, "https://urlhaus.abuse.ch/downloads/text_recent/", "data/url/urlhaus.txt")
        resultats['known_url_by_urlhaus'] = known_url_by_urlhaus

        # Check if url is present in the Phishing Database lists
        known_url_by_phishing_database_newtoday = check_attribute_in_txt_list(url, "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-links-NEW-today.txt", "data/url/phishing_database_newtoday.txt")
        resultats['known_url_by_phishing_database_newtoday'] = known_url_by_phishing_database_newtoday
        known_url_by_phishing_database_activelinks = check_attribute_in_txt_list(url, "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-links-ACTIVE.txt", "data/url/phishing_database_activelinks.txt")
        resultats['known_url_by_phishing_database_activelinks'] = known_url_by_phishing_database_activelinks

        # Check if url is present in the Phishunt list
        known_url_by_phishunt = check_attribute_in_txt_list(url, "https://phishunt.io/feed.txt", "data/url/phishunt.txt")
        resultats['known_url_by_phishunt'] = known_url_by_phishunt

        # Check if url is present in the Urlabuse lists
        known_url_by_urlabuse_malware = check_attribute_in_txt_list(url, "https://urlabuse.com/public/data/malware_url.txt", "data/url/urlabuse_malware.txt")
        resultats['known_url_by_urlabuse_malware'] = known_url_by_urlabuse_malware
        known_url_by_urlabuse_phishing = check_attribute_in_txt_list(url, "https://urlabuse.com/public/data/phishing_url.txt", "data/url/urlabuse_phishing.txt")
        resultats['known_url_by_urlabuse_phishing'] = known_url_by_urlabuse_phishing
        known_url_by_urlabuse_hacked = check_attribute_in_txt_list(url, "https://urlabuse.com/public/data/hacked_url.txt", "data/url/urlabuse_hacked.txt")
        resultats['known_url_by_urlabuse_hacked'] = known_url_by_urlabuse_hacked

        # Check if url is present in the Threatview list
        known_url_by_threatview = check_attribute_in_txt_list(url, "https://threatview.io/Downloads/URL-High-Confidence-Feed.txt", "data/url/threatview.txt")
        resultats['known_url_by_threatview'] = known_url_by_threatview

        # Check if url is present in the Trcert list
        known_url_by_trcert = check_attribute_in_txt_list(url, "https://raw.githubusercontent.com/cenk/trcert-malware/main/trcert-urls.txt", "data/url/trcert.txt")
        resultats['known_url_by_trcert'] = known_url_by_trcert

        # Check if domain is present in the Phishing Army list
        known_domain_by_phishing_army = check_attribute_in_txt_list(subdomain_extracted, "https://phishing.army/download/phishing_army_blocklist.txt", "data/domain/phishing_army.txt")
        resultats['known_domain_by_phishing_army'] = known_domain_by_phishing_army

        # Check if domain is present in the ShadowWhisperer lists
        known_domain_by_shadowwhisperer_malware = check_attribute_in_txt_list(subdomain_extracted, "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/refs/heads/master/RAW/Malware", "data/domain/shadowwhisperer_malware.txt")
        resultats['known_domain_by_shadowwhisperer_malware'] = known_domain_by_shadowwhisperer_malware
        known_domain_by_shadowwhisperer_scam = check_attribute_in_txt_list(subdomain_extracted, "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/refs/heads/master/RAW/Scam", "data/domain/shadowwhisperer_scam.txt")
        resultats['known_domain_by_shadowwhisperer_scam'] = known_domain_by_shadowwhisperer_scam
        known_domain_by_shadowwhisperer_urlshortener = check_attribute_in_txt_list(subdomain_extracted, "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/refs/heads/master/RAW/UrlShortener", "data/domain/shadowwhisperer_urlshortener.txt")
        resultats['known_domain_by_shadowwhisperer_urlshortener'] = known_domain_by_shadowwhisperer_urlshortener

        # Check if domain is present in the Adguardteam lists
        known_domain_by_adguardteam_f10 = check_attribute_in_txt_list(subdomain_extracted, "https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt", "data/domain/adguard_filter_10.txt")
        resultats['known_domain_by_adguardteam_f10'] = known_domain_by_adguardteam_f10
        known_domain_by_adguardteam_f11 = check_attribute_in_txt_list(subdomain_extracted, "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt", "data/domain/adguard_filter_11.txt")
        resultats['known_domain_by_adguardteam_f11'] = known_domain_by_adguardteam_f11
        known_domain_by_adguardteam_f30 = check_attribute_in_txt_list(subdomain_extracted, "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt", "data/domain/adguard_filter_30.txt")
        resultats['known_domain_by_adguardteam_f30'] = known_domain_by_adguardteam_f30
        known_domain_by_adguardteam_f34 = check_attribute_in_txt_list(subdomain_extracted, "https://adguardteam.github.io/HostlistsRegistry/assets/filter_34.txt", "data/domain/adguard_filter_34.txt")
        resultats['known_domain_by_adguardteam_f34'] = known_domain_by_adguardteam_f34
        known_domain_by_adguardteam_f41 = check_attribute_in_txt_list(subdomain_extracted, "https://adguardteam.github.io/HostlistsRegistry/assets/filter_41.txt", "data/domain/adguard_filter_41.txt")
        resultats['known_domain_by_adguardteam_f41'] = known_domain_by_adguardteam_f41
        
        # Check if domain is present in the Duggytuxy list
        known_domain_by_duggytuxy = check_attribute_in_txt_list(subdomain_extracted, "https://raw.githubusercontent.com/duggytuxy/phishing_scam_domains/refs/heads/main/phishing_scam_domains.txt", "data/domain/duggytuxy.txt")
        resultats['known_domain_by_duggytuxy'] = known_domain_by_duggytuxy

        # Check if domain is present in the Discord-AntiScam list
        known_domain_by_discordantiscan = check_attribute_in_txt_list(subdomain_extracted, "https://raw.githubusercontent.com/Discord-AntiScam/scam-links/refs/heads/main/list.txt", "data/domain/discord-antiscam.txt")
        resultats['known_domain_by_discordantiscan'] = known_domain_by_discordantiscan

        # Check if domain is present in the Wu Tingfeng list
        known_domain_by_elliotwutingfeng = check_attribute_in_txt_list(subdomain_extracted, "https://raw.githubusercontent.com/elliotwutingfeng/GlobalAntiScamOrg-blocklist/refs/heads/main/global-anti-scam-org-scam-urls.txt", "data/domain/elliotwutingfeng.txt")
        resultats['known_domain_by_elliotwutingfeng'] = known_domain_by_elliotwutingfeng

        # Check if domain is present in the Threatview list
        known_domain_by_threatview = check_attribute_in_txt_list(subdomain_extracted, "https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt", "data/domain/threatview.txt")
        resultats['known_domain_by_threatview'] = known_domain_by_threatview

        # Check if ip is present in the Duggytuxy list
        known_ip_by_duggytuxy = check_attribute_in_txt_list(ip, "https://raw.githubusercontent.com/duggytuxy/malicious_ip_addresses/refs/heads/main/botnets_zombies_scanner_spam_ips.txt", "data/ip/duggytuxy.txt")
        resultats['known_ip_by_duggytuxy'] = known_ip_by_duggytuxy

        # Check if ip is present in the Bitwire list
        known_ip_by_bitwire = check_attribute_in_txt_list(ip, "https://raw.githubusercontent.com/bitwire-it/ipblocklist/refs/heads/main/ip-list.txt", "data/ip/bitwire.txt")
        resultats['known_ip_by_bitwire'] = known_ip_by_bitwire

        # Check if ip is present in the Binary Defense list
        known_ip_by_binarydefense = check_attribute_in_txt_list(ip, "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/bds_atif.ipset", "data/ip/binarydefense.txt")
        resultats['known_ip_by_binarydefense'] = known_ip_by_binarydefense

        # Check if ip is present in the Blocklist.de list
        known_ip_by_blocklistde = check_attribute_in_txt_list(ip, "http://lists.blocklist.de/lists/all.txt", "data/ip/blocklistde.txt")
        resultats['known_ip_by_blocklistde'] = known_ip_by_blocklistde

        # Check if ip is present in the Clean-MX.de lists
        known_ip_by_cleanmxde_spam = check_attribute_in_txt_list(ip, "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/cleanmx_phishing.ipset", "data/ip/cleanmxde_spam.txt")
        resultats['known_ip_by_cleanmxde_spam'] = known_ip_by_cleanmxde_spam
        known_ip_by_cleanmxde_viruses = check_attribute_in_txt_list(ip, "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/cleanmx_viruses.ipset", "data/ip/cleanmxde_viruses.txt")
        resultats['known_ip_by_cleanmxde_viruses'] = known_ip_by_cleanmxde_viruses

        # Check if ip is present in the EmergingThreats.net list
        known_ip_by_emergingthreats = check_attribute_in_txt_list(ip, "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "data/ip/emergingthreats.txt")
        resultats['known_ip_by_emergingthreats'] = known_ip_by_emergingthreats

        # Check if ip is present in the FireHOL list
        known_ip_by_firehol = check_attribute_in_txt_list(ip, "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/firehol_abusers_30d.netset", "data/ip/firehol.txt")
        resultats['known_ip_by_firehol'] = known_ip_by_firehol

        # Check if url, domain or ip is present in VirusTotal
        if vt_api_key:
            resultats['vt_api_key'] = True

            vt_url_known, vt_url_malicious, vt_url_total = check_url_vt(url)
            if vt_url_known is None:
                resultats['vt_url_error'] = True
                resultats['vt_url_reason'] = vt_url_malicious
                resultats['vt_url_malicious'] = 0
            else:
                resultats['vt_url_known'] = vt_url_known
                resultats['vt_url_malicious'] = vt_url_malicious
                resultats['vt_url_total'] = vt_url_total
            
            vt_domain_known, vt_domain_malicious, vt_domain_total = check_domain_vt(subdomain_extracted)
            if vt_domain_known is None:
                resultats['vt_domain_error'] = True
                resultats['vt_domain_reason'] = vt_domain_malicious
                resultats['vt_domain_malicious'] = 0
            else:
                resultats['vt_domain_known'] = vt_domain_known
                resultats['vt_domain_malicious'] = vt_domain_malicious
                resultats['vt_domain_total'] = vt_domain_total

            vt_ip_known, vt_ip_malicious, vt_ip_total = check_ip_vt(ip)
            if vt_ip_known is None:
                resultats['vt_ip_error'] = True
                resultats['vt_ip_reason'] = vt_ip_malicious
                resultats['vt_ip_malicious'] = 0
            else:
                resultats['vt_ip_known'] = vt_ip_known
                resultats['vt_ip_malicious'] = vt_ip_malicious
                resultats['vt_ip_total'] = vt_ip_total
        else:
            resultats['vt_api_key'] = False
            resultats['vt_url_malicious'] = 0
            resultats['vt_domain_malicious'] = 0
            resultats['vt_ip_malicious'] = 0

        # Check if url, domain or ip is present in AlienVault OTX
        if otx_api_key:
            resultats['otx_api_key'] = True

            otx_url_known, otx_url_nb_pulse = check_url_otx(url)
            if otx_url_known is None:
                resultats['otx_url_error'] = True
                resultats['otx_url_reason'] = otx_url_nb_pulse
                resultats['otx_url_nb_pulse'] = 0
            else:
                resultats['otx_url_known'] = otx_url_known
                resultats['otx_url_nb_pulse'] = otx_url_nb_pulse
            
            otx_domain_known, otx_domain_nb_pulse = check_domain_otx(subdomain_extracted)
            if otx_domain_known is None:
                resultats['otx_domain_error'] = True
                resultats['otx_domain_reason'] = otx_domain_nb_pulse
                resultats['otx_domain_nb_pulse'] = 0
            else:
                resultats['otx_domain_known'] = otx_domain_known
                resultats['otx_domain_nb_pulse'] = otx_domain_nb_pulse

            otx_ip_known, otx_ip_nb_pulse = check_ip_otx(ip)
            if otx_ip_known is None:
                resultats['otx_ip_error'] = True
                resultats['otx_ip_reason'] = otx_ip_nb_pulse
                resultats['otx_ip_nb_pulse'] = 0
            else:
                resultats['otx_ip_known'] = otx_ip_known
                resultats['otx_ip_nb_pulse'] = otx_ip_nb_pulse
        else:
            resultats['otx_api_key'] = False
            resultats['otx_url_nb_pulse'] = 0
            resultats['otx_domain_nb_pulse'] = 0
            resultats['otx_ip_nb_pulse'] = 0

        # Check if url, domain or ip is present in MISP
        if misp_url and misp_api_key:
            resultats['misp_api_key'] = True

            misp_url_known, misp_url_info = check_url_misp(url)
            if misp_url_known is None:
                resultats['misp_url_error'] = True
                resultats['misp_url_reason'] = misp_url_info
                resultats['misp_url_known'] = False
            else:
                resultats['misp_url_known'] = misp_url_known
            
            misp_domain_known, misp_domain_info = check_domain_misp(subdomain_extracted)
            if misp_domain_known is None:
                resultats['misp_domain_error'] = True
                resultats['misp_domain_reason'] = misp_domain_info
                resultats['misp_domain_known'] = False
            else:
                resultats['misp_domain_known'] = misp_domain_known

            misp_ipsrc_known, misp_ipsrc_info = check_ipsrc_misp(ip)
            misp_ipdst_known, misp_ipdst_info = check_ipdst_misp(ip)
            if misp_ipsrc_known is None and misp_ipdst_known is None:
                resultats['misp_ip_error'] = True
                resultats['misp_ip_reason'] = misp_ip_info
                resultats['misp_ip_known'] = False
            else:
                misp_ip_known = misp_ipsrc_known or misp_ipdst_known
                resultats['misp_ip_known'] = misp_ip_known
        else:
            resultats['misp_api_key'] = False
            resultats['misp_url_known'] = False
            resultats['misp_domain_known'] = False
            resultats['misp_ip_known'] = False

    else:
        resultats['domain_is_new'] = None
        resultats['cert_is_self_signed'] = None
        resultats['cert_is_expired'] = None
        resultats['downloadable'] = None
        resultats['punycode_detected'] = None
        resultats['non_ascii_caracters'] = None
        resultats['url_short_detected'] = None
        resultats['redirection'] = None
        resultats['html_is_there_external_domain'] = None
        resultats['html_is_there_hidden_images'] = None
        resultats['html_is_there_hidden_links'] = None
        resultats['html_is_there_hidden_forms'] = None
        resultats['html_is_there_hidden_inputs'] = None
        resultats['html_is_there_hidden_iframes'] = None
        resultats['js_detected'] = None
        resultats['js_redirection'] = None
        resultats['js_keylogging'] = None
        resultats['js_dom_manipulation'] = None
        resultats['known_url_by_openphish'] = None
        resultats['known_url_by_urlhaus'] = None
        resultats['known_url_by_phishing_database_newtoday'] = None
        resultats['known_url_by_phishing_database_activelinks'] = None
        resultats['known_url_by_phishunt'] = None
        resultats['known_url_by_urlabuse_malware'] = None
        resultats['known_url_by_urlabuse_phishing'] = None
        resultats['known_url_by_urlabuse_hacked'] = None
        resultats['known_url_by_threatview'] = None
        resultats['known_url_by_trcert'] = None
        resultats['vt_url_malicious'] = 0
        resultats['otx_url_nb_pulse'] = 0
        resultats['misp_url_known'] = None
        resultats['known_domain_by_phishing_army'] = None
        resultats['known_domain_by_shadowwhisperer_malware'] = None
        resultats['known_domain_by_shadowwhisperer_scam'] = None
        resultats['known_domain_by_shadowwhisperer_urlshortener'] = None
        resultats['known_domain_by_adguardteam_f10'] = None
        resultats['known_domain_by_adguardteam_f11'] = None
        resultats['known_domain_by_adguardteam_f30'] = None
        resultats['known_domain_by_adguardteam_f34'] = None
        resultats['known_domain_by_adguardteam_f41'] = None
        resultats['known_domain_by_duggytuxy'] = None
        resultats['known_domain_by_discordantiscan'] = None
        resultats['known_domain_by_elliotwutingfeng'] = None
        resultats['known_domain_by_threatview'] = None
        resultats['vt_domain_malicious'] = 0
        resultats['otx_domain_nb_pulse'] = 0
        resultats['misp_domain_known'] = None
        resultats['known_ip_by_duggytuxy'] = None
        resultats['known_ip_by_bitwire'] = None
        resultats['known_ip_by_binarydefense'] = None
        resultats['known_ip_by_blocklistde'] = None
        resultats['known_ip_by_cleanmxde_spam'] = None
        resultats['known_ip_by_cleanmxde_viruses'] = None
        resultats['known_ip_by_emergingthreats'] = None
        resultats['known_ip_by_firehol'] = None
        resultats['vt_ip_malicious'] = 0
        resultats['otx_ip_nb_pulse'] = 0
        resultats['misp_ip_known']= None

    # Calcul score general information
    if resultats['domain_is_new']:
        score_domain_is_new = 1
    else:
        score_domain_is_new = 0
    score_general_information = score_domain_is_new
    if score_general_information == 1:
        resultats['score_general_information'] = 2
    else:
        resultats['score_general_information'] = 0
    
    # Calcul certificate
    if resultats['cert_is_self_signed']:
        score_cert_is_self_signed = 1
    else:
        score_cert_is_self_signed = 0
    if resultats['cert_is_expired']:
        score_cert_is_expired = 1
    else:
        score_cert_is_expired = 0

    score_certificate_information = score_cert_is_self_signed + score_cert_is_expired
    if score_certificate_information == 2:
        resultats['score_certificate_information'] = 2
    elif score_certificate_information == 1:
        resultats['score_certificate_information'] = 1
    else:
        resultats['score_certificate_information'] = 0

    # Calcul behavior
    if resultats['downloadable']:
        score_downloadable = 1
    else:
        score_downloadable = 0
    if resultats['redirection']:
        score_redirection = 1
    else:
        score_redirection = 0
    
    score_behavior_information = score_downloadable + score_redirection
    if score_behavior_information == 2:
        resultats['score_behavior_information'] = 2
    elif score_behavior_information == 1:
        resultats['score_behavior_information'] = 1
    else:
        resultats['score_behavior_information'] = 0

    # Calcul detection masking
    if resultats['punycode_detected']:
        score_punycode_detected = 1
    else:
        score_punycode_detected = 0
    if resultats['non_ascii_caracters']:
        score_non_ascii_caracters = 1
    else:
        score_non_ascii_caracters = 0
    if resultats['url_short_detected']:
        score_url_short = 1
    else:
        score_url_short = 0
    if resultats['typosquat_found_domains'] or resultats['typosquat_fr_found_domains']:
        score_typosquat_found_domains = 3
    else:
        score_typosquat_found_domains = 0

    score_mask_information = score_punycode_detected + score_non_ascii_caracters + score_url_short + score_typosquat_found_domains
    if score_mask_information >=3:
        resultats['score_mask_information'] = 2
    elif score_mask_information > 0 and score_mask_information < 3:
        resultats['score_mask_information'] = 1
    else:
        resultats['score_mask_information'] = 0

    # Calcul html analysis
    if resultats['html_is_there_external_domain']:
        score_html_external_domains = 1
    else:
        score_html_external_domains = 0   
    if resultats['html_is_there_hidden_images']:
        score_html_hidden_images = 1
    else:
        score_html_hidden_images = 0
    if resultats['html_is_there_hidden_links']:
        score_html_hidden_links = 1
    else:
        score_html_hidden_links = 0
    if resultats['html_is_there_hidden_forms']:
        score_html_hidden_forms = 1
    else:
        score_html_hidden_forms = 0
    if resultats['html_is_there_hidden_inputs']:
        score_html_hidden_inputs = 1
    else:
        score_html_hidden_inputs = 0
    if resultats['html_is_there_hidden_iframes']:
        score_html_hidden_iframes = 1
    else:
        score_html_hidden_iframes = 0

    score_analysis_html = score_html_external_domains + score_html_hidden_images + score_html_hidden_links + score_html_hidden_forms + score_html_hidden_inputs + score_html_hidden_iframes
    if score_analysis_html >= 4:
        resultats['score_analysis_html'] = 2
    elif score_analysis_html > 0 and score_analysis_html < 4:
        resultats['score_analysis_html'] = 1
    else:
        resultats['score_analysis_html'] = 0
    
    # Calcul javascript analysis
    if resultats['js_detected']:
        if resultats['js_redirection']:
            score_js_redirection = 1
        else:
            score_js_redirection = 0
        if resultats['js_keylogging']:
            score_js_keylogging = 4
        else:
            score_js_keylogging = 0
        if resultats['js_dom_manipulation']:
            score_js_dom_manipulation = 1
        else:
            score_js_dom_manipulation = 0
    else:
        score_js_redirection = 0
        score_js_keylogging = 0
        score_js_dom_manipulation = 0

    score_analysis_js = score_js_redirection + score_js_keylogging + score_js_dom_manipulation
    if score_analysis_js >= 3:
        resultats['score_analysis_js'] = 2
    elif score_analysis_js > 0 and score_analysis_js < 3:
        resultats['score_analysis_js'] = 1
    else:
        resultats['score_analysis_js'] = 0
    
    # Calcul url reputation
    if resultats['known_url_by_openphish']:
        score_url_openphish = 1
    else:
        score_url_openphish = 0
    if resultats['known_url_by_urlhaus']:
        score_url_urlhaus = 1
    else:
        score_url_urlhaus = 0
    if resultats['known_url_by_phishing_database_newtoday'] == True or resultats['known_url_by_phishing_database_activelinks'] == True:
        score_url_phishing_database = 1
    else:
        score_url_phishing_database = 0
    if resultats['known_url_by_phishunt']:
        score_url_phishunt = 1
    else:
        score_url_phishunt = 0
    if resultats['known_url_by_urlabuse_malware'] == True or resultats['known_url_by_urlabuse_phishing'] == True or resultats['known_url_by_urlabuse_hacked'] == True:
        score_url_urlabuse = 1
    else:
        score_url_urlabuse = 0
    if resultats['known_url_by_threatview']:
        score_url_threatview = 1
    else:
        score_url_threatview = 0
    if resultats['known_url_by_trcert']:
        score_url_trcert = 1
    else:
        score_url_trcert = 0
    if resultats['vt_url_malicious'] >= 1:
        score_url_vt = 1
    else:
        score_url_vt = 0
    if resultats['misp_url_known']:
        score_url_misp = 1
    else:
        score_url_misp = 0

    score_malicious_url = score_url_openphish + score_url_urlhaus + score_url_phishing_database + score_url_phishunt + score_url_urlabuse + score_url_threatview + score_url_trcert + score_url_vt + score_url_misp
    if score_malicious_url >= 1:
        resultats['score_malicious_url'] = 2
    else:
        resultats['score_malicious_url'] = 0
    
    # Calcul domain reputation
    if resultats['known_domain_by_phishing_army']:
        score_domain_phishing_army = 1
    else:
        score_domain_phishing_army = 0
    if resultats['known_domain_by_shadowwhisperer_malware'] == True or resultats['known_domain_by_shadowwhisperer_scam'] == True or resultats['known_domain_by_shadowwhisperer_urlshortener'] == True:
        score_domain_shadowwhisperer = 1
    else:
        score_domain_shadowwhisperer = 0
    if resultats['known_domain_by_adguardteam_f10'] == True or resultats['known_domain_by_adguardteam_f11'] == True or resultats['known_domain_by_adguardteam_f30'] == True or resultats['known_domain_by_adguardteam_f34'] == True or resultats['known_domain_by_adguardteam_f41'] == True:
        score_domain_adguardteam = 1
    else:
        score_domain_adguardteam = 0
    if resultats['known_domain_by_duggytuxy']:
        score_domain_duggytuxy = 1
    else:
        score_domain_duggytuxy = 0
    if resultats['known_domain_by_discordantiscan']:
        score_domain_discordantiscan = 1
    else:
        score_domain_discordantiscan = 0
    if resultats['known_domain_by_elliotwutingfeng']:
        score_domain_elliotwutingfeng = 1
    else:
        score_domain_elliotwutingfeng = 0
    if resultats['known_domain_by_threatview']:
        score_domain_threatview = 1
    else:
        score_domain_threatview = 0
    if resultats['vt_domain_malicious'] >= 1:
        score_domain_vt = 1
    else:
        score_domain_vt = 0
    if resultats['misp_domain_known']:
        score_domain_misp = 1
    else:
        score_domain_misp = 0

    score_malicious_domain = score_domain_phishing_army + score_domain_shadowwhisperer + score_domain_adguardteam + score_domain_duggytuxy + score_domain_discordantiscan + score_domain_elliotwutingfeng + score_domain_threatview + score_domain_vt + score_domain_misp
    if score_malicious_domain >= 3:
        resultats['score_malicious_domain'] = 2
    elif score_malicious_domain > 0 and score_malicious_domain < 3:
        resultats['score_malicious_domain'] = 1
    else:
        resultats['score_malicious_domain'] = 0
    
    # Calcul ip reputation
    if resultats['known_ip_by_duggytuxy']:
        score_ip_duggytuxy = 1
    else:
        score_ip_duggytuxy = 0
    if resultats['known_ip_by_bitwire']:
        score_ip_bitwire = 1
    else:
        score_ip_bitwire = 0
    if resultats['known_ip_by_binarydefense']:
        score_ip_binarydefense = 1
    else:
        score_ip_binarydefense = 0
    if resultats['known_ip_by_blocklistde']:
        score_ip_blocklistde = 1
    else:
        score_ip_blocklistde = 0
    if resultats['known_ip_by_cleanmxde_spam'] == True or resultats['known_ip_by_cleanmxde_viruses'] == True:
        score_ip_cleanmxde = 1
    else:
        score_ip_cleanmxde = 0
    if resultats['known_ip_by_emergingthreats']:
        score_ip_emergingthreats = 1
    else:
        score_ip_emergingthreats = 0
    if resultats['known_ip_by_firehol']:
        score_ip_firehol = 1
    else:
        score_ip_firehol = 0
    if resultats['vt_ip_malicious'] >= 1:
        score_ip_vt = 1
    else:
        score_ip_vt = 0
    if resultats['misp_ip_known']:
        score_ip_misp = 1
    else:
        score_ip_misp = 0

    score_malicious_ip = score_ip_duggytuxy + score_ip_bitwire + score_ip_binarydefense + score_ip_blocklistde + score_ip_cleanmxde + score_ip_emergingthreats + score_ip_firehol + score_ip_vt + score_ip_misp
    if score_malicious_ip >= 5:
        resultats['score_malicious_ip'] = 2
    elif score_malicious_ip > 0 and score_malicious_ip < 5:
        resultats['score_malicious_ip'] = 1
    else:
        resultats['score_malicious_ip'] = 0
    
    # Calcul final score
    if score_general_information == 2 or score_certificate_information == 2 or score_behavior_information == 2 or score_mask_information >= 3 or score_analysis_html >= 4 or score_analysis_js >= 3 or score_malicious_url >= 1 or score_malicious_domain >= 3 or score_malicious_ip >= 5:
        resultats['score_general'] = 2
    elif score_general_information == 0 and score_certificate_information == 0 and score_behavior_information == 0 and score_mask_information == 0 and score_analysis_html == 0 and score_analysis_js == 0 and score_malicious_url == 0 and score_malicious_domain == 0 and score_malicious_ip == 0:
        resultats['score_general'] = 0
    else:
        resultats['score_general'] = 1

    return resultats