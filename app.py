import re
from urllib.parse import urlparse
import sys
import streamlit as st
import numpy as np
import pickle
from tld import get_tld  # Ensure you have the `tld` library installed

#Use of IP or not in domain
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0
    
def abnormal_url(url):
    hostname = urlparse(url).hostname
    # print(hostname)
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

def count_dot(url):
    count_dot = url.count('.')
    return count_dot
  
def count_www(url):
    url.count('www')
    return url.count('www')


def count_atrate(url):

    return url.count('@')


def no_of_dir(url):
    urldir = urlparse(url).path
    # print(urldir)
    return urldir.count('/')
# no_of_dir("https://en.wikipedia.org/wiki/API")


def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')


def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0

# def count_https(url):
#     return url.count('https')


# def count_http(url):
#     return url.count('http')


def count_percentage(url):
    return url.count('%')

def count_question_marks(url):
    return url.count('?')


def count_hyphen(url):
    return url.count('-')


def count_equal(url):
    return url.count('=')

def url_length(url):
    return len(str(url))


def hostname_length(url):
    return len(urlparse(url).netloc)


def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                      url)
    if match:
        return 1
    else:
        return 0


def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits


def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters

#First Directory Length
def fd_length(url):
    urlpath= urlparse(url).path
    # print(urlpath)
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0
# print(fd_length("bopsecrets.org/rexroth/cr/1.htm"))

#Length of Top Level Domain

def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1

def load_model(path):
    # Load the saved random forest model 
    with open(path, 'rb') as file:
        model = pickle.load(file)
        return model

def url_to_features(url):
    features = []
    features.append(having_ip_address(url))
    features.append(abnormal_url(url))
    features.append(count_dot(url))
    features.append(count_www(url))
    features.append(count_atrate(url))
    features.append(no_of_dir(url))
    features.append(no_of_embed(url))
    features.append(shortening_service(url))
    features.append(count_percentage(url))
    features.append(count_question_marks(url))
    features.append(count_hyphen(url))
    features.append(count_equal(url))
    features.append(url_length(url))
    features.append(hostname_length(url))
    features.append(suspicious_words(url))
    features.append(fd_length(url))
    tld = get_tld(url, fail_silently=True)
    features.append(tld_length(tld))
    features.append(digit_count(url))
    features.append(letter_count(url))
    return features

def get_name(i):
    if int(i) == 0:
        return "SAFE"
    elif int(i) == 1:
        return "DEFACEMENT"
    elif int(i) == 2:
        return "PHISHING"
    elif int(i) == 3:
        return "MALWARE"

def get_prediction_from_url(url, model):
    features = get_features(url)
    features = np.array(features).reshape((1, -1))
    print(features)
    pred = model.predict(features)

    return get_name(pred[0])

def main():
    # Get the path as a commandline argument
    path = sys.argv[1]

    # Load the model
    model = load_model(path)

    # Streamlit App
    st.title("Malicious URL Detector")
    st.markdown("""
    ### About the App
    This application classifies URLs as **SAFE**, **DEFACEMENT**, **PHISHING**, or **MALWARE** using a pre-trained Random Forest model. 
    Enter a URL in the input box, and click **Predict** to see the results.
    """)
    
    # User input for URL
    url = st.text_input("Enter a URL:", "")
    
    if st.button("Predict"):
        if url:
            try:
                pred = get_prediction_from_url(url, model)
                st.success(f"The URL is classified as: **{pred}**.")
            except Exception as e:
                st.error(f"Error processing the URL: {e}")
        else:
            st.warning("Please enter a URL to proceed.")

main()
