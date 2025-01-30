import streamlit as st
import numpy as np
import pickle
from tld import get_tld  # Ensure you have the `tld` library installed

def load_model(path):
    # Load the saved random forest model 
    with open(path, 'rb') as file:
        model = pickle.load(file)
        return model

from feature_extraction import (  # Import functions
    having_ip_address, abnormal_url, count_dot, count_www,
    count_atrate, no_of_dir, no_of_embed, shortening_service,
    count_percentage, count_question_marks,
    count_hyphen, count_equal, url_length, hostname_length,
    suspicious_words, digit_count, letter_count, fd_length, tld_length
)

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

def main(path):
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
