import streamlit as st
import joblib
import pandas as pd
import numpy as np
import tldextract


# Load the trained model
model = joblib.load('Phishing_best.pkl')

# Function to extract features from the URL
def extract_features(url):
    domain_info = tldextract.extract(url)
    domain = domain_info.domain
    subdomain = domain_info.subdomain
    suffix = domain_info.suffix

    features = {
        'url_length': len(url),
        'number_of_dots_in_url': url.count('.'),
        'having_repeated_digits_in_url': int(any(url.count(c) > 1 for c in url if c.isdigit())),
        'number_of_digits_in_url': sum(c.isdigit() for c in url),
        'number_of_special_char_in_url': sum(not c.isalnum() and c not in ['.', '/'] for c in url),
        'number_of_hyphens_in_url': url.count('-'),
        'number_of_underline_in_url': url.count('_'),
        'number_of_slash_in_url': url.count('/'),
        'number_of_questionmark_in_url': url.count('?'),
        'number_of_equal_in_url': url.count('='),
        'number_of_at_in_url': url.count('@'),
        'number_of_dollar_in_url': url.count('$'),
        'number_of_exclamation_in_url': url.count('!'),
        'number_of_hashtag_in_url': url.count('#'),
        'number_of_percent_in_url': url.count('%'),
        'domain_length': len(domain + '.' + suffix),
        'number_of_dots_in_domain': domain.count('.'),
        'number_of_hyphens_in_domain': domain.count('-'),
        'having_special_characters_in_domain': int(any(not c.isalnum() for c in domain)),
        'number_of_special_characters_in_domain': sum(not c.isalnum() for c in domain),
        'having_digits_in_domain': int(any(c.isdigit() for c in domain)),
        'number_of_digits_in_domain': sum(c.isdigit() for c in domain),
        'having_repeated_digits_in_domain': int(any(domain.count(c) > 1 for c in domain if c.isdigit())),
        'number_of_subdomains': subdomain.count('.') + 1 if subdomain else 0,
        'having_dot_in_subdomain': int('.' in subdomain),
        'having_hyphen_in_subdomain': int('-' in subdomain),
        'average_subdomain_length': len(subdomain) / (subdomain.count('.') + 1) if subdomain else 0,
        'average_number_of_dots_in_subdomain': subdomain.count('.') / (subdomain.count('.') + 1) if subdomain else 0,
        'average_number_of_hyphens_in_subdomain': subdomain.count('-') / (subdomain.count('.') + 1) if subdomain else 0,
        'having_special_characters_in_subdomain': int(any(not c.isalnum() for c in subdomain)),
        'number_of_special_characters_in_subdomain': sum(not c.isalnum() for c in subdomain),
        'having_digits_in_subdomain': int(any(c.isdigit() for c in subdomain)),
        'number_of_digits_in_subdomain': sum(c.isdigit() for c in subdomain),
        'having_repeated_digits_in_subdomain': int(any(subdomain.count(c) > 1 for c in subdomain if c.isdigit())),
        'having_path': int('/' in url.split(domain + '.' + suffix)[-1]),
        'path_length': len(url.split(domain + '.' + suffix)[-1].split('?')[0].split('#')[0]),
        'having_query': int('?' in url),
        'having_fragment': int('#' in url),
        'having_anchor': int('@' in url),
        'entropy_of_url': -sum([float(url.count(c)) / len(url) * np.log2(float(url.count(c)) / len(url)) for c in set(url)]),
        'entropy_of_domain': -sum([float(domain.count(c)) / len(domain) * np.log2(float(domain.count(c)) / len(domain)) for c in set(domain)])
    }

    return pd.DataFrame(features, index=[0])

# Streamlit app
def main():
    st.title("Phishing URL Detection")
    st.write("Enter the URL to check if it is a phishing site")

    # Input URL
    url = st.text_input("URL", "http://example.com")

    # Extract features
    if st.button("Predict"):
        if url:
            features = extract_features(url)
            prediction = model.predict(features)[0]
            prediction_proba = model.predict_proba(features)[0]

            # Display the result
            if prediction == 1:
                st.error(f"This URL is likely a phishing site ")
            else:
                st.success(f"This URL is likely not a phishing site")
        else:
            st.warning("Please enter a valid URL")

if __name__ == "__main__":
    main()
