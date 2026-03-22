import streamlit as st
import requests
import time
import base64
import os

# Set your VirusTotal API key from environment variable
API_KEY ="39abcf53f8589c70549b9ddbdd4940fb3f367c5e1cda4a4a1fe656fcbf7bdfae"  # It's better to store API keys securely, not hardcoded
URL = "https://www.virustotal.com/api/v3/urls"


# Function to encode the URL in base64
def encode_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


# Function to check website safety using VirusTotal
def check_website_virustotal(site_url):
    headers = {"x-apikey": API_KEY}

    # Encode the URL before sending the request
    encoded_url = encode_url(site_url)
    response = requests.get(f"{URL}/{encoded_url}", headers=headers)

    if response.status_code == 200:
        result = response.json()

        if "data" in result:
            stats = result["data"]["attributes"]["last_analysis_stats"]
            return stats
        return "Scan results not available yet"

    return f"Error scanning website (Status: {response.status_code})"


# Streamlit UI
st.title("🔍 Website Safety Checker")
st.write("Check if a website is safe using **VirusTotal**.")

# Input field for URL
site_url = st.text_input("Enter website URL (e.g., https://example.com)")

if st.button("Check Safety"):
    if site_url:
        with st.spinner("Checking... Please wait"):
            result = check_website_virustotal(site_url)

        # Display results
        if isinstance(result, dict):
            st.subheader("Scan Results")
            st.write(f"✅ **Harmless detections**: {result.get('harmless', 0)}")
            st.write(f"⚠️ **Suspicious detections**: {result.get('suspicious', 0)}")
            st.write(f"❌ **Malicious detections**: {result.get('malicious', 0)}")
        else:
            st.error(result)
    else:
        st.warning("Please enter a valid website URL.")

st.markdown("---")
