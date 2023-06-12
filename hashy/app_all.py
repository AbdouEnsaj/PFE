import nltk
import numpy as np
import pandas as pd
from nltk.corpus import stopwords
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
import requests
import time
import json
import re
import time
import json
from flask import Flask, render_template, request

app = Flask(__name__)



# Load the SpamHam dataset
spamham = pd.read_csv('/Users/LENOVO/Downloads/archive (8)/spam.csv', encoding='latin-1')

# Preprocess the data
spamham.drop(['Unnamed: 2', 'Unnamed: 3', 'Unnamed: 4'], axis=1, inplace=True)
spamham.rename(columns={'v1': 'label', 'v2': 'text'}, inplace=True)
spamham['label'] = np.where(spamham['label'] == 'spam', 1, 0)


# Data Cleaning
stop_words = stopwords.words('english')
spamham['text'] = spamham['text'].apply(lambda x: ' '.join([word for word in x.split() if word not in (stop_words)]))
spamham['text'] = spamham['text'].apply(lambda x: re.sub('[^a-zA-z0-9\s]', '', x))


# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(spamham['text'], spamham['label'], test_size=0.2, random_state=42)

# Create the vectorizer
vectorizer = TfidfVectorizer()

# Transform the training data
X_train_vectorized = vectorizer.fit_transform(X_train)

# Train the classifier
classifier = MultinomialNB()
classifier.fit(X_train_vectorized, y_train)



API_key = '1c5d6dfa26f66838c1345dabebcaedcb16840dcb990d415e5dca33bc3b272a27'
url = 'https://www.virustotal.com/vtapi/v2/url/report'

def check_url(domain):
    parameters = {'apikey': API_key, 'resource': domain}

    response = requests.get(url=url, params=parameters)
    json_response = json.loads(response.text)

    if json_response['response_code'] <= 0:
        return(f"The url '{domain}' was not found. Please scan it manually.")
    elif json_response['response_code'] >= 1:
        if json_response['positives'] <= 0:
            return("not malicious")
        else:
            return("malicious")

    time.sleep(15)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/result', methods=['POST'])
def result():
    # Get the form data
    domain = request.form['domain']
    subject = request.form['subject']
    body = request.form['body']

    # Check URL
    domain_result = check_url(domain)

   
    input_text_vectorized = vectorizer.transform([body])
    prediction= classifier.predict(input_text_vectorized)
    if prediction[0] == 1:
       body_result = "Phishing attempt"
    else:
       body_result = "Not a phishing attempt"


    input_text_vectorized = vectorizer.transform([subject])
    prediction= classifier.predict(input_text_vectorized)
    if prediction[0] == 1:
      subject_result = "Phishing attempt"
    else:
      subject_result = "Not a Phishing attempt"

  
    
    
    return render_template('result.html',
                           domain_result=domain_result,subject_result=subject_result, body_result=body_result)

if __name__ == '__main__':
    app.run(debug=True)
