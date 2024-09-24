from flask import Flask, request, render_template
import numpy as np
import pandas as pd
from sklearn import metrics 
import warnings
import pickle
warnings.filterwarnings('ignore')
from feature import FeatureExtraction

# Load the model
try:
    with open("pickle/model.pkl", "rb") as file:
        gbc = pickle.load(file)
except Exception as e:
    raise Exception(f"Error loading model: {e}")

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        try:
            obj = FeatureExtraction(url)
            features = obj.getFeaturesList()
            x = np.array(features).reshape(1, -1)  # Adjust reshape if needed

            if not hasattr(gbc, 'predict'):
                raise ValueError("Loaded object is not a valid model.")
            
            y_pred = gbc.predict(x)[0]
            y_pro_phishing = gbc.predict_proba(x)[0, 0]
            y_pro_non_phishing = gbc.predict_proba(x)[0, 1]

            pred = "It is {0:.2f} % safe to go ".format(y_pro_phishing * 100)
            return render_template('index.html', xx=round(y_pro_non_phishing, 2), url=url)
        except Exception as e:
            return str(e), 500
    return render_template("index.html", xx=-1)

if __name__ == "__main__":
    app.run(debug=True)
