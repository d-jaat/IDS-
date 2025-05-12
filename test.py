import pandas as pd
import joblib
# Assuming features is a dictionary of extracted features
features_df = pd.DataFrame([features])

# Load the pre-trained model
model = joblib.load('model.pkl')
