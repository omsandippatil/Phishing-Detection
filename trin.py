# trin.py

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib  # To save the trained model

def load_data(csv_file):
    """Load the dataset from CSV file."""
    df = pd.read_csv(csv_file)
    return df

def preprocess_data(df):
    """Preprocess the dataset, separating features and target."""
    X = df.drop(columns=['class'])  # Features
    y = df['class']                 # Target
    return X, y

def train_model(X_train, y_train):
    """Train a RandomForestClassifier model."""
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    return model

def evaluate_model(model, X_test, y_test):
    """Evaluate the model on test data."""
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {accuracy}")

def save_model(model, model_file='pickle/model.pkl'):
    """Save the trained model to a file."""
    joblib.dump(model, model_file)
    print(f"Model saved as {model_file}")

if __name__ == "__main__":
    # Load data
    csv_file = 'phishing.csv'
    df = load_data(csv_file)
    
    # Preprocess data
    X, y = preprocess_data(df)
    
    # Split data into train and test sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train model
    model = train_model(X_train, y_train)
    
    # Evaluate model
    evaluate_model(model, X_test, y_test)
    
    # Save model
    save_model(model)
