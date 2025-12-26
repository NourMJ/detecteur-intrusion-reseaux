import pandas as pd
from sklearn.ensemble import IsolationForest

class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1)

    def train(self, csv_file):
        df = pd.read_csv(csv_file)
        X = df[["confidence"]]
        self.model.fit(X)

    def predict(self, confidence):
        return self.model.predict([[confidence]])[0] == -1

