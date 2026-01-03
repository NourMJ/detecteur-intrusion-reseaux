import os
import pandas as pd
from sklearn.ensemble import IsolationForest

class AnomalyDetector:
    """
    Train/predict anomalies from window-based flow statistics.
    Expected columns in stats CSV:
      - icmp_count
      - syn_count
      - unique_dst_ports
      - udp53_count
      - total_packets
    """

    FEATURES = ["icmp_count", "syn_count", "unique_dst_ports", "udp53_count", "total_packets"]

    def __init__(self, contamination=0.05, random_state=42):
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state
        )
        self.is_trained = False

    def train(self, stats_csv_file: str):
        if not os.path.exists(stats_csv_file):
            raise FileNotFoundError(f"Stats file not found: {stats_csv_file}")

        df = pd.read_csv(stats_csv_file)

        # basic safety: keep only needed columns
        missing = [c for c in self.FEATURES if c not in df.columns]
        if missing:
            raise ValueError(f"Missing columns in stats CSV: {missing}")

        X = df[self.FEATURES].fillna(0)
        if len(X) < 30:
            # You can lower this, but having some baseline helps
            raise ValueError("Not enough samples to train (need ~30+ windows).")

        self.model.fit(X)
        self.is_trained = True

    def predict(self, window_features: dict) -> bool:
        """
        window_features example:
        {
          "icmp_count": 2,
          "syn_count": 1,
          "unique_dst_ports": 2,
          "udp53_count": 0,
          "total_packets": 25
        }
        Returns True if anomaly detected.
        """
        if not self.is_trained:
            return False  # or raise error, but this is smoother in real-time IDS

        x = pd.DataFrame([[window_features.get(f, 0) for f in self.FEATURES]], columns=self.FEATURES)
        pred = self.model.predict(x)[0]   # -1 anomaly, 1 normal
        return pred == -1
