from flask import Flask, render_template
import pandas as pd

app = Flask(__name__)

CSV_FILE = "../data/alerts.csv"

@app.route("/")
def dashboard():
    try:
        df = pd.read_csv(CSV_FILE)

        alerts = df.to_dict(orient="records")

        attack_types = df["type"].value_counts().to_dict()
        severity_counts = df["severity"].value_counts().to_dict()

        stats = {
            "total": len(df),
            "high": severity_counts.get("HIGH", 0),
            "medium": severity_counts.get("MEDIUM", 0)
        }

    except FileNotFoundError:
        alerts = []
        attack_types = {}
        severity_counts = {}
        stats = {"total": 0, "high": 0, "medium": 0}

    return render_template(
        "dashboard.html",
        alerts=alerts,
        stats=stats,
        attack_types=attack_types,
        severity_counts=severity_counts
    )


if __name__ == "__main__":
    app.run(debug=True)

