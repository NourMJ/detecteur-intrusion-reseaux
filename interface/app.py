from flask import Flask, render_template
import pandas as pd
import os
import csv

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.path.join(BASE_DIR, "..", "data", "alerts.csv")

REQUIRED_COLS = ["time", "type", "source_ip", "dest_ip", "severity", "confidence", "reason"]

def detect_delimiter(path):
    """Detect delimiter between ',', ';', '\t'."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        sample = f.read(2048)
    # If Excel/locale saved it, it's often ';'
    if sample.count(";") > sample.count(",") and sample.count(";") > sample.count("\t"):
        return ";"
    if sample.count("\t") > sample.count(",") and sample.count("\t") > sample.count(";"):
        return "\t"
    return ","

def read_alerts_safe(path):
    if (not os.path.exists(path)) or os.path.getsize(path) == 0:
        return pd.DataFrame(columns=REQUIRED_COLS)

    sep = detect_delimiter(path)

    # Read with detected separator
    try:
        df = pd.read_csv(path, sep=sep, engine="python")
    except Exception:
        # fallback: tolerate bad lines on older pandas
        df = pd.read_csv(path, sep=sep, engine="python", error_bad_lines=False)

    # Clean column names (remove spaces/BOM)
    df.columns = [str(c).strip().replace("\ufeff", "") for c in df.columns]

    # If still wrong (single column), try the other common separators
    if len(df.columns) == 1:
        for try_sep in [";", ",", "\t"]:
            if try_sep == sep:
                continue
            try:
                df2 = pd.read_csv(path, sep=try_sep, engine="python")
                df2.columns = [str(c).strip().replace("\ufeff", "") for c in df2.columns]
                if len(df2.columns) > 1:
                    df = df2
                    break
            except Exception:
                pass

    # Ensure required columns exist
    for c in REQUIRED_COLS:
        if c not in df.columns:
            df[c] = ""

    df = df.fillna("")
    df["confidence"] = pd.to_numeric(df["confidence"], errors="coerce").fillna(0).astype(int)
    df["severity"] = df["severity"].astype(str).str.upper()

    # newest first
    try:
        df = df.sort_values("time", ascending=False)
    except Exception:
        pass

    return df

@app.route("/")
def dashboard():
    df = read_alerts_safe(CSV_FILE)

    alerts = df.to_dict(orient="records")
    attack_types = df["type"].value_counts().to_dict() if len(df) else {}
    severity_counts = df["severity"].value_counts().to_dict() if len(df) else {}

    stats = {
        "total": int(len(df)),
        "high": int(severity_counts.get("HIGH", 0)),
        "medium": int(severity_counts.get("MEDIUM", 0)),
        "low": int(severity_counts.get("LOW", 0)),
    }

    return render_template(
        "dashboard.html",
        alerts=alerts,
        stats=stats,
        attack_types=attack_types,
        severity_counts=severity_counts
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
