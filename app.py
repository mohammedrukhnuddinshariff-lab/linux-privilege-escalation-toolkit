
from flask import Flask, render_template

app = Flask(__name__)


@app.route("/")
def home():
    modules = [
        "System Information",
        "SUID / SGID Audit",
        "File Permissions Audit",
        "Linux Capabilities Audit",
        "Sudo Configuration Audit",
        "Systemd Service Audit",
        "Cron Permissions Audit",
        "Kernel Information",
    ]

    return render_template("index.html", modules=modules)


@app.route("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(debug=False)
