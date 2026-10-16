from flask import Flask, render_template
from database import get_alerts

app = Flask(__name__)

@app.route("/")
def dashboard():
    alerts = get_alerts()
    return render_template("index.html", alerts=alerts)

if __name__ == "__main__":
    app.run(debug=True)