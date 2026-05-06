from flask import Flask, render_template, request

from phishing_detector import analyze_text


app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    sample = ""

    if request.method == "POST":
        sample = request.form.get("message", "").strip()
        result = analyze_text(sample)

    return render_template("index.html", result=result, sample=sample)


if __name__ == "__main__":
    app.run(debug=True)
