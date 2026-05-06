from flask import Flask, jsonify, render_template, request

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


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/api/analyze-url", methods=["POST", "OPTIONS"])
def analyze_url_api():
    if request.method == "OPTIONS":
        return build_cors_response({})

    payload = request.get_json(silent=True) or {}
    url = payload.get("url", "").strip()
    result = analyze_text(url)
    score = result["score"]

    response = {
        "url": url,
        "score": score,
        "status": site_status(score),
        "reasons": result["reasons"],
    }

    return build_cors_response(response)


def site_status(score):
    if score >= 70:
        return "Dangerous"
    if score >= 35:
        return "Suspicious"
    return "Safe"


def build_cors_response(payload):
    response = jsonify(payload)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    return response


if __name__ == "__main__":
    app.run(debug=True)
