import os

from flask import Flask

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]


@app.get("/healthz")
def healthz():
    return {"ok": True}


def run_legacy():
    # codit-expect: CWE-489 Werkzeug debugger (remote code execution console) bound to all interfaces
    app.run(host="0.0.0.0", port=8000, debug=True)



def run():
    # codit-safe: CWE-489 debug explicitly off
    app.run(host="0.0.0.0", port=8000, debug=False)


if __name__ == "__main__":
    run()
