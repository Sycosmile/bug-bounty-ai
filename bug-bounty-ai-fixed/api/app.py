from flask import Flask, request, jsonify
from core.context import Context
from core.registry import Registry
from core.engine import Engine

from skills import recon, exposure, web_scan, report

app = Flask(__name__)

def build_registry():
    r = Registry()
    r.register(recon.skill)
    r.register(exposure.skill)
    r.register(web_scan.skill)
    r.register(report.skill)
    return r

@app.route("/run", methods=["POST"])
def run():
    data = request.json

    context = Context(data["target"])
    engine = Engine(build_registry())

    result = engine.run(context)

    return jsonify(result.report)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
