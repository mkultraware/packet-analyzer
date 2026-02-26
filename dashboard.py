from flask import Flask, render_template, jsonify
import sqlite3

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect("packets.db")
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def stats():
    conn = get_db()
    c = conn.cursor()

    total = c.execute("SELECT COUNT(*) FROM packets").fetchone()[0]

    # Protocol breakdown
    protocols = c.execute(
        "SELECT protocol, COUNT(*) as count FROM packets GROUP BY protocol ORDER BY count DESC"
    ).fetchall()

    # Top destinations
    top_destinations = c.execute(
        "SELECT dst_ip, COUNT(*) as count FROM packets GROUP BY dst_ip ORDER BY count DESC LIMIT 10"
    ).fetchall()

    # DNS queries
    dns_queries = c.execute(
        "SELECT detail, COUNT(*) as count FROM packets WHERE protocol='DNS' GROUP BY detail ORDER BY count DESC LIMIT 15"
    ).fetchall()

    # Recent packets
    recent = c.execute(
        "SELECT timestamp, protocol, src_ip, dst_ip, detail FROM packets ORDER BY id DESC LIMIT 20"
    ).fetchall()

    # Timeline
    timeline = c.execute("""
        SELECT strftime('%H:%M', timestamp) as minute, COUNT(*) as count
        FROM packets
        WHERE timestamp >= datetime('now', '-1 hour')
        GROUP BY minute ORDER BY minute
    """).fetchall()

    conn.close()

    return jsonify({
        "total": total,
        "protocols": [dict(r) for r in protocols],
        "top_destinations": [dict(r) for r in top_destinations],
        "dns_queries": [dict(r) for r in dns_queries],
        "recent": [dict(r) for r in recent],
        "timeline": [dict(r) for r in timeline]
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)