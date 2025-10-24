from flask import Flask, render_template_string, request, redirect, url_for, flash
from keystore import (
    read_store,
    is_store_encrypted,
    save_keystore_encrypted,
    create_entry,
    save_keystore,
)
import os

app = Flask(__name__)
app.secret_key = os.environ.get("KEYSAFE_SECRET", "dev-secret")

T_INDEX = """
<h1>Keysafe</h1>
<a href="/create">Create</a>
{% with messages = get_flashed_messages() %}
    {% if messages %}
        <ul class="flashes">
        {% for m in messages %}
            <li>{{ m }}</li>
        {% endfor %}
        </ul>
    {% endif %}
{% endwith %}
<h2>Entries</h2>
<ul>
{% for e in entries %}
  <li>{{ e.id }} - {{ e.label }} - {{ e.created_at }}</li>
{% endfor %}
</ul>
"""


@app.route("/")
def index():
    ks_path = "keystore.json"
    master = None
    if is_store_encrypted(ks_path):
        master = request.args.get("master")
    try:
        store = read_store(ks_path, master)
    except Exception:
        flash("Keystore is encrypted — provide master via ?master=...")
        store = {"entries": []}
    entries = store.get("entries", [])
    return render_template_string(T_INDEX, entries=entries)


T_CREATE = """
<h1>Create entry</h1>
{% with messages = get_flashed_messages() %}
    {% if messages %}
        <ul class="flashes">
        {% for m in messages %}
            <li>{{ m }}</li>
        {% endfor %}
        </ul>
    {% endif %}
{% endwith %}
<form method="post">
label: <input name="label"><br>
bits: <input name="bits" value="2048"><br>
master: <input name="master"><br>
<button type="submit">Create</button>
</form>
"""


@app.route("/create", methods=["GET", "POST"])
def create():
    if request.method == "POST":
        label = request.form["label"]
        bits = int(request.form.get("bits", 2048))
        master = request.form.get("master")
        if not master:
            flash("Master password required to encrypt keystore")
            return redirect(url_for("create"))
        e = create_entry(label, master, bits=bits)
        # append and save encrypted
        try:
            store = read_store("keystore.json", master) if os.path.exists("keystore.json") else {"entries": []}
        except Exception as exc:
            # most likely wrong master or corrupted keystore — surface a user-friendly message
            flash("Failed to read existing keystore: {}".format(str(exc)))
            return redirect(url_for("create"))
        store.setdefault("entries", []).append(e)
        save_keystore_encrypted("keystore.json", store.get("entries", []), master)
        flash("Created entry " + e["id"])
        return redirect(url_for("index"))
    return render_template_string(T_CREATE)


if __name__ == "__main__":
    app.run(debug=True)
