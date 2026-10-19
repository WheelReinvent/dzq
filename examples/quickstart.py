"""Create a gratitude, sign it, "send" it, open it, check it.

    pip install cryptography
    python3 examples/quickstart.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "reference", "python"))

from dzq import Identity, check_dzq, read_dzq
from dzq.archive import open_dzq, zip_entries

# 1. Two people, each with an identifier (normally each in their own app).
alice = Identity.create()
bob = Identity.create()

# 2. Alice writes a thank-you to Bob and signs it.
file_bytes = alice.thank(to=bob.aid, title="Thank you", message="For fixing my bike.")

# 3. "Send" it: e-mail, chat, QR, AirDrop — it is just a file.
with open("thank-you.dzq", "wb") as f:
    f.write(file_bytes)

# 4. Bob opens it and reads what it says.
received = open("thank-you.dzq", "rb").read()
note = read_dzq(received)
print(note["title"], "—", note["message"])

# 5. Bob checks it: signed by Alice, to him, not changed since.
result = check_dzq(received)
print("valid:", result.valid)
print("from Alice:", result.issuer == alice.aid)
print("to Bob:", result.recipient == bob.aid)

# Someone edits the text inside the file: the check fails.
bundle, _ = open_dzq(received)
forged = zip_entries([("credential.acdc", bundle.replace("bike", "car!").encode())])
print("edited copy valid:", check_dzq(forged).valid, "-", check_dzq(forged).code)
