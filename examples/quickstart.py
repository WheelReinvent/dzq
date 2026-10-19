"""Create a statement, sign it, open it, verify it — printing each step.

    pip install cryptography
    python3 examples/quickstart.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "reference", "python"))

import dzq  # noqa: E402

# 1. Identities. Each person has one; normally it lives in their own app.
alice = dzq.Identity.create()
bob = dzq.Identity.create()
print("1. identities\n  ", alice, "\n  ", bob)

# 2. What types exist, and which fields they take.
print("\n2. types\n  ", dzq.types.TYPES)

# 3. Alice signs a statement: a type, a recipient, the type's content.
statement = alice.sign(
    type="gratitude",
    to=bob.aid,
    content={"title": "Thank you", "message": "For fixing my bike.", "category": "help"},
)
print("\n3. signed\n", statement)

# 4. The .dzq file as bytes. Send them any way: e-mail, chat, QR, AirDrop.
data = statement.to_dzq()
print("\n4. file: %d bytes" % len(data))

# 5. Bob opens it: this shows what it says, and trusts nothing yet.
received = dzq.open(data)
print("\n5. opened\n", received)
print("   content:", received.content)

# 6. Bob verifies it: who signed, to whom, unchanged.
check = received.verify()
print("\n6. verified\n", check)
print("   signed by Alice:", check.signed_by == alice.aid, "| to Bob:", check.to == bob.aid)

# 7. A tampered copy: same file, one word changed inside.
tampered = dzq.open(received.bundle.replace("bike", "car!"))
print("\n7. tampered copy\n", tampered.verify())
