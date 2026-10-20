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
print("\n2. types\n  ", list(dzq.types.BUILTIN.values()))

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

# 8. Your own type: describe the fields, sign, and carry the type in the file.
from dzq.typedoc import TypeDoc, make_type  # noqa: E402

_, text = make_type("acme:board-post", "1.0.0",
                    public=[{"name": "area", "required": True, "max": 64}],
                    private=[{"name": "text", "required": True, "max": 2000}])
post_type = TypeDoc(text)
post = alice.sign(type=post_type, to="any(%s)" % bob.aid, content={"area": "Podil", "text": "A kid's bike, free"})
print("\n8. own type\n", dzq.open(post.to_dzq()).verify())
print("   a reader without the type:", dzq.open(post.bundle).verify().result["type_known"])
