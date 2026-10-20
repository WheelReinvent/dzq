"""Reference implementation of dzq/1.2 (https://github.com/WheelReinvent/dzq)."""

__version__ = "1.2.0"
SPEC_VERSION = "dzq/1.2"

from .archive import check_dzq, open_dzq, read_dzq  # noqa: E402,F401
from .identity import Identity  # noqa: E402,F401
from .statement import Statement, Verification, open_statement as open  # noqa: E402,F401
from . import types  # noqa: E402,F401
from .verify import check_credential, verify_presentation  # noqa: E402,F401
