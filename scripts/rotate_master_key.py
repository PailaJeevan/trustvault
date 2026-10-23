"""Rotate TV_MASTER_KEY without downtime for reads.

    # 1. generate a new key
    python -c "import secrets,base64;print(base64.b64encode(secrets.token_bytes(32)).decode())"
    # 2. run with the CURRENT key in TV_MASTER_KEY and the new one in TV_NEW_MASTER_KEY
    TV_NEW_MASTER_KEY=<new> python -m scripts.rotate_master_key
    # 3. put the new key in TV_MASTER_KEY (.env / host settings) and reload the app

Between steps 2 and 3 the running app still holds the old key and cannot open
files, so do step 3 straight away. Keep the old key until you have confirmed
downloads work. The rotation is recorded in the audit trail with key ids.
"""
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402
from app.keys import rotate_master_key  # noqa: E402

if __name__ == "__main__":
    raw = os.environ.get("TV_NEW_MASTER_KEY")
    if not raw:
        sys.exit(__doc__)
    result = rotate_master_key(create_app(), base64.b64decode(raw))
    print(f"Re-wrapped {result['files']} file key(s) and {result['mfa_secrets']} MFA secret(s).")
    print(f"Key id {result['old_key_id']} -> {result['new_key_id']}. Now set TV_MASTER_KEY to the new key and reload.")
