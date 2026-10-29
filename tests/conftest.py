import io
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Isolate the import-time configuration from the developer's real .env, database and storage.
_import_dir = Path(tempfile.mkdtemp(prefix="ipeh-import-"))
os.environ["DATABASE_PATH"] = str(_import_dir / "import.db")
os.environ["STORAGE_PATH"] = str(_import_dir / "storage")
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_EMAIL"] = "admin@example.test"
os.environ["ADMIN_PASSWORD"] = "Admin-Test-Pass-1"
os.environ["CONTRACT_ADDRESS"] = ""
os.environ["MST_SIGNER_PRIVATE_KEY"] = ""
os.environ["MST_NETWORK"] = "coral-testnet"

import app as app_module  # noqa: E402
from fakes import FakeChain  # noqa: E402

ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]
USER_PASSWORD = "User-Test-Pass-1"
CSRF = "test-csrf-token"


@pytest.fixture
def chain(monkeypatch):
    fake = FakeChain()
    monkeypatch.setattr(app_module, "chain", fake)
    return fake


@pytest.fixture
def app(tmp_path, chain):
    app_module.configure(tmp_path / "test.db", tmp_path / "storage")
    app_module.app.config["TESTING"] = True
    return app_module


@pytest.fixture
def client(app):
    return app.app.test_client()


def post(client, url, data=None, **kw):
    with client.session_transaction() as s:
        s["csrf"] = CSRF
    payload = {"csrf_token": CSRF, **(data or {})}
    return client.post(url, data=payload, **kw)


def register(client, username, password=USER_PASSWORD):
    return post(client, "/register", {"username": username, "email": f"{username}@example.test", "password": password})


def login(client, identity, password=USER_PASSWORD):
    return post(client, "/login", {"identity": identity, "password": password})


def logout(client):
    return post(client, "/logout")


def signup_and_login(client, username):
    register(client, username)
    login(client, username)


def upload(client, content=b"original work", filename="work.txt", title="My work", follow_redirects=False, **fields):
    data = {"title": title, "description": "", "file": (io.BytesIO(content), filename), **fields}
    return post(client, "/upload", data, content_type="multipart/form-data", follow_redirects=follow_redirects)


def evidence_id_from(response):
    return int(response.headers["Location"].rstrip("/").split("/")[-1])
