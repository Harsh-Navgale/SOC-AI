import os
import glob
import httpx

BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8080/api")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
DOCS_DIR = "/data/org_docs"


def _auth_headers() -> dict:
    # Routes through the backend's own /api/ingest so embeddings use whatever AI model is
    # actually configured, instead of this tool picking its own.
    resp = httpx.post(
        f"{BACKEND_URL}/auth/login",
        json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        timeout=30.0,
    )
    resp.raise_for_status()
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def ingest_docs():
    files = glob.glob(f"{DOCS_DIR}/**/*.txt", recursive=True) + glob.glob(f"{DOCS_DIR}/**/*.md", recursive=True)
    if not files:
        print(f"No .txt or .md files found in {DOCS_DIR}")
        return

    headers = _auth_headers()
    for path in files:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()

        resp = httpx.post(
            f"{BACKEND_URL}/ingest",
            params={"filename": path, "text": text},
            headers=headers,
            timeout=120.0,
        )
        resp.raise_for_status()
        print(f"Ingested {path} ({resp.json()['ingested_chunks']} chunks)")


def main():
    while True:
        print("\nSOC-AI Console")
        print("1) Ingest org-specific files from /data/org_docs into the Vector DB")
        print("2) Exit")
        choice = input("Choose an option: ").strip()

        if choice == "1":
            ingest_docs()
        elif choice == "2":
            break
        else:
            print("Invalid option")


if __name__ == "__main__":
    main()
