
SNYK_CLIENT_ID := (shell cat .env | grep SNYK_CLIENT_ID)

snyk:
	set -a; source .env; set +a; uv run snyk.py

test:
	set -a; source .env; set +a; uv run pytest
