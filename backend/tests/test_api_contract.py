import os
from pathlib import Path

os.environ.setdefault("TEA121_DATABASE_URL", "sqlite:////tmp/tea121-backend-contract.db")

import yaml
from app.main import app


def test_openapi_matches_checked_in_contract():
    expected = yaml.safe_load(
        (Path(__file__).resolve().parents[2] / "contracts" / "openapi.yaml").read_text(
            encoding="utf-8"
        )
    )
    assert app.openapi() == expected
