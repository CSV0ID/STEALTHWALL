"""Unit tests for top-level 1-line StealthWall SDK."""

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient
from stealthwall import StealthWall


def test_top_level_stealthwall_1_line_integration():
    app = FastAPI()

    # 1-line integration
    StealthWall(app, dry_run=True)

    @app.get("/hello")
    def hello():
        return {"msg": "ok"}

    client = TestClient(app)
    res = client.get("/hello")
    assert res.status_code == 200
    assert res.json() == {"msg": "ok"}
