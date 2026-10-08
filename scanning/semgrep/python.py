# Test cases for python.yml (`semgrep --test scanning/semgrep`). Not imported or executed.
# ruff: noqa
import logging
import os
import pickle
import subprocess

import httpx
import jwt
import requests
import sqlalchemy
import yaml

logger = logging.getLogger(__name__)


def sql(db, name, table):
    # ruleid: sentineledge-sql-built-from-strings
    sqlalchemy.text(f"SELECT * FROM users WHERE name = '{name}'")
    # ruleid: sentineledge-sql-built-from-strings
    sqlalchemy.text("SELECT * FROM " + table)
    # ruleid: sentineledge-sql-built-from-strings
    db.execute("DELETE FROM sessions WHERE id = '%s'" % name)
    # ok: sentineledge-sql-built-from-strings
    sqlalchemy.text("SELECT * FROM users WHERE name = :name")
    # ok: sentineledge-sql-built-from-strings
    db.execute(sqlalchemy.text("SELECT 1 WHERE :x"), {"x": name})


def outbound(url):
    # ruleid: sentineledge-outbound-http-without-egress-guard
    httpx.get(url)
    # ruleid: sentineledge-outbound-http-without-egress-guard
    requests.post(url, json={})
    # ruleid: sentineledge-outbound-http-without-egress-guard
    client = httpx.Client(timeout=5)
    return client


def deserialize(blob, text):
    # ruleid: sentineledge-unsafe-deserialization
    pickle.loads(blob)
    # ruleid: sentineledge-unsafe-deserialization
    yaml.load(text)
    # ok: sentineledge-unsafe-deserialization
    yaml.load(text, Loader=yaml.SafeLoader)
    # ok: sentineledge-unsafe-deserialization
    yaml.safe_load(text)


def tokens(token, key):
    # ruleid: sentineledge-jwt-without-verification
    jwt.decode(token, key, options={"verify_signature": False}, algorithms=["HS256"])
    # ruleid: sentineledge-jwt-without-verification
    jwt.decode(token, key)
    # ok: sentineledge-jwt-without-verification
    jwt.decode(token, key, algorithms=["HS256"], audience="sentineledge")


def commands(path):
    # ruleid: sentineledge-shell-command
    subprocess.run(f"ls {path}", shell=True)
    # ruleid: sentineledge-shell-command
    os.system("ls " + path)
    # ok: sentineledge-shell-command
    subprocess.run(["ls", path], check=True)


def logging_cases(user, password, refresh_token):
    # ruleid: sentineledge-secret-in-log
    logger.info("sign-in for %s with %s", user, password)
    # ruleid: sentineledge-secret-in-log
    logger.warning("refresh failed: %s", refresh_token)
    # ok: sentineledge-secret-in-log
    logger.info("refresh token reuse detected for %s", user)
