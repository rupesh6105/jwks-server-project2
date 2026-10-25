# Acknowledgment of AI Use

**Student:** Rupesh Pokharel
**Assignment:** Project 2 — Extending the Basic JWKS Server (SQLite)
**Tool used:** Claude (Anthropic), accessed through the Claude app
**Date of use:** October 25, 2026

## What I used AI for

I used Claude to build this project. It is not a case of AI assisting with
parts of my own code: Claude produced essentially all of the submitted work.
Specifically, Claude wrote:

- `jwks_server/db.py` — the SQLite layer: the table schema, the PEM
  serialization of private keys into the `key` BLOB column, and every
  parameterized query;
- `jwks_server/keys.py` — RSA generation, PKCS#1 PEM serialization, and the
  JWK encoding;
- `jwks_server/server.py` — the Flask endpoints, reworked to read their key
  material from the database;
- `main.py` — start-up, database seeding, and the restart behaviour;
- the test suite in `tests/` (115 tests, 100% coverage), including the SQL
  injection tests;
- `blackbox.py`, the external test client, including its database inspection;
- this repository's `README.md`.

## The prompts I used

My prompts were short. In order, they were substantially:

1. I attached the Project 2 assignment description along with my Project 1
   files (`main.py`, `blackbox.py`, `setup.cfg`, `README.md`) and said I
   needed to extend the JWKS server. Claude chose how to structure the
   database layer, how to serialize the keys, and how to organize the tests.
2. Follow-up messages during the build were about running and verifying the
   result rather than designing it.

I did not write prompts specifying the schema handling, the query structure,
the module layout, or the tests. Those decisions were Claude's.

## What I did myself

- Installed the dependencies and ran the server on my own machine.
- Ran the test suite and the blackbox client.
- Verified the database file, its schema, and that keys persist across a
  restart.
- Captured the screenshots in `docs/` from my own terminal.
- Created the GitHub repository and pushed the code.

## Screenshots

Per the syllabus, AI was not used to generate any screenshot in this
repository. The images in `docs/` are real screen captures taken on my own
machine and show my username and the live output.

## Note on Project 1

My Project 1 submission was missing this acknowledgment, which I added after
my grader pointed it out. I am including it here from the start.
