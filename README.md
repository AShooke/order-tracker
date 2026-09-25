# Order Tracker

A small order tracking app for the AI Dev Tools Zoomcamp observability homework. It includes a web page, API, tests, and a local deployment workflow. You add telemetry, alerts, and an incident responder in Homework 4.

The main user flow is creating an order and checking its status. Three sample orders are created on first startup.

## Run it

You need Docker with Compose. To run locally without Docker, you also need Python 3.11+ and `uv`.

```bash
docker compose up --build -d --wait
```

Open <http://127.0.0.1:8000>. The API is at `/api/orders`, health check at `/healthz`, and deployed version at `/version`. Data is stored in a Docker volume and survives container recreation.

If port 8000 is occupied, set `ORDER_TRACKER_PORT`, for example:

```bash
ORDER_TRACKER_PORT=18080 docker compose up --build -d --wait
```

Run tests with `uv run --frozen pytest -q`. Stop the app with `docker compose down`. Add `-v` only if you also want to delete the order data.

## CI and local deployment

[The workflow](.github/workflows/ci.yml) runs the tests and builds an image on pushes and pull requests. A GitHub-hosted runner cannot access your laptop's Docker daemon, so deployment runs locally through `act`. Install `act`, then run this in your clone:

```bash
act -j ci -P ubuntu-latest=catthehacker/ubuntu:act-latest
```

The same workflow tests, builds an image tagged with the commit SHA, deploys it with Docker Compose, waits for the health check, and checks the running release. You can check it yourself with `curl http://127.0.0.1:8000/version`.

Run `act` after committing a change. The workflow uses the current commit SHA as its release ID. If port 8000 is in use, add `--env ORDER_TRACKER_PORT=18080` to the `act` command.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` | Web page |
| GET | `/healthz` | Database health check |
| GET | `/version` | Deployed commit |
| GET | `/api/orders` | List orders |
| POST | `/api/orders` | Create an order |
| GET | `/api/orders/{id}` | Check an order |
| PATCH | `/api/orders/{id}` | Change an order status |

The app uses SQLite to keep setup small. Run one app container at a time. The course exercise is about detecting and handling an incident, not scaling the database.
