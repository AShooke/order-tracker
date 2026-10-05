# Order Tracker

A small order tracking app for the AI Dev Tools Zoomcamp observability homework. It includes a web page, API, tests, and a Docker Compose setup. It includes a provisioned 5xx alert; webhook notification is not configured.

The main user flow is creating an order and checking its status. Three sample orders are created on first startup.

## Run it

You need Docker with Compose. To run the tests, you also need Python 3.11+ and `uv`.

```bash
docker compose up --build -d --wait
```

Open <http://127.0.0.1:8000>. The API is at `/api/orders`, and the health check is at `/healthz`. Data is stored in a Docker volume and survives container recreation.

The app exports OpenTelemetry request metrics, logs, and traces to the Collector over OTLP. The Collector forwards metrics to Prometheus, logs to Loki, and traces to Tempo. Grafana is provisioned with those three data sources and an Order Tracker request dashboard. The request counter includes the matched route and HTTP status code.

Grafana evaluates the Order Tracker 5xx alert every minute over a rolling five-minute window. It returns to OK when there is no 5xx data and includes the affected route and dashboard link in its annotations.

The host-run incident responder accepts authenticated Grafana-compatible webhooks at `POST http://127.0.0.1:8001/alerts`. It queues firing alerts for a read-only Copilot CLI investigation; install and authenticate Copilot CLI on the host before enabling it. Generate a webhook token and start the service in PowerShell:

```powershell
$env:RESPONDER_WEBHOOK_TOKEN = [guid]::NewGuid().ToString("N")
python .\incident-response\responder.py
```

Send the token as `Authorization: Bearer <token>`. The responder exposes `/healthz` and `/jobs/{job_id}` for service and investigation status. The CLI is invoked with `-p` (non-interactive mode) and restricted to repository view/search tools; it cannot edit files or run shell commands.

If port 8000 is occupied, set `ORDER_TRACKER_PORT`, for example:

```bash
ORDER_TRACKER_PORT=18080 docker compose up --build -d --wait
```

Open Grafana at <http://127.0.0.1:3000> (default credentials: `admin` / `admin`) and select the **Order Tracker Requests** dashboard in the **Order Tracker** folder. Prometheus is available at <http://127.0.0.1:9090>.

Run tests with `uv run --frozen pytest -q`. Stop the stack with `docker compose down`. Add `-v` only if you also want to delete the stored order and telemetry data.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` | Web page |
| GET | `/healthz` | Database health check |
| GET | `/api/orders` | List orders |
| POST | `/api/orders` | Create an order |
| GET | `/api/orders/{id}` | Check an order |
| PATCH | `/api/orders/{id}` | Change an order status |

The app uses SQLite to keep setup small. Run one app container at a time. The course exercise is about detecting and handling an incident, not scaling the database.
