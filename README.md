# 🎬 ** The Cyber‑Sentinel Saga**

> *"In the neon‑lit corridors of the internet, a silent guardian watches—parsing, enriching, and defending against the invisible threats that crawl through your logs. This is the story of **adi‑debug**, the AI‑powered threat‑detection platform forged by the relentless developer **adhi‑debug**.*"

---

## 🌌 Overview

**The Cyber‑Sentinel Saga** is a **real‑time AI‑driven threat‑detection engine** that ingests **Nginx access logs**, enriches each request with **GeoIP** intelligence, and runs a **hybrid arsenal of rule‑based and machine‑learning models** (Auto‑Encoder, Random‑Forest, Isolation‑Forest). The results flow into **PostgreSQL**, broadcast via **WebSocket**, and visualized on a sleek **React + Vite** dashboard.

```
Nginx Logs → Log Tailer → Parser → GeoIP Enrichment →
Rules + ML Models → Threat Score → PostgreSQL → WebSocket → Dashboard
```

> **Developer:** **adhi‑debug** – a code‑craftsman who believes security should be as beautiful as it is effective.

---

## 🛠️ Prerequisites (Windows)

| Tool | Minimum version | Install command |
|------|----------------|-----------------|
| **Python** | 3.12+ | <code>winget install Python.Python.3.12</code> |
| **Node.js** | 20.x | <code>winget install OpenJS.Nodejs</code> |
| **npm** (bundled) | — | — |
| **Docker Desktop** (optional) | 4.x | <code>winget install Docker.DockerDesktop</code> |
| **PostgreSQL** | 15.x | <code>winget install PostgreSQL</code> |
| **Redis** | 7.x | <code>winget install Redis.Redis</code> |
| **MaxMind GeoLite2** | – | Download from <https://dev.maxmind.com/geoip/geolite2-free-download> |

---

## 🚀 Quick‑Start (no Docker)

```powershell
# 1️⃣ Clone & navigate
git clone https://github.com/adhi-debug/The-Cyber-Sentinel-Saga-.git
cd adi‑debug\backend

# 2️⃣ Create & activate a virtual‑env
python -m venv .venv
.\.venv\Scripts\Activate.ps1   # PowerShell
# .\.venv\Scripts\activate.bat # CMD

# 3️⃣ Install Python dependencies
pip install -U pip
pip install -e .   # editable install pulls requirements

# 4️⃣ Prepare GeoIP DB (place in data folder)
mkdir ..\data\geoip
# Copy GeoLite2‑City.mmdb into that folder

# 5️⃣ Create a sample Nginx log (or point to a real one)
mkdir ..\data\nginx
New-Item -Path ..\data\nginx\access.log -ItemType File

# 6️⃣ Configure environment variables (see .env example below)
Copy-Item .env.example .env
# Edit .env with a text editor – adjust paths if needed
notepad .env

# 7️⃣ Fire up the FastAPI backend
python -m uvicorn app.main:app --reload
#   → http://127.0.0.1:8000/health should return {"status":"ok"}

# 8️⃣ In a *new* terminal, launch the UI
cd ..\frontend
npm install            # first run only
npm run dev            # → http://localhost:5173
```

### 📄 Sample `.env` (excerpt)
```
ENV=development
DEBUG=true
HOST=0.0.0.0
PORT=8000
LOG_LEVEL=INFO
PROJECT_ROOT=g:/PROJECT/temp/adi-debug
API_KEY=adi-debug-key

DATABASE_URL=
REDIS_URL=redis:

GEOIP_ACCOUNT_ID=
GEOIP_LICENSE_KEY=
GEOIP_DB_PATH=
NGINX_LOG_PATH=g:

MODEL_DIR=g:/PROJECT/temp/adi-debug/data/models
SKIP_AUTO_TRAIN=false
```

---

## 🧩 Inside the Engine

| Component | Purpose |
|-----------|---------|
| **LogTailer** | Asynchronously follows the Nginx access log, feeding raw lines into a bounded queue. |
| **Parser** | Extracts IP, HTTP method, URL, status code, and timestamps. |
| **GeoIPService** | Resolves IP → Country/City/ASN using MaxMind DB. |
| **RuleEngine** | Fast, deterministic signatures (e.g., suspicious URI patterns). |
| **InferenceEngine** *(optional)* | Loads ONNX models – Auto‑Encoder, Random‑Forest, Isolation‑Forest – and scores anomalies. |
| **Pipeline** | Orchestrates queues, applies enrichment, runs detection, and pushes alerts to the dispatcher. |
| **AlertDispatcher** | Persists threats, writes to PostgreSQL, and pushes via WebSocket to the dashboard. |

---

## 📚 Model Retraining (1‑second wizardry)

1. Drop new training data (CSV, Parquet, or JSON) into `data/models/training/`.
2. Run the built‑in trainer:
   ```powershell
   cd backend
   python -m app.scripts.retrain_models
   ```
3. The script **re‑exports ONNX** artifacts into `data/models/` and flips `skip_auto_train` to `false`. The next inference cycle picks up the fresh models instantly – no server restart needed.

---

## 🐞 Common Pitfalls & Fix‑It Cheat‑Sheet

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| **`ValidationError: project_root`** | `.env` contains `PROJECT_ROOT` but Settings has no field. | Delete or comment the line, or add `project_root` to `config.py`. |
| **Backend starts but UI stays blank** | Frontend proxy URL mismatched. | Ensure `vite.config.ts` points to `http://localhost:8000`. |
| **No alerts appear** | Log tailer cannot locate the log file. | Verify `NGINX_LOG_PATH` points to an existing `access.log`. |
| **GeoIP fields empty** | Missing `GeoLite2-City.mmdb`. | Download the DB, place it at the path defined in `.env`. |
| **Model not loaded** | `data/models/` empty or ONNX runtime missing. | Install `onnxruntime` (`pip install onnxruntime`) and place model files. |

---

## 🏁 Endgame

With **adi‑debug** humming, you have a living sentinel that watches every request, paints it with geographic context, and instantly scores its threat level. Extend it, swap models, add custom rules—your security story is only limited by imagination.

> **“When the logs whisper, the sentinel listens.”** – *adi‑debug* (by **adhi‑debug**)

---

## 📜 License & Credits

- **License:** MIT – see `LICENSE` for details.
- **Author:** **adhi‑debug** – <alphaadhi131@gmail.com>
- **Contributors:** Open‑source community, core team members listed in `CONTRIBUTORS.md`.

---

*May your servers stay silent, and your alerts be loud.*
