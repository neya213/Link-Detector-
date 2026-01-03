# PhishGuard Detector
A real-time phishing URL detection system using parallel DFA pattern matching

## 🏗️ Architecture
```
┌─────────────────┐
│   Frontend      │
│   (Next.js)     │ ← User enters URL to scan
└────────┬────────┘
         │ HTTP POST
         ↓
┌─────────────────┐
│   Backend       │
│   (FastAPI)     │ ← DFA pattern matching
└────────┬────────┘
         │
         ↓
    JSON Results
    (Risk + Indicators)
```

---

## PhishGuard Detector - Setup & Run Instructions

This project is divided into two separate applications:

- **Backend**: A FastAPI server that performs DFA-based phishing detection.
- **Frontend**: A Next.js interface for scanning URLs and viewing results.

**You must run both terminals simultaneously** for the application to work.

---

## 1. Prerequisites

Before starting, ensure you have the following installed:

- **Node.js** - Check with `node -v`. Download from [nodejs.org](https://nodejs.org)
- **Python 3.x** - Check with `python --version`. Download from [python.org](https://python.org)

---

## 2. How to Run the Project

### Step A: Start the Backend
This starts the FastAPI server on port 8000.

1. Open your **first terminal window**.
2. Navigate to the backend folder:
```bash
cd Backend
```

3. Install dependencies (only required the first time):
```bash
pip install -r requirements.txt
```

4. Start the server:
```bash
python main.py
```

✅ **Success**: You should see: `Uvicorn running on http://127.0.0.1:8000`

---

### Step B: Start the Frontend (The Interface)
This starts the website, usually on port 3000.

1. Open a **new, second terminal window** (keep the backend running!).
2. Navigate to the **project root** (where `package.json` is):
```bash
cd C:\Link-Detector-
```

3. Install dependencies (only required the first time):
```bash
npm install
```

4. Start the website:
```bash
npm run dev
```

✅ **Success**: Click the link shown (e.g., `http://localhost:3000`) to open the app in your browser.

---

## 3. Troubleshooting

| Error Message | Solution |
|--------------|----------|
| `Couldn't find any pages or app directory` | You are likely in the wrong folder. Make sure you run `npm run dev` from the **project root** where `package.json` is located, NOT from a Frontend subfolder. |
| `Address already in use` | The server is already running in another window. Close other terminals or press `Ctrl + C` to stop the old process. |
| Frontend says "Backend connection failed" | Ensure the Backend terminal is running and hasn't crashed. The frontend needs the backend at `http://localhost:8000` to scan URLs. |
| `not enough values to unpack (expected 4, got 3)` | The `detector.py` file is outdated. Make sure it returns 4 values including `dfa_visualizations`. |

---

## 📁 Project Structure
```
/app         - Next.js pages (layout, homepage)
/components  - React components (url-scanner, UI components)
/Backend     - Phishing detection API (FastAPI + DFA modules)
  ├── detector.py         - Main detection logic
  ├── dfa_keyword.py      - Keyword pattern matching
  ├── dfa_symbols.py      - Symbol abuse detection
  ├── dfa_ip.py           - IP-based URL detection
  ├── dfa_tld.py          - Suspicious TLD detection
  ├── dfa_encoded.py      - Encoded character detection
  └── main.py             - FastAPI server
```

---

## 👥 Team
**Frontend:** James Agbon, John Timothy Dela Cruz, Simon Rito
**Backend:** James Agbon, Clarence Ignacio
