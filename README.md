# ScamRakshak

Agentic Honey-Pot API for Scam Detection & Intelligence Extraction

## Overview

ScamRakshak is an AI-powered honeypot system that:
- Detects scam messages (lottery, UPI fraud, phishing, etc.)
- Engages scammers with human-like responses
- Extracts intelligence (phone numbers, UPI IDs, bank accounts, links)
- Reports findings to the evaluation endpoint

## Tech Stack

- **Framework**: FastAPI (Python)
- **AI**: Google Gemini 1.5 Flash
- **Deployment**: Railway / Render

## Quick Start

### 1. Clone and Install

```bash
cd ScamRakshak
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env and add your API keys:
# - API_KEY: Your secret key for the x-api-key header
# - GEMINI_API_KEY: Get from https://makersuite.google.com/app/apikey
```

### 3. Run Locally

```bash
uvicorn app.main:app --reload
```

### 4. Test the API

```bash
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-api-key" \
  -d '{
    "sessionId": "test-123",
    "message": {
      "sender": "scammer",
      "text": "Congratulations! You won 10 lakh lottery. Send bank details.",
      "timestamp": 1770005528731
    },
    "conversationHistory": [],
    "metadata": {"channel": "SMS"}
  }'
```

## API Endpoints

### POST / - Main Honeypot Endpoint

Receives scam messages and returns AI-generated responses.

**Headers:**
- `x-api-key`: Your API key (required)
- `Content-Type`: application/json

**Request Body:**
```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "Message content",
    "timestamp": 1770005528731
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "Haan ji? Lottery? Maine toh koi ticket nahi liya..."
}
```

### GET /health - Health Check

Returns service status.

## Project Structure

```
ScamRakshak/
├── app/
│   ├── main.py              # FastAPI app & endpoints
│   ├── config.py            # Environment configuration
│   ├── core/
│   │   ├── gemini_client.py # Gemini AI wrapper
│   │   ├── scam_detector.py # Scam detection logic
│   │   ├── agent.py         # Honeypot persona
│   │   └── intelligence.py  # Intel extraction
│   ├── models/
│   │   └── schemas.py       # Pydantic models
│   ├── services/
│   │   ├── session_manager.py  # Session storage
│   │   └── callback_service.py # GUVI callback
│   └── utils/
│       └── patterns.py      # Regex patterns
├── requirements.txt
├── Dockerfile
├── Procfile
└── .env.example
```

## Deployment

### Railway

1. Push code to GitHub
2. Create new project on Railway
3. Connect to GitHub repo
4. Add environment variables (API_KEY, GEMINI_API_KEY)
5. Deploy!

### Render

1. Push code to GitHub
2. Create new Web Service on Render
3. Connect to GitHub repo
4. Add environment variables
5. Deploy!

## License

MIT
