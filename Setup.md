# SISA Local Deployment & Setup Guide

This document outlines how to run the SISA platform on your local machine.

## Prerequisites
- Node.js (v18+)
- Python (3.10+)
- `npm` or `yarn`

## 1. Backend Setup

The FastAPI backend must be running for the Honeypot, Digital Twin, and Scanning operations to function.

```bash
cd backend

# Create a virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate  # On macOS/Linux
# .\venv\Scripts\activate # On Windows

# Install the required dependencies
pip install -r requirements.txt

# Start the uvicorn development server
uvicorn app.main:app --reload --port 8000
```
The backend API will start securely at `http://localhost:8000`.

## 2. Frontend Setup

The React frontend runs via Vite and uses a proxy to securely communicate with the backend.

```bash
# In a new terminal window, navigate to the root directory
# Install dependencies
npm install

# Start the local development server
npm run dev
```
The Cyberpunk UI will be available at `http://localhost:3000`.

## 3. Production Deployment (Vercel)

The repository is pre-configured for **Vercel** with zero-config required:
- `vercel.json` intercepts all `/api/*` and `/analyze` requests and routes them to `api/index.py`.
- `api/index.py` correctly bootstraps the FastAPI backend as a Vercel Serverless Function.
- The React build command compiles to `dist/`, which Vercel serves as static assets.

Simply link your GitHub repository to Vercel, and click **Deploy**. It works out of the box.
