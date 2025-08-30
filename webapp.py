from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import requests
from phishing_detector.detector import analyze

app = FastAPI()
templates = Jinja2Templates(directory="templates")

def fetch_html(url: str, timeout=8):
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent":"Mozilla/5.0 (PhishCheckerBot)"})
        return r.status_code, r.text
    except Exception as e:
        return None, ""

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "result": None})

@app.post("/check", response_class=HTMLResponse)
async def check_url(request: Request, url: str = Form(...)):
    code, html = fetch_html(url)
    if code is None:
        result = {"label": "Error", "explanation": f"ไม่สามารถโหลดเว็บ {url} ได้"}
    else:
        verdict = analyze(url, html)
        result = {
            "label": verdict.label,
            "explanation": verdict.explanation,
            "justifications": verdict.justification_axioms
        }
    return templates.TemplateResponse("index.html", {"request": request, "result": result, "url": url})
