# example_run.py
import requests
from phishing_detector.detector import analyze

def fetch_html(url: str, timeout=8):
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent":"Mozilla/5.0 (PhishCheckerBot)"})
        return r.status_code, r.text
    except Exception as e:
        return None, ""

def demo_local_examples():
    # Demo 1: phishing-style (local example)
    url1 = "http://facebook-Alertt-Com-Securitys.Com/"
    html1 = """
    <html>
      <head><meta name="keywords" content="facebook, security, login"></head>
      <body>
        <a href="#">Click</a>
        <a href="https://www.facebook.com/">Official</a>
        <form method="post" action=""><input name="u"></form>
        <img src="https://cdn.example.com/logo.png"/>
      </body>
    </html>
    """
    v1 = analyze(url1, html1)
    print("=== Demo 1 ===")
    print("URL:", url1)
    print("Verdict:", v1.label)
    print("Justification:", v1.justification_axioms)
    print("Explanation:", v1.explanation)
    print()

    # Demo 2: likely legitimate
    url2 = "https://www.example.com/account/profile"
    html2 = """
    <html><head><meta name="keywords" content="example,profile"/></head>
    <body><a href="/home">Home</a><form method="post" action="/submit"><input name="n"></form></body></html>
    """
    v2 = analyze(url2, html2)
    print("=== Demo 2 ===")
    print("URL:", url2)
    print("Verdict:", v2.label)
    print("Justification:", v2.justification_axioms)
    print("Explanation:", v2.explanation)
    print()

def demo_fetch_url(url: str):
    code, html = fetch_html(url)
    if code is None:
        print("ไม่สามารถโหลดหน้าเว็บได้:", url)
        return
    v = analyze(url, html)
    print("URL:", url)
    print("Verdict:", v.label)
    print("Justification:", v.justification_axioms)
    print("Explanation:", v.explanation)
    print()

if __name__ == "__main__":
    demo_local_examples()
    # Uncomment to test live URLs (use responsibly)
    # demo_fetch_url("http://auth-paypal0-0.myjino.ru/Access-763342/Access/")
