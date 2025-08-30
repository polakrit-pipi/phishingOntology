# phish_detector/utils.py
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from typing import List, Tuple

BRAND_KEYWORDS = [
    "paypal","apple","amazon","bank","chase","facebook","meta","google","microsoft",
    "outlook","office365","instagram","line","kbank","scb","krungsri","krungsri","kplus"
]

COMMON_TLDS = set([
 "com","net","org","info","biz","co","io","ai","app","edu","gov","mil","ru","de","uk","cn","fr","jp","br","in","it","es","au","nl","se","no"
])

def parse_host_and_scheme(url: str):
    p = urlparse(url)
    host = (p.hostname or "").lower()
    scheme = (p.scheme or "").lower()
    return host, scheme

def is_ip_host(host: str) -> bool:
    return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host))

def count_dots(host: str) -> int:
    return host.count(".")

def count_subdomains(host: str) -> int:
    if not host: return 0
    parts = host.split(".")
    # approximate: top-level + second-level = 2, rest are subdomains
    return max(0, len(parts) - 2)

def has_double_slash_in_path(url: str) -> bool:
    p = urlparse(url)
    return "//" in (p.path or "")

def has_tld_in_path(url: str) -> bool:
    p = urlparse(url)
    path = (p.path or "").lower()
    for tld in COMMON_TLDS:
        if ("."+tld) in path:
            return True
    return False

def has_symbols_in_domain(host: str) -> bool:
    # non a-z 0-9 . -
    return bool(re.search(r"[^a-z0-9\.-]", host))

def domain_prefix_suffix_like_brand(host: str) -> bool:
    # check first label for brand and hyphen pattern
    if not host: return False
    first = host.split(".")[0]
    for b in BRAND_KEYWORDS:
        if b in first and "-" in first:
            return True
    return False

def brand_in_path_or_subdomain(host: str, url: str) -> bool:
    p = urlparse(url)
    text = (host + " " + (p.path or "") + " " + (p.query or "")).lower()
    for b in BRAND_KEYWORDS:
        if b in text:
            return True
    return False

def external_resource_ratio(base_host: str, resource_urls: List[str]) -> float:
    total = 0
    ext = 0
    for r in resource_urls:
        if not r: continue
        try:
            h = urlparse(r).hostname or ""
        except Exception:
            h = ""
        if not h: 
            continue
        total += 1
        if h.lower() != base_host.lower():
            ext += 1
    return (ext/total) if total else 0.0

def abnormal_links(hrefs: List[str]) -> bool:
    # any void / empty / javascript links
    for h in hrefs:
        if not h:
            return True
        s = h.strip().lower()
        if s in ("", "#", "javascript:void(0)", "javascript:;", "void(0)", "javascript:void(0);"):
            return True
    return False

def forms_action_abnormal(forms: List[Tuple[str,str]], base_host: str) -> bool:
    # forms: list of (method, action)
    for method, action in forms:
        a = (action or "").strip().lower()
        if a in ("", "#", "javascript:void(0)", "javascript:;"):
            return True
        ah = urlparse(a).hostname or ""
        if ah and ah.lower() != base_host.lower():
            return True
    return False

def anchors_point_elsewhere(hrefs: List[str], base_host: str) -> bool:
    total = 0
    other = 0
    for h in hrefs:
        if not h:
            continue
        host = urlparse(h).hostname or ""
        if host:
            total += 1
            if host.lower() != base_host.lower():
                other += 1
    if total < 3:
        return False
    return (other / total) >= 0.6

def meta_keyword_mismatch(meta_content: str, base_host: str) -> bool:
    if not meta_content:
        return False
    tokens = re.findall(r"[a-z0-9]+", meta_content.lower())
    primary = base_host.split(".")[0]
    for t in tokens:
        if t in BRAND_KEYWORDS and t != primary:
            return True
    return False

def extract_html_features(html: str):
    soup = BeautifulSoup(html or "", "html.parser")
    hrefs = [a.get("href","") for a in soup.find_all("a")]
    imgs = [i.get("src","") for i in soup.find_all("img")]
    scripts = [s.get("src","") for s in soup.find_all("script")]
    links_tag = [l.get("href","") for l in soup.find_all("link")]
    forms = [( (f.get("method") or "").lower(), (f.get("action") or "") ) for f in soup.find_all("form")]
    meta_keywords = ""
    m = soup.find("meta", attrs={"name":"keywords"})
    if not m:
        m = soup.find("meta", attrs={"property":"keywords"})
    if m and m.get("content"):
        meta_keywords = m.get("content","")
    return {
        "hrefs": hrefs,
        "imgs": imgs,
        "scripts": scripts,
        "links_tag": links_tag,
        "forms": forms,
        "meta_keywords": meta_keywords
    }
