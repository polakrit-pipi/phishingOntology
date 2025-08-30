# phish_detector/detector.py
from dataclasses import dataclass, asdict
from typing import Dict, List
from .utils import *
import time

@dataclass
class Features:
    hasIP: bool
    hasHttps: bool
    hasDslash: bool
    hasTldPath: bool
    hasSurl: bool
    hasSaP: bool
    hasDIquery: bool
    hasRurl: bool
    hasSubDomain: int
    hasDots: int
    hasAurl: bool
    hasLIdAnchor: bool
    hasFAction: bool
    hasMkeyword: bool

    @staticmethod
    def from_url_and_html(url: str, html: str):
        host, scheme = parse_host_and_scheme(url)
        html_feats = extract_html_features(html)
        resource_urls = html_feats["imgs"] + html_feats["scripts"] + html_feats["links_tag"]
        res_ratio = external_resource_ratio(host, resource_urls)

        return Features(
            hasIP=is_ip_host(host),
            hasHttps=(scheme == "https"),
            hasDslash=has_double_slash_in_path(url),
            hasTldPath=has_tld_in_path(url),
            hasSurl=has_symbols_in_domain(host),
            hasSaP=domain_prefix_suffix_like_brand(host),
            hasDIquery=brand_in_path_or_subdomain(host, url),
            hasRurl=(res_ratio > 0.5),
            hasSubDomain=count_subdomains(host),
            hasDots=count_dots(host),
            hasAurl=abnormal_links(html_feats["hrefs"]),
            hasLIdAnchor=anchors_point_elsewhere(html_feats["hrefs"], host),
            hasFAction=forms_action_abnormal(html_feats["forms"], host),
            hasMkeyword=meta_keyword_mismatch(html_feats["meta_keywords"], host),
        )

EXPLANATION_MAP = {
    "IPurl": "URL ใช้ IP แทนชื่อโดเมน",
    "HttpsFalse": "ไม่มีการใช้ HTTPS ที่ถูกต้อง/ปลอดภัย",
    "Dslash": "มี '//' ซ้อนใน path เพื่อทำให้ดูเหมือนโดเมนจริง",
    "TldPath": "มีชื่อโดเมนระดับบน (TLD) โผล่ใน path",
    "Surl": "โดเมนมีอักขระแปลกปลอม (non-ASCII/สัญลักษณ์)",
    "SaP": "โดเมนมี prefix/suffix คล้ายแบรนด์จริง (เช่น paypal-secure-login)",
    "DIquery": "มีคีย์เวิร์ดแบรนด์ดังใน subdomain/path",
    "NofDots": "โดเมนมีจุด (.) จำนวนมากผิดปกติ",
    "Subdomain": "มีจำนวน subdomain มากผิดปกติ",
    "Rurl": "โหลด resource จำนวนมากจากโดเมนภายนอก",
    "Aurl": "มีลิงก์ผิดปกติ (เช่น href='#' หรือ javascript:void(0))",
    "LIdAnchor": "ลิงก์ส่วนใหญ่ชี้ไปโดเมนอื่นเพื่อสร้างความน่าเชื่อถือ",
    "FAction": "ฟอร์มส่งข้อมูลไป action ที่ว่าง/ผิดปกติ/ข้ามโดเมน",
    "MetaKeyword": "คำหลัก (meta keywords) ไม่สอดคล้องกับโดเมน",
}

@dataclass
class Verdict:
    label: str
    justification_axioms: List[str]
    explanation: str
    features: Dict

def reason(features: Features) -> Verdict:
    axioms = []

    # Ax.4 like: MetaKeyword && (Aurl or FAction or LIdAnchor or IP) && not HTTPS
    cond_ax4 = features.hasMkeyword and (features.hasAurl or features.hasFAction or features.hasLIdAnchor or features.hasIP) and (not features.hasHttps)
    if cond_ax4:
        if features.hasIP: axioms.append("IPurl")
        if features.hasAurl: axioms.append("Aurl")
        if features.hasFAction: axioms.append("FAction")
        if features.hasLIdAnchor: axioms.append("LIdAnchor")
        axioms.append("MetaKeyword")
        axioms.append("HttpsFalse")
        label = "Phishing"
    else:
        cond_ax5 = (features.hasDslash or features.hasTldPath) and features.hasFAction
        cond_ax6 = (features.hasIP or features.hasSurl or features.hasDIquery or (features.hasDots >= 6) or features.hasSaP or (features.hasSubDomain >= 4)) and (not features.hasHttps)
        if cond_ax5 or cond_ax6:
            if features.hasDslash: axioms.append("Dslash")
            if features.hasTldPath: axioms.append("TldPath")
            if features.hasFAction: axioms.append("FAction")
            if features.hasIP: axioms.append("IPurl")
            if features.hasSurl: axioms.append("Surl")
            if features.hasDIquery: axioms.append("DIquery")
            if features.hasDots >= 6: axioms.append("NofDots")
            if features.hasSaP: axioms.append("SaP")
            if features.hasSubDomain >= 4: axioms.append("Subdomain")
            axioms.append("HttpsFalse")
            label = "Phishing"
        else:
            normal_content = (not features.hasFAction) and (not features.hasAurl) and (not features.hasLIdAnchor) and (not features.hasMkeyword)
            normal_url = features.hasHttps or ((features.hasDots < 6) and (not features.hasDslash) and (not features.hasSaP) and (features.hasSubDomain < 4) and (not features.hasSurl) and (not features.hasDIquery) and (not features.hasIP) and (not features.hasRurl) and (not features.hasTldPath))
            if normal_content and normal_url:
                label = "Legitimate"
                axioms = []
            else:
                # fallback threshold
                strong = sum([
                    features.hasIP, (not features.hasHttps), features.hasFAction,
                    features.hasSaP, (features.hasSubDomain >= 4), features.hasDIquery,
                    features.hasAurl, features.hasTldPath
                ])
                if strong >= 2:
                    label = "Phishing"
                    if features.hasIP: axioms.append("IPurl")
                    if not features.hasHttps: axioms.append("HttpsFalse")
                    if features.hasFAction: axioms.append("FAction")
                    if features.hasSaP: axioms.append("SaP")
                    if features.hasSubDomain >= 4: axioms.append("Subdomain")
                    if features.hasDIquery: axioms.append("DIquery")
                    if features.hasAurl: axioms.append("Aurl")
                    if features.hasTldPath: axioms.append("TldPath")
                else:
                    label = "Legitimate"
                    axioms = []

    # dedupe keep order
    seen = set()
    axioms = [a for a in axioms if not (a in seen or seen.add(a))]

    if axioms:
        pieces = [EXPLANATION_MAP.get(a, a) for a in axioms]
        explanation = "สรุป: จัดเป็น *Phishing* เพราะ " + "; ".join(pieces)
    else:
        explanation = "สรุป: จัดเป็น *Legitimate* (ไม่พบความผิดปกติสำคัญตามกฎที่กำหนด)"

    return Verdict(
        label=label,
        justification_axioms=axioms,
        explanation=explanation,
        features=asdict(features)
    )

def analyze(url: str, html: str):
    feats = Features.from_url_and_html(url, html)
    return reason(feats)
