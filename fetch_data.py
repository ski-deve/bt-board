#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
비테크놀로지 보안 전광판 - 수집기 + 화면 생성기 (GitHub Actions 용)

실행하면 site/ 폴더에 두 파일을 만듭니다.
  site/data.json   : 뉴스 / CISA KEV / NVD / Cisco 권고 / 부산 보안 행사 / 부산 날씨
  site/index.html  : 1080x1920 세로 전광판 화면 (data.json 을 60초마다 다시 읽음)

부산 행사는 저장소 최상위의 events.json 에 직접 등록합니다 (없어도 동작).
  [{"date":"2026-11-20","end":"2026-11-21","time":"10:00","title":"행사명","place":"벡스코","link":"https://..."}]
  - end, time, place, link 는 생략 가능. 날짜가 지난 행사는 자동으로 숨겨집니다.

외부 라이브러리 없이 파이썬 3 표준 라이브러리만 사용합니다.
로컬 테스트:  python fetch_data.py  ->  site 폴더에서  python -m http.server 8080
"""
import email.utils
import html
import json
import os
import re
import time
import datetime as dt
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

# ----------------------------- 설정 -----------------------------
NEWS_FEEDS = [
    ("보안뉴스", "https://www.boannews.com/rss/allArticle.xml"),
    ("데일리시큐", "https://www.dailysecu.com/rss/allArticle.xml"),
    ("KISA", "https://knvd.krcert.or.kr/rss/securityNotice.do"),  # 실패하면 줄을 지워도 됩니다
]
CISCO_PSIRT = "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
BUSAN = (35.1796, 129.0756)
EVENTS_FILE = Path("events.json")

# 취급 솔루션 관련 뉴스 필터 키워드 (소문자로 비교)
MY_KEYWORDS = [
    "지니언스", "genians", "아이스페라", "ai-spera", "aispera", "에스에스알", "ssr", "metieye", "solidstep",
    "악스게이트", "axgate", "시스코", "cisco", "넷앤드", "netand", "umbrella", "meraki", "firepower",
    "edr", "nac", "ztna", "vpn", "방화벽", "웹쉘", "웹셸", "접근통제", "취약점 진단", "침입방지", "ips",
]

# 부산 보안 행사 뉴스 자동 보충용 키워드 (제목에 지역어 + 행사어가 함께 있어야 하고, 종료 표현이 없어야 함)
BUSAN_KW = ["부산", "부울경", "동남권", "벡스코", "bexco", "영남권"]
EVENT_KW = ["세미나", "교육", "컨퍼런스", "콘퍼런스", "행사", "포럼", "설명회", "웨비나", "해커톤",
            "공격방어대회", "워크숍", "아카데미", "모집", "개최 예정", "개최한다", "열린다"]
PAST_KW = ["성료", "마쳐", "마치", "성황", "폐막", "막내렸", "막 내렸", "참가해", "참가했"]

OUT = Path("site")
UA = {"User-Agent": "Mozilla/5.0 (BeeBoard/1.0)"}
KST = dt.timezone(dt.timedelta(hours=9))


# ----------------------------- 유틸 -----------------------------
def http_get(url, timeout=25):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def to_epoch(s):
    if not s:
        return 0
    s = s.strip()
    try:
        return int(email.utils.parsedate_to_datetime(s).timestamp())
    except Exception:
        pass
    try:
        d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=KST)
        return int(d.timestamp())
    except Exception:
        return 0


def clean(s):
    s = html.unescape(s or "")
    s = re.sub(r"<[^>]+>", "", s)
    return re.sub(r"\s+", " ", s).strip()


def parse_rss(url, source):
    root = ET.fromstring(http_get(url))
    out = []
    for it in root.iter("item"):
        title = clean(it.findtext("title"))
        if not title:
            continue
        pub = it.findtext("pubDate") or it.findtext("{http://purl.org/dc/elements/1.1/}date")
        out.append({
            "src": source,
            "title": title,
            "link": (it.findtext("link") or "").strip(),
            "ts": to_epoch(pub),
            "desc": clean(it.findtext("description") or it.findtext("{http://www.w3.org/2005/Atom}summary") or "")[:400],
        })
    return out


# ----------------------------- 취약점 한글 분류 -----------------------------
# 공격 유형: (영어 키워드들, 한글 이름, 한 줄 영향 설명, 위험 등급 1=빨강 2=주황 3=노랑)
# 위에서부터 먼저 일치하는 것이 적용되므로 순서를 바꾸지 마세요.
ATTACKS = [
    (("remote code execution", "arbitrary code", "code execution", "command injection", "os command",
      "code injection", "deserialization"), "원격 코드 실행", "서버를 원격으로 장악", 1),
    (("authentication bypass", "improper authentication", "missing authentication", "authorization bypass",
      "default credential", "hard-coded", "hardcoded", "auth bypass"), "인증 우회", "로그인 없이 접근", 1),
    (("privilege escalation", "elevation of privilege", "improper privilege", "privilege"),
     "권한 상승", "관리자 권한 탈취", 1),
    (("sql injection",), "SQL 인젝션", "DB 정보 탈취·변조", 1),
    (("xml external entity", "xxe", "server-side request forgery", "ssrf"), "XXE·SSRF", "내부 정보 유출", 2),
    (("path traversal", "directory traversal", "file upload", "arbitrary file", "file read", "file inclusion"),
     "파일 조작·탈취", "서버 파일 열람·유출", 2),
    (("security feature bypass", "bypass"), "보안 기능 우회", "방어 장치 무력화", 2),
    (("buffer overflow", "use after free", "use-after-free", "out-of-bounds", "memory corruption", "heap",
      "type confusion"), "메모리 손상", "코드 실행·장애 유발", 2),
    (("denial of service", "denial-of-service", "resource exhaustion", "crash"),
     "서비스 거부(DoS)", "장비 중단·마비", 3),
    (("cross-site scripting", "xss"), "XSS", "악성 스크립트 실행", 3),
    (("information disclosure", "sensitive information", "information exposure", "information leak", "disclosure"),
     "정보 노출", "민감정보 유출", 3),
]
DEFAULT_ATK = ("기타 취약점", "상세 내용은 원문 확인", 3)

# 대상 분류: (영어 단어들, 분류 이름)
DEFAULT_CAT = "기타 SW·장비"
CATS = [
    (("vpn", "firewall", "adaptive security appliance", "asa", "ftd", "firepower", "fortios", "fortigate",
      "pan-os", "sonicwall", "globalprotect", "netscaler", "big-ip", "secure client"), "방화벽·VPN"),
    (("exchange", "mail", "webmail", "zimbra", "roundcube", "postfix", "esa"), "메일 서버"),
    (("chrome", "chromium", "firefox", "edge", "safari", "browser", "webkit"), "웹 브라우저"),
    (("windows", "kernel", "linux", "ubuntu", "android", "ios", "macos", "apple"), "OS·커널"),
    (("wordpress", "php", "apache", "nginx", "tomcat", "iis", "node.js", "openssh", "ssh", "web", "joomla",
      "drupal", "struts", "spring"), "웹·서버 SW"),
    (("sql", "oracle", "mysql", "postgres", "postgresql", "database", "mongodb", "redis"), "데이터베이스"),
    (("router", "switch", "meraki", "access point", "wlc", "camera", "nas", "synology", "qnap", "d-link",
      "dlink", "tp-link", "zyxel"), "네트워크·IoT 장비"),
    (("vmware", "esxi", "vcenter", "hyper-v", "citrix", "kubernetes", "docker", "gitlab", "jenkins", "ibm",
      "sap", "gpustack", "aspera"), "서버·플랫폼"),
]
# 분류별 우리 취급 솔루션 제안 (영업 포인트)
SOL = {
    "방화벽·VPN": "AXGATE·Cisco FirePower",
    "메일 서버": "Cisco ESA",
    "웹·서버 SW": "SolidStep·MetiEye",
    "OS·커널": "지니언스 EDR",
    "웹 브라우저": "지니언스 EDR",
    "데이터베이스": "넷앤드 DB접근통제",
    "네트워크·IoT 장비": "지니언스 NAC·Meraki",
    "서버·플랫폼": "SolidStep·넷앤드 PSM",
    "Cisco 장비·SW": "Cisco 보안 패치",
    DEFAULT_CAT: "Ai-Spera CTI",
}
OUR_VENDORS = ("cisco", "genians", "axgate", "netand", "ai-spera", "ssr")
SEV_KO = {"Critical": "치명", "High": "높음", "Medium": "중간", "Low": "낮음"}


def classify(*texts):
    """제목/설명에서 공격 유형을 찾아 (한글 이름, 영향 설명, 등급) 반환"""
    for t in texts:
        low = (t or "").lower()
        for keys, label, eff, lvl in ATTACKS:
            if any(k in low for k in keys):
                return label, eff, lvl
    return DEFAULT_ATK


def categorize(text):
    low = (text or "").lower()
    for keys, cat in CATS:
        if any(re.search(r"\b" + re.escape(k) + r"\b", low) for k in keys):
            return cat
    return DEFAULT_CAT


def guess_product(desc):
    """NVD 영문 설명에서 제품명 부분만 대략 추출"""
    try:
        m = re.search(r"(?:vulnerability|flaw|issue|weakness) in (?:the )?(.{4,60}?)"
                      r"(?: (?:of|could|allows|that|which|before|prior|through|version)\b|[,.;(])", desc, re.I)
        if m:
            return m.group(1).strip()
        m = re.match(r"(.{4,40}?)(?: (?:before|prior to|through|version|allows|is|in|up to)\b|[,(])", desc)
        return (m.group(1) if m else desc[:40]).strip()
    except Exception:
        return desc[:40]


def kev_item(v):
    name = v.get("vulnerabilityName", "")
    vendor = v.get("vendorProject", "")
    product = v.get("product", "")
    short = v.get("shortDescription", "")
    atk, eff, lvl = classify(name, short)
    cat = categorize(" ".join([vendor, product, name, short]))
    if cat == DEFAULT_CAT and "cisco" in vendor.lower():
        cat = "Cisco 장비·SW"
    return {
        "cve": v.get("cveID", ""),
        "vendor": vendor,
        "product": product,
        "name": name,
        "added": v.get("dateAdded", ""),
        "due": v.get("dueDate", ""),
        "ransom": v.get("knownRansomwareCampaignUse", "") == "Known",
        "ours": any(k in vendor.lower() for k in OUR_VENDORS),
        "atk": atk, "eff": eff, "lvl": lvl, "cat": cat, "sol": SOL.get(cat, SOL[DEFAULT_CAT]),
    }


def psirt_item(x):
    desc = x.get("desc", "")
    atk, eff, lvl = classify(x["title"], desc)
    cat = categorize(x["title"])
    if cat == DEFAULT_CAT:
        cat = "Cisco 장비·SW"
    m = re.search(r"(?:Impact Rating|Severity)\W{0,6}(Critical|High|Medium|Low)", desc, re.I)
    sev = SEV_KO.get(m.group(1).capitalize(), "") if m else ""
    title = re.sub(r"\s+Vulnerabilit(?:y|ies)$", "", x["title"])
    return {"title": title, "link": x.get("link", ""), "ts": x["ts"],
            "atk": atk, "eff": eff, "lvl": lvl, "cat": cat, "sev": sev}


# ----------------------------- 수집 -----------------------------
def fetch_news():
    items, ok = [], 0
    for name, url in NEWS_FEEDS:
        try:
            items += parse_rss(url, name)
            ok += 1
        except Exception as e:
            print("[실패] 뉴스", name, e)
    if ok == 0:
        raise RuntimeError("모든 뉴스 피드 실패")
    seen, uniq = set(), []
    for it in sorted(items, key=lambda x: x["ts"], reverse=True):
        key = re.sub(r"\W", "", it["title"])[:30]
        if key in seen:
            continue
        seen.add(key)
        low = it["title"].lower()
        it["mine"] = any(k in low for k in MY_KEYWORDS)
        it.pop("desc", None)
        uniq.append(it)
    cutoff = time.time() - 48 * 3600
    recent = [x for x in uniq if x["ts"] >= cutoff]
    return (recent if len(recent) >= 8 else uniq)[:30]


def fetch_kev():
    data = json.loads(http_get(KEV_URL, 40).decode("utf-8"))
    vulns = sorted(data.get("vulnerabilities", []),
                   key=lambda v: (v.get("dateAdded", ""), v.get("cveID", "")), reverse=True)[:8]
    return [kev_item(v) for v in vulns]


def fetch_nvd():
    now = dt.datetime.now(dt.timezone.utc)
    start = now - dt.timedelta(days=2)
    q = urllib.parse.urlencode({
        "cvssV3Severity": "CRITICAL",
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 50,
    })
    data = json.loads(http_get("https://services.nvd.nist.gov/rest/json/cves/2.0?" + q, 40).decode("utf-8"))
    out = []
    for v in data.get("vulnerabilities", []):
        c = v.get("cve", {})
        score = 0
        for k in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30"):
            if c.get("metrics", {}).get(k):
                score = c["metrics"][k][0]["cvssData"].get("baseScore", 0)
                break
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        atk, eff, lvl = classify(desc)
        out.append({"cve": c.get("id", ""), "score": score, "desc": clean(desc)[:110],
                    "atk": atk, "eff": eff, "lvl": lvl, "cat": categorize(desc),
                    "prod": guess_product(clean(desc))})
    out.sort(key=lambda x: x["score"], reverse=True)
    return out[:6]


def fetch_psirt():
    items = parse_rss(CISCO_PSIRT, "Cisco")
    items.sort(key=lambda x: x["ts"], reverse=True)
    return [psirt_item(x) for x in items[:6]]


def fetch_events():
    """부산 보안 행사: 1) events.json 직접 등록분(날짜순)  2) 뉴스에서 찾은 관련 소식"""
    today = dt.datetime.now(KST).date()
    out = []
    if EVENTS_FILE.exists():
        try:
            arr = json.loads(EVENTS_FILE.read_text(encoding="utf-8"))
        except Exception as e:
            print("[경고] events.json 형식 오류:", e)
            arr = []
        for e in arr:
            try:
                s = dt.date.fromisoformat(str(e["date"]))
                en = dt.date.fromisoformat(str(e.get("end") or e["date"]))
            except Exception:
                continue
            if en < today:
                continue
            out.append({"kind": "event", "date": s.isoformat(), "end": en.isoformat(),
                        "time": e.get("time", ""), "title": e.get("title", ""),
                        "place": e.get("place", ""), "link": e.get("link", "")})
    out.sort(key=lambda x: (x["date"], x["title"]))

    found, seen = [], set()
    cutoff = time.time() - 14 * 86400
    for name, url in NEWS_FEEDS:
        try:
            items = parse_rss(url, name)
        except Exception:
            continue
        for it in items:
            t = it["title"]
            low = t.lower()
            if it["ts"] < cutoff:
                continue
            if not any(k in low for k in BUSAN_KW) or not any(k in t for k in EVENT_KW):
                continue
            if any(k in t for k in PAST_KW):
                continue
            key = re.sub(r"\W", "", t)[:30]
            if key in seen:
                continue
            seen.add(key)
            found.append({"kind": "news", "src": it["src"], "title": t, "link": it["link"], "ts": it["ts"]})
    found.sort(key=lambda x: x["ts"], reverse=True)
    print("행사: 등록", len(out), "건 / 뉴스 후보", len(found), "건")
    return out[:10] + found[:5]


def fetch_weather():
    q = urllib.parse.urlencode({
        "latitude": BUSAN[0], "longitude": BUSAN[1],
        "current": "temperature_2m,weather_code",
        "daily": "weather_code,temperature_2m_max,temperature_2m_min,precipitation_probability_max",
        "timezone": "Asia/Seoul", "forecast_days": 7,
    })
    d = json.loads(http_get("https://api.open-meteo.com/v1/forecast?" + q).decode("utf-8"))
    dd = d["daily"]
    days = []
    for i, t in enumerate(dd["time"]):
        days.append({
            "date": t, "code": dd["weather_code"][i],
            "max": round(dd["temperature_2m_max"][i]), "min": round(dd["temperature_2m_min"][i]),
            "pop": dd["precipitation_probability_max"][i],
        })
    return {"temp": round(d["current"]["temperature_2m"]), "code": d["current"]["weather_code"], "days": days}


def load_prev():
    """수집 실패 시 직전 data.json 을 재사용 (배포된 Pages 에서 가져옴)"""
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" not in repo:
        return {}
    owner, name = repo.split("/", 1)
    try:
        url = "https://%s.github.io/%s/data.json?%d" % (owner, name, int(time.time()))
        return json.loads(http_get(url, 15).decode("utf-8"))
    except Exception:
        return {}


def main():
    prev = load_prev()
    data = {"generated": int(time.time()), "errors": []}
    jobs = (("news", fetch_news, []), ("kev", fetch_kev, []), ("nvd", fetch_nvd, []),
            ("psirt", fetch_psirt, []), ("events", fetch_events, []), ("weather", fetch_weather, {}))
    for key, fn, empty in jobs:
        try:
            data[key] = fn()
            print("[성공]", key)
        except Exception as e:
            print("[실패]", key, e)
            data["errors"].append(key)
            data[key] = prev.get(key, empty)
    OUT.mkdir(exist_ok=True)
    (OUT / "data.json").write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    (OUT / "index.html").write_text(INDEX_HTML, encoding="utf-8")
    (OUT / ".nojekyll").write_text("", encoding="utf-8")
    print("완료:", len(data["news"]), "news,", len(data["kev"]), "kev,", len(data["events"]), "events")


# ----------------------------- 화면 (TV 브라우저 호환을 위해 단순 문법 사용) -----------------------------
INDEX_HTML = r"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BEE TECHNOLOGY 보안 전광판</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{width:100%;height:100%;background:#050A16;overflow:hidden;font-family:'Noto Sans KR','Malgun Gothic','Apple SD Gothic Neo',sans-serif;color:#E5EEF9}
#board{position:absolute;left:50%;top:50%;width:1080px;height:1920px;transform-origin:center center;
 background:radial-gradient(ellipse at 20% 0%,#0F2A4A 0%,#0A1428 45%,#050A16 100%);
 padding:14px;display:grid;grid-template-rows:130px 190px 380px 350px 300px 190px 1fr 40px;row-gap:14px}
.panel{background:rgba(15,28,52,.85);border:1px solid rgba(34,211,238,.18);border-radius:20px;padding:18px 22px;overflow:hidden;position:relative}
.ttl{font-size:26px;font-weight:900;letter-spacing:-.5px;color:#22D3EE;margin-bottom:10px;padding-left:12px;border-left:6px solid #22D3EE;line-height:1.1}
.ttl small{font-size:18px;font-weight:500;color:#7C93B2;margin-left:10px}
/* header */
#head{display:grid;grid-template-columns:1fr auto;align-items:center;padding:0 10px}
.brand{display:flex;align-items:center}
.brand svg{margin-right:16px}
.brand b{font-size:40px;font-weight:900;letter-spacing:-1px;display:block;line-height:1.1}
.brand span{font-size:20px;color:#7C93B2}
.clock{text-align:right}
#clock{font-size:78px;font-weight:900;color:#22D3EE;line-height:1;letter-spacing:-2px}
#date{font-size:26px;font-weight:700;margin-top:4px}
#range{font-size:18px;color:#7C93B2}
/* weather */
#wx{display:grid;grid-template-columns:270px 1fr;column-gap:18px;padding:12px 18px}
.now{border-right:1px solid rgba(34,211,238,.18);padding-right:14px}
.now .big{font-size:70px;font-weight:900;line-height:1;margin-top:6px}
.now .cond{font-size:24px;font-weight:700;color:#A9C1DE}
.week{display:grid;grid-template-columns:repeat(7,1fr);column-gap:8px}
.day{text-align:center;border-radius:14px;padding:6px 2px;background:rgba(255,255,255,.04)}
.day.today{border:2px solid #22D3EE;background:rgba(34,211,238,.1)}
.day.rain{background:rgba(59,130,246,.22)}
.day .dn{font-size:22px;font-weight:700}
.day .dd{font-size:16px;color:#7C93B2}
.day .tt{font-size:22px;font-weight:700;margin-top:2px}
.day .tt i{font-style:normal;color:#7C93B2;font-weight:500}
.day .pp{font-size:17px;color:#60A5FA}
/* rows */
.row{display:grid;grid-template-columns:100px 1fr 80px;column-gap:12px;align-items:center;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.07)}
.row:last-child{border-bottom:0}
.row.p6{padding:6px 0}
.src{font-size:17px;font-weight:700;text-align:center;border-radius:8px;padding:4px 0;background:rgba(34,211,238,.15);color:#22D3EE}
.t{font-size:26px;font-weight:700;line-height:1.28;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.ago{font-size:17px;color:#7C93B2;text-align:right}
.kev{display:grid;grid-template-columns:215px 1fr 120px;column-gap:12px;align-items:center;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.07)}
.kev:last-child{border-bottom:0}
.cve{font-family:Consolas,monospace;font-size:23px;font-weight:700;color:#22D3EE}
.kev .a{font-size:24px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.kev .b{font-size:19px;color:#C7D6EA;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.due{font-size:17px;text-align:right;color:#F97316;font-weight:700}
.tag{display:inline-block;font-size:15px;font-weight:900;padding:1px 8px;border-radius:6px;margin-right:8px;vertical-align:middle}
.tag.our{background:#F97316;color:#111}
.tag.rw{background:#EF4444;color:#fff}
.atk{display:inline-block;font-size:17px;font-weight:900;padding:1px 9px;border-radius:6px;margin-right:8px;vertical-align:middle}
.l1{background:#EF4444;color:#fff}.l2{background:#F97316;color:#111}.l3{background:#FACC15;color:#111}
.sol{color:#22D3EE;font-weight:700}
.two{display:grid;grid-template-columns:1fr 1fr;column-gap:14px}
.two .panel{padding:16px 18px}
.mini{padding:4px 0;border-bottom:1px solid rgba(255,255,255,.07);font-size:20px;line-height:1.3}
.mini:last-child{border-bottom:0}
.mini b{display:inline-block;min-width:54px;text-align:center;border-radius:6px;margin-right:8px;padding:0 6px;font-size:19px}
.sc9{background:#EF4444;color:#fff}.sc7{background:#F97316;color:#111}
.mine .t{font-size:23px}
.empty{color:#7C93B2;font-size:20px;padding:10px 0}
/* 부산 행사 */
.ev{display:grid;grid-template-columns:175px 1fr 96px;column-gap:12px;align-items:center;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.07)}
.ev:last-child{border-bottom:0}
.ev .dt{font-size:21px;font-weight:900;color:#22D3EE;white-space:nowrap}
.ev .dt.nw{color:#7C93B2;font-weight:700}
.ev .tt2{font-size:24px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ev .pl{font-size:18px;font-weight:500;color:#7C93B2;margin-left:8px}
.ev .bd{font-size:18px;font-weight:900;text-align:center;border-radius:8px;padding:3px 0;background:rgba(34,211,238,.15);color:#22D3EE}
.ev .bd.hot{background:#EF4444;color:#fff}
.ev .bd.soon{background:#F97316;color:#111}
.ev .bd.nw{background:rgba(255,255,255,.08);color:#9FB4CE;font-weight:500;font-size:16px}
/* 링크 */
a.lk{color:inherit;text-decoration:none;cursor:pointer}
a.mini{display:block}
a.lk:hover,a.lk:focus{outline:2px solid #22D3EE;outline-offset:2px;border-radius:8px;background:rgba(34,211,238,.08)}
#foot{display:flex;justify-content:space-between;align-items:center;font-size:18px;color:#7C93B2;padding:0 10px}
#foot .bad{color:#EF4444;font-weight:900}
</style>
</head>
<body>
<div id="board">
  <div id="head">
    <div class="brand">
      <svg width="370" height="100" viewBox="0 0 370 100" style="border-radius:14px">
        <defs>
          <linearGradient id="lgO" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#F9A83F"/><stop offset="1" stop-color="#E8590C"/></linearGradient>
          <linearGradient id="lgG1" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#C9C9C9"/><stop offset="1" stop-color="#9A9A9A"/></linearGradient>
          <linearGradient id="lgG2" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#8E8E8E"/><stop offset="1" stop-color="#5F5F5F"/></linearGradient>
          <linearGradient id="lgG3" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#E3E3E3"/><stop offset="1" stop-color="#BDBDBD"/></linearGradient>
        </defs>
        <rect width="370" height="100" rx="14" fill="#FFFFFF"/>
        <g stroke="#FFFFFF" stroke-width="2.6" stroke-linejoin="round">
          <polygon points="48,6 86.1,28 63.6,41 48,32" fill="url(#lgO)"/>
          <polygon points="86.1,28 86.1,72 63.6,59 63.6,41" fill="url(#lgG1)"/>
          <polygon points="86.1,72 48,94 48,68 63.6,59" fill="url(#lgG2)"/>
          <polygon points="48,94 9.9,72 32.4,59 48,68" fill="url(#lgG1)"/>
          <polygon points="9.9,72 9.9,28 32.4,41 32.4,59" fill="url(#lgG3)"/>
          <polygon points="9.9,28 48,6 48,32 32.4,41" fill="url(#lgG3)"/>
          <polygon points="48,32 63.6,41 63.6,59 48,68 32.4,59 32.4,41" fill="#ECECEC"/>
        </g>
        <text x="106" y="58" font-family="'Malgun Gothic','Noto Sans KR',sans-serif" font-size="29" font-weight="900" fill="#555555">(주)비테크놀로지</text>
        <text x="108" y="83" font-family="Arial,'Noto Sans KR',sans-serif" font-size="17" font-weight="700" letter-spacing="1.6" fill="#666666">BEE TECHNOLOGY</text>
      </svg>
      <div style="margin-left:22px"><b style="font-size:34px">오늘의 보안 브리핑</b><span>Daily Security Briefing</span></div>
    </div>
    <div class="clock"><div id="clock">--:--</div><div id="date"></div><div id="range"></div></div>
  </div>

  <div id="wx" class="panel"></div>

  <div class="panel"><div class="ttl">오늘의 보안뉴스<small>어제·오늘</small></div><div id="news"></div></div>

  <div class="panel"><div class="ttl">긴급 취약점<small>실제 공격에 악용 중 · 위험 유형과 우리 대응 솔루션</small></div><div id="kev"></div></div>

  <div class="two">
    <div class="panel"><div class="ttl">신규 Critical CVE<small>NVD</small></div><div id="nvd"></div></div>
    <div class="panel"><div class="ttl">Cisco 보안 권고<small>PSIRT</small></div><div id="psirt"></div></div>
  </div>

  <div class="panel mine"><div class="ttl">우리 솔루션 관련 뉴스<small>지니언스·AXGATE·SSR·넷앤드·Ai-Spera·Cisco</small></div><div id="mine"></div></div>

  <div class="panel"><div class="ttl">부산 보안 행사<small>세미나·교육·컨퍼런스</small></div><div id="events"></div></div>

  <div id="foot"><span id="upd">데이터 확인 중...</span><span>BEE TECHNOLOGY Security Board</span></div>
</div>

<script>
var W=1080,H=1920,DATA=null,DAYS=['일','월','화','수','목','금','토'];
function $(id){return document.getElementById(id)}
function pad(n){return n<10?'0'+n:''+n}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
function fit(){var s=Math.min(window.innerWidth/W,window.innerHeight/H);$('board').style.transform='translate(-50%,-50%) scale('+s+')'}
window.addEventListener('resize',fit);fit();

var NVD='https://nvd.nist.gov/vuln/detail/';
/* 링크가 있으면 새 탭으로 열리는 <a>, 없으면 일반 <div> */
function A(cls,url,inner){
 if(!/^https?:\/\//i.test(url||''))return '<div class="'+cls+'">'+inner+'</div>';
 return '<a class="'+cls+' lk" href="'+esc(url)+'" target="_blank" rel="noopener">'+inner+'</a>'}

function tick(){
 var d=new Date(),y=new Date(d.getTime()-864e5);
 $('clock').textContent=pad(d.getHours())+':'+pad(d.getMinutes());
 $('date').textContent=d.getFullYear()+'.'+pad(d.getMonth()+1)+'.'+pad(d.getDate())+' ('+DAYS[d.getDay()]+')';
 $('range').textContent='기준 '+pad(y.getMonth()+1)+'/'+pad(y.getDate())+' ~ '+pad(d.getMonth()+1)+'/'+pad(d.getDate());
 if(DATA){var m=Math.floor((d.getTime()/1000-DATA.generated)/60),el=$('upd');
  if(m>60){el.innerHTML='<span class="bad">갱신 지연 ('+m+'분 전 데이터)</span>'}
  else{el.textContent='마지막 갱신 '+(m<1?'방금':m+'분 전')+(DATA.errors&&DATA.errors.length?' (일부 수집 실패: '+DATA.errors.join(', ')+')':'')}}
}
function ago(ts){if(!ts)return '';var m=Math.floor((Date.now()/1000-ts)/60);if(m<60)return Math.max(m,1)+'분 전';var h=Math.floor(m/60);return h<24?h+'시간 전':Math.floor(h/24)+'일 전'}

/* 날씨 아이콘 */
function kind(c){if(c<=1)return 'sun';if(c==2)return 'part';if(c==3)return 'cloud';if(c==45||c==48)return 'fog';
 if((c>=71&&c<=77)||c==85||c==86)return 'snow';return 'rain'}
function label(c){var k=kind(c);return {sun:'맑음',part:'구름조금',cloud:'흐림',fog:'안개',snow:'눈',rain:c>=95?'뇌우':'비'}[k]}
var CL='<path d="M14 38a8 8 0 0 1 2-15 11 11 0 0 1 21 3 7 7 0 0 1-1 12z" fill="#CBD5E1"/>';
function ico(c,s){var k=kind(c),b='';
 if(k=='sun')b='<circle cx="28" cy="28" r="10" fill="#FBBF24"/><g stroke="#FBBF24" stroke-width="3" stroke-linecap="round"><path d="M28 6v6M28 44v6M6 28h6M44 28h6M12 12l4 4M40 40l4 4M44 12l-4 4M16 40l-4 4"/></g>';
 else if(k=='part')b='<circle cx="20" cy="20" r="9" fill="#FBBF24"/>'+CL;
 else if(k=='cloud')b=CL;
 else if(k=='fog')b='<g stroke="#94A3B8" stroke-width="4" stroke-linecap="round"><path d="M10 20h36M6 30h44M12 40h32"/></g>';
 else if(k=='snow')b=CL+'<g fill="#fff"><circle cx="20" cy="46" r="3"/><circle cx="30" cy="50" r="3"/><circle cx="40" cy="46" r="3"/></g>';
 else b=CL+'<g stroke="#60A5FA" stroke-width="3.5" stroke-linecap="round"><path d="M20 43l-3 8M30 43l-3 8M40 43l-3 8"/></g>';
 return '<svg width="'+s+'" height="'+s+'" viewBox="0 0 56 56">'+b+'</svg>'}

function todayStr(){var t=new Date();return t.getFullYear()+'-'+pad(t.getMonth()+1)+'-'+pad(t.getDate())}
function dnum(s){var p=s.split('-');return Date.UTC(+p[0],+p[1]-1,+p[2])/864e5}
function md(s){var p=s.split('-'),dd=new Date(+p[0],+p[1]-1,+p[2]);return pad(+p[1])+'/'+pad(+p[2])+'('+DAYS[dd.getDay()]+')'}

function renderWx(w){
 if(!w||!w.days){$('wx').innerHTML='<div class="empty">날씨 데이터 없음</div>';return}
 var ts=todayStr();
 var h='<div class="now"><div class="ttl" style="margin-bottom:0">부산 날씨</div><div style="display:flex;align-items:center">'+ico(w.code,64)+'<div class="big" style="margin-left:6px">'+w.temp+'°</div></div><div class="cond">'+label(w.code)+' · 최고 '+w.days[0].max+'° / 최저 '+w.days[0].min+'°</div></div><div class="week">';
 for(var i=0;i<w.days.length;i++){var d=w.days[i],dt=new Date(d.date+'T00:00:00'),rain=kind(d.code)=='rain'||kind(d.code)=='snow';
  h+='<div class="day'+(d.date==ts?' today':'')+(rain?' rain':'')+'"><div class="dn">'+(d.date==ts?'오늘':DAYS[dt.getDay()])+'</div><div class="dd">'+pad(dt.getMonth()+1)+'/'+pad(dt.getDate())+'</div>'+ico(d.code,46)+'<div class="tt">'+d.max+'° <i>'+d.min+'°</i></div><div class="pp">강수 '+d.pop+'%</div></div>'}
 $('wx').innerHTML=h+'</div>'}

function renderEvents(list){
 var ts=todayStr(),tn=dnum(ts),h='',cnt=0;
 for(var i=0;i<(list||[]).length&&cnt<3;i++){var e=list[i];
  if(e.kind=='event'){
   if(e.end<ts)continue;
   var sd=dnum(e.date),ed=dnum(e.end),bd,bc='';
   if(tn>=sd&&tn<=ed){bd=(sd==ed)?'오늘':'진행중';bc=' hot'}
   else{var df=sd-tn;bd='D-'+df;if(df<=7)bc=' soon'}
   var dtx=md(e.date)+(e.end!=e.date?'~'+md(e.end).slice(0,5):'')+(e.time?' '+esc(e.time):'');
   h+=A('ev',e.link,'<span class="dt">'+dtx+'</span><div class="tt2">'+esc(e.title)+(e.place?'<span class="pl">'+esc(e.place)+'</span>':'')+'</div><span class="bd'+bc+'">'+bd+'</span>');
  }else{
   h+=A('ev',e.link,'<span class="dt nw">관련 소식</span><div class="tt2">'+esc(e.title)+'</div><span class="bd nw">'+ago(e.ts)+'</span>');
  }
  cnt++}
 $('events').innerHTML=h||'<div class="empty">예정된 부산 보안 행사 정보를 준비 중입니다</div>'}

function render(d){
 renderWx(d.weather);
 var n=(d.news||[]).slice(0,4),h='';
 for(var i=0;i<n.length;i++)h+=A('row',n[i].link,'<span class="src">'+esc(n[i].src)+'</span><div class="t">'+esc(n[i].title)+'</div><span class="ago">'+ago(n[i].ts)+'</span>');
 $('news').innerHTML=h||'<div class="empty">뉴스 데이터 없음</div>';

 var k=(d.kev||[]).slice(0,4);h='';
 for(i=0;i<k.length;i++){var v=k[i];
  h+=A('kev',NVD+v.cve,'<div class="cve">'+esc(v.cve)+'</div><div><div class="a">'+(v.ours?'<span class="tag our">취급</span>':'')+(v.ransom?'<span class="tag rw">랜섬웨어</span>':'')+'<span class="atk l'+(v.lvl||3)+'">'+esc(v.atk)+'</span>'+esc(v.vendor)+' '+esc(v.product)+'</div><div class="b">'+esc(v.cat)+' · '+esc(v.eff)+' <span class="sol">→ '+esc(v.sol)+'</span></div></div><div class="due">조치 '+esc(String(v.due).slice(5))+'</div>')}
 $('kev').innerHTML=h||'<div class="empty">KEV 데이터 없음</div>';

 var nv=(d.nvd||[]).slice(0,3);h='';
 for(i=0;i<nv.length;i++)h+=A('mini',NVD+nv[i].cve,'<b class="'+(nv[i].score>=9?'sc9':'sc7')+'">'+nv[i].score+'</b><span class="atk l'+(nv[i].lvl||3)+'">'+esc(nv[i].atk)+'</span><span style="color:#22D3EE;font-weight:700;font-size:17px">'+esc(nv[i].cve)+'</span><div style="font-size:18px;color:#C7D6EA;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+esc(nv[i].cat)+' · '+esc(nv[i].eff)+'</div><div style="font-size:14px;color:#7C93B2;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+esc(nv[i].prod)+'</div>');
 $('nvd').innerHTML=h||'<div class="empty">최근 2일간 신규 Critical 없음</div>';

 var ps=(d.psirt||[]).slice(0,3);h='';
 for(i=0;i<ps.length;i++)h+=A('mini',ps[i].link,'<span class="atk l'+(ps[i].lvl||3)+'">'+esc(ps[i].atk)+'</span>'+(ps[i].sev?'<span class="atk '+(ps[i].sev=='치명'||ps[i].sev=='높음'?'l1':'l3')+'">'+esc(ps[i].sev)+'</span>':'')+'<span style="font-size:18px;color:#C7D6EA">'+esc(ps[i].eff)+'</span><div style="font-size:15px;color:#7C93B2;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+esc(ps[i].title)+' · '+ago(ps[i].ts)+'</div>');
 $('psirt').innerHTML=h||'<div class="empty">Cisco 권고 데이터 없음</div>';

 var mine=(d.news||[]).filter(function(x){return x.mine}).slice(0,2);h='';
 for(i=0;i<mine.length;i++)h+=A('row p6',mine[i].link,'<span class="src">'+esc(mine[i].src)+'</span><div class="t">'+esc(mine[i].title)+'</div><span class="ago">'+ago(mine[i].ts)+'</span>');
 $('mine').innerHTML=h||'<div class="empty">오늘 해당 키워드 뉴스가 없습니다</div>';

 renderEvents(d.events);
 tick()}

function load(){
 var x=new XMLHttpRequest();x.open('GET','data.json?'+Date.now(),true);
 x.onload=function(){try{DATA=JSON.parse(x.responseText);render(DATA)}catch(e){}};
 x.send()}
load();setInterval(load,60000);setInterval(tick,1000);tick();
setTimeout(function(){location.reload()},6*3600*1000); /* 6시간마다 전체 새로고침 (TV 브라우저 멈춤 방지) */
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
