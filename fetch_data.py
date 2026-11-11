#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
비테크놀로지 보안 전광판 - 수집기 + 화면 생성기 (GitHub Actions 용)

실행하면 site/ 폴더에 두 파일을 만듭니다.
  site/data.json   : 뉴스 / CISA KEV / NVD / Cisco 권고 / 부산 보안 행사 / 부산 날씨 / 통계(추이·위협수준·긴급알림)
  site/index.html  : 1080x1920 세로 전광판 화면 (data.json 을 60초마다 다시 읽음)

부산 행사는 저장소 최상위의 events.json 에 직접 등록합니다 (없어도 동작).
  [{"date":"2026-11-20","end":"2026-11-21","time":"10:00","title":"행사명","place":"벡스코","link":"https://..."}]
  - end, time, place, link 는 생략 가능. 날짜가 지난 행사는 자동으로 숨겨집니다.

화면 동작
  - 하단 티커: 긴급 알림, CVE, 뉴스, 행사가 가로로 계속 흐릅니다.
  - 자동 순환: 뉴스 / 긴급 취약점 / 우리 솔루션 뉴스가 몇 초마다 다음 페이지로 넘어갑니다.
  - 상태 바: 평소에는 위협 수준과 신규 건수, 긴급 조건이 생기면 빨간 깜빡임 배너로 바뀝니다.
  - 추이 그래프: 최근 7일 CISA KEV 신규 등재 건수, 최근 30일 공격 유형 비율.

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

# 위협 수준 (자체 산정 기준이며 국가 공식 경보 단계와 무관합니다)
#   점수 = 신규 악용(2일, 최대 8) + 취급 제품 해당(7일, 건당 3점, 최대 6) + Critical CVE 5건 이상(2점) + Cisco 긴급 권고(3점)
THREAT_MID = 5    # 이 점수 이상이면 "주의"
THREAT_HIGH = 10  # 이 점수 이상이면 "경계"

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

_KEV_CACHE = None   # KEV 원본 (한 번만 내려받아 재사용)
_NVD_TOTAL = None   # 최근 2일 Critical CVE 전체 건수


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
    return (recent if len(recent) >= 12 else uniq)[:30]


def load_kev():
    global _KEV_CACHE
    if _KEV_CACHE is None:
        _KEV_CACHE = json.loads(http_get(KEV_URL, 40).decode("utf-8"))
    return _KEV_CACHE


def fetch_kev():
    data = load_kev()
    vulns = sorted(data.get("vulnerabilities", []),
                   key=lambda v: (v.get("dateAdded", ""), v.get("cveID", "")), reverse=True)[:8]
    return [kev_item(v) for v in vulns]


def fetch_nvd():
    global _NVD_TOTAL
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
    _NVD_TOTAL = int(data.get("totalResults", len(out)) or 0)
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


def build_stats(psirt, prev_nvd=0):
    """KEV 원본으로 7일 추이, 30일 공격 유형 비율, 위협 수준, 긴급 알림을 계산"""
    kev = _KEV_CACHE
    if not kev:
        raise RuntimeError("KEV 데이터 없음")
    # CISA 등재일은 미국 기준이라 UTC 날짜를 '오늘'로 사용
    anchor = dt.datetime.now(dt.timezone.utc).date()
    days = [anchor - dt.timedelta(days=i) for i in range(6, -1, -1)]
    counts = dict((d.isoformat(), 0) for d in days)
    s30 = (anchor - dt.timedelta(days=29)).isoformat()
    s7 = (anchor - dt.timedelta(days=6)).isoformat()
    s3 = (anchor - dt.timedelta(days=3)).isoformat()
    s2 = (anchor - dt.timedelta(days=2)).isoformat()

    types, total30, ours7 = {}, 0, 0
    a_ours, a_rw = [], []
    vulns = sorted(kev.get("vulnerabilities", []), key=lambda v: v.get("dateAdded", ""), reverse=True)
    for v in vulns:
        a = v.get("dateAdded", "")
        if a in counts:
            counts[a] += 1
        if a < s30:
            break
        lab = classify(v.get("vulnerabilityName", ""), v.get("shortDescription", ""))[0]
        if lab == DEFAULT_ATK[0]:
            lab = "기타"
        types[lab] = types.get(lab, 0) + 1
        total30 += 1
        ours = any(k in v.get("vendorProject", "").lower() for k in OUR_VENDORS)
        if ours and a >= s7:
            ours7 += 1
        if ours and a >= s3 and len(a_ours) < 3:
            it = kev_item(v)
            a_ours.append("취급 제품 취약점 %s · %s %s · %s → %s" % (it["cve"], it["vendor"], it["product"], it["atk"], it["sol"]))
        if (not ours) and v.get("knownRansomwareCampaignUse", "") == "Known" and a >= s2 and len(a_rw) < 2:
            a_rw.append("랜섬웨어 연루 취약점 등재 %s · %s %s" % (v.get("cveID", ""), v.get("vendorProject", ""), v.get("product", "")))

    now = time.time()
    a_ps = []
    for p in psirt or []:
        if p.get("sev") in ("치명", "높음") and now - p.get("ts", 0) <= 86400 and len(a_ps) < 2:
            a_ps.append("Cisco 보안 권고 · %s (%s, 위험도 %s)" % (p.get("title", ""), p.get("atk", ""), p.get("sev", "")))

    nvd = _NVD_TOTAL if _NVD_TOTAL is not None else prev_nvd
    new2 = counts.get(anchor.isoformat(), 0) + counts.get((anchor - dt.timedelta(days=1)).isoformat(), 0)
    score = min(new2, 8) + 3 * min(ours7, 2) + (2 if nvd >= 5 else 0) + (3 if a_ps else 0)
    level = "경계" if score >= THREAT_HIGH else ("주의" if score >= THREAT_MID else "안정")

    items = sorted([(k, n) for k, n in types.items() if k != "기타"], key=lambda x: -x[1])
    top = items[:4]
    rest = sum(n for _, n in items[4:]) + types.get("기타", 0)
    if rest:
        top.append(("기타", rest))
    return {
        "days": [{"d": d.isoformat(), "n": counts[d.isoformat()]} for d in days],
        "types": [{"name": k, "n": n} for k, n in top],
        "total30": total30, "new2": new2, "ours7": ours7, "nvd": nvd,
        "score": score, "level": level, "alerts": (a_ours + a_ps + a_rw)[:5],
    }


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
    try:
        data["stats"] = build_stats(data.get("psirt", []), (prev.get("stats") or {}).get("nvd", 0))
        print("[성공] stats 위협수준:", data["stats"]["level"], "점수:", data["stats"]["score"])
    except Exception as e:
        print("[실패] stats", e)
        data["errors"].append("stats")
        data["stats"] = prev.get("stats", {})
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
 padding:14px;display:grid;grid-template-rows:116px 60px 160px 310px 290px 180px 220px 150px 1fr 52px 28px;row-gap:10px}
.panel{background:rgba(15,28,52,.85);border:1px solid rgba(34,211,238,.18);border-radius:20px;padding:18px 22px;overflow:hidden;position:relative}
.ttl{font-size:26px;font-weight:900;letter-spacing:-.5px;color:#22D3EE;margin-bottom:10px;padding-left:12px;border-left:6px solid #22D3EE;line-height:1.1}
.ttl small{font-size:18px;font-weight:500;color:#7C93B2;margin-left:10px}
.dots{position:absolute;right:22px;top:24px}
.dots i{display:inline-block;width:10px;height:10px;border-radius:50%;background:rgba(255,255,255,.2);margin-left:6px}
.dots i.on{background:#22D3EE}
.fade{transition:opacity .4s ease}
.fade.out{opacity:0}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.35}}
/* header */
#head{display:grid;grid-template-columns:1fr auto;align-items:center;padding:0 10px}
.brand{display:flex;align-items:center}
.brand svg{margin-right:16px}
.brand b{font-size:40px;font-weight:900;letter-spacing:-1px;display:block;line-height:1.1}
.brand span{font-size:20px;color:#7C93B2}
.clock{text-align:right}
#clock{font-size:60px;font-weight:900;color:#22D3EE;line-height:60px;letter-spacing:-2px}
#date{font-size:22px;font-weight:700;line-height:28px}
#range{font-size:15px;color:#7C93B2;line-height:18px}
/* 상태 바 */
#status{display:flex;align-items:center;padding:6px 18px;transition:background .4s}
#status.alerting{background:rgba(127,29,29,.75);border-color:#EF4444}
.chip{display:flex;align-items:baseline;font-size:20px;font-weight:700;padding:4px 16px;border-radius:12px;background:rgba(255,255,255,.08);margin-right:22px;white-space:nowrap}
.chip b{font-size:30px;font-weight:900;margin-left:8px}
.chip small{font-size:13px;margin-left:8px;opacity:.7;font-weight:500}
.chip.lv0{background:#34D399;color:#04281c}
.chip.lv1{background:#F97316;color:#111}
.chip.lv2{background:#EF4444;color:#fff}
#stats{display:flex;flex:1;justify-content:space-between}
.st{display:flex;align-items:baseline;white-space:nowrap}
.st .lb{font-size:17px;color:#9FB4CE;margin-right:8px}
.st b{font-size:38px;font-weight:900;color:#22D3EE;line-height:1}
.st em{font-style:normal;font-size:17px;color:#9FB4CE;margin-left:3px}
#alert{display:none;align-items:center;flex:1;min-width:0}
#status.alerting #alert{display:flex}
#status.alerting #stats,#status.alerting #chip{display:none}
.alchip{background:#EF4444;color:#fff;font-size:26px;font-weight:900;padding:4px 18px;border-radius:12px;margin-right:18px;animation:blink 1.1s ease-in-out infinite;white-space:nowrap}
.altx{font-size:26px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1;min-width:0}
.alno{font-size:18px;color:#FCA5A5;margin-left:12px;white-space:nowrap}
/* weather */
#wx{display:grid;grid-template-columns:270px 1fr;column-gap:18px;padding:12px 18px}
.now{border-right:1px solid rgba(34,211,238,.18);padding-right:14px}
.now .big{font-size:56px;font-weight:900;line-height:1}
.now .cond{font-size:22px;font-weight:700;color:#A9C1DE;line-height:28px}
.week{display:grid;grid-template-columns:repeat(7,1fr);column-gap:8px}
.day{text-align:center;border-radius:14px;padding:4px 2px;background:rgba(255,255,255,.04)}
.day.today{border:2px solid #22D3EE;background:rgba(34,211,238,.1)}
.day.rain{background:rgba(59,130,246,.22)}
.day .dn{font-size:20px;font-weight:700;line-height:24px}
.day .dd{font-size:14px;color:#7C93B2;line-height:16px}
.day .tt{font-size:20px;font-weight:700;line-height:24px}
.day .tt i{font-style:normal;color:#7C93B2;font-weight:500}
.day .pp{font-size:15px;color:#60A5FA;line-height:18px}
/* rows */
.row{display:grid;grid-template-columns:100px 1fr 80px;column-gap:12px;align-items:center;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.07)}
.row:last-child{border-bottom:0}
.src{font-size:17px;font-weight:700;text-align:center;border-radius:8px;padding:4px 0;background:rgba(34,211,238,.15);color:#22D3EE}
.t{font-size:25px;font-weight:700;line-height:1.28;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.ago{font-size:17px;color:#7C93B2;text-align:right}
.kev{display:grid;grid-template-columns:215px 1fr 120px;column-gap:12px;align-items:center;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.07)}
.kev:last-child{border-bottom:0}
.cve{font-family:Consolas,monospace;font-size:23px;font-weight:700;color:#22D3EE}
.kev .a{font-size:24px;font-weight:700;line-height:30px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.kev .b{font-size:19px;line-height:24px;color:#C7D6EA;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.due{font-size:17px;text-align:right;color:#F97316;font-weight:700}
.tag{display:inline-block;font-size:15px;font-weight:900;padding:1px 8px;border-radius:6px;margin-right:8px;vertical-align:middle}
.tag.our{background:#F97316;color:#111}
.tag.rw{background:#EF4444;color:#fff}
.atk{display:inline-block;font-size:17px;font-weight:900;padding:1px 9px;border-radius:6px;margin-right:8px;vertical-align:middle;line-height:22px}
.l1{background:#EF4444;color:#fff}.l2{background:#F97316;color:#111}.l3{background:#FACC15;color:#111}
.sol{color:#22D3EE;font-weight:700}
.two{display:grid;grid-template-columns:1fr 1fr;column-gap:14px}
.two .panel{padding:16px 18px}
.mini{padding:3px 0;border-bottom:1px solid rgba(255,255,255,.07);font-size:20px;line-height:26px}
.mini:last-child{border-bottom:0}
.mini b{display:inline-block;min-width:54px;text-align:center;border-radius:6px;margin-right:8px;padding:0 6px;font-size:19px}
.sc9{background:#EF4444;color:#fff}.sc7{background:#F97316;color:#111}
.mine .t{font-size:23px}
.empty{color:#7C93B2;font-size:20px;padding:10px 0}
/* 추이 차트 */
#chart{display:grid;grid-template-columns:1.1fr 1fr;column-gap:26px;padding:14px 22px}
#chart .ttl{margin-bottom:6px}
.bars{display:flex;align-items:flex-end;height:112px}
.bc{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end}
.bv{font-size:17px;font-weight:900;color:#C7D6EA;line-height:18px;height:18px}
.bar{width:60%;max-width:46px;height:0;background:#2563EB;border-radius:6px 6px 0 0;transition:height 1s ease}
.bar.td{background:#22D3EE}
.bl{font-size:14px;color:#7C93B2;line-height:18px;height:18px}
.dn2{display:flex;align-items:center;height:112px}
.dnw{position:relative;width:104px;height:104px;margin-right:16px;flex:none}
.dnc{position:absolute;left:0;top:0;width:104px;height:104px;display:flex;flex-direction:column;align-items:center;justify-content:center}
.dnc b{font-size:28px;font-weight:900;line-height:1}
.dnc span{font-size:13px;color:#7C93B2}
.lg{font-size:17px;line-height:21px;white-space:nowrap;display:flex;align-items:center}
.lg i{width:12px;height:12px;border-radius:3px;margin-right:8px;flex:none}
.lg b{margin-left:6px;color:#22D3EE}
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
/* 티커 */
#ticker{padding:0 18px;display:flex;align-items:center;overflow:hidden}
.live{font-size:18px;font-weight:900;color:#EF4444;margin-right:16px;white-space:nowrap;display:flex;align-items:center}
.live i{display:inline-block;width:12px;height:12px;border-radius:50%;background:#EF4444;margin-right:8px;animation:blink 1s infinite}
#tkmask{flex:1;overflow:hidden;white-space:nowrap}
#tk{display:inline-block;white-space:nowrap;will-change:transform}
@keyframes tkscroll{from{transform:translateX(0)}to{transform:translateX(-50%)}}
.ti{display:inline-block;font-size:24px;font-weight:700;margin-right:56px}
.tg{display:inline-block;font-size:16px;font-weight:900;padding:1px 9px;border-radius:6px;margin-right:10px;vertical-align:middle}
.tgN{background:rgba(34,211,238,.2);color:#22D3EE}
.tgC{background:#F97316;color:#111}
.tgA{background:#EF4444;color:#fff}
.tgE{background:#34D399;color:#04281c}
/* 링크 */
a.lk{color:inherit;text-decoration:none;cursor:pointer}
a.mini{display:block}
a.lk:hover,a.lk:focus{outline:2px solid #22D3EE;outline-offset:2px;border-radius:8px;background:rgba(34,211,238,.08)}
#foot{display:flex;justify-content:space-between;align-items:center;font-size:18px;color:#7C93B2;padding:0 10px}
#foot .bad{color:#EF4444;font-weight:900}
.pulse{display:inline-block;width:10px;height:10px;border-radius:50%;background:#34D399;margin-right:8px;animation:blink 2s infinite}
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

  <div id="status" class="panel">
    <div id="chip" class="chip lv0">위협 수준<b>-</b><small>자체 산정</small></div>
    <div id="stats">
      <div class="st"><span class="lb">신규 악용(2일)</span><b id="c1">0</b><em>건</em></div>
      <div class="st"><span class="lb">Critical CVE(2일)</span><b id="c2">0</b><em>건</em></div>
      <div class="st"><span class="lb">취급 제품 해당(7일)</span><b id="c3">0</b><em>건</em></div>
    </div>
    <div id="alert"></div>
  </div>

  <div id="wx" class="panel"></div>

  <div class="panel"><div class="ttl">오늘의 보안뉴스<small>어제·오늘</small></div><div class="dots" id="d-news"></div><div id="news" class="fade"></div></div>

  <div class="panel"><div class="ttl">긴급 취약점<small>실제 공격에 악용 중 · 위험 유형과 우리 대응 솔루션</small></div><div class="dots" id="d-kev"></div><div id="kev" class="fade"></div></div>

  <div id="chart" class="panel">
    <div><div class="ttl">최근 7일 악용 취약점<small>CISA 신규 등재 건수</small></div><div id="trend"></div></div>
    <div><div class="ttl">공격 유형 비율<small>최근 30일</small></div><div id="donut"></div></div>
  </div>

  <div class="two">
    <div class="panel"><div class="ttl">신규 Critical CVE<small>NVD</small></div><div id="nvd"></div></div>
    <div class="panel"><div class="ttl">Cisco 보안 권고<small>PSIRT</small></div><div id="psirt"></div></div>
  </div>

  <div class="panel mine"><div class="ttl">우리 솔루션 관련 뉴스<small>지니언스·AXGATE·SSR·넷앤드·Ai-Spera·Cisco</small></div><div class="dots" id="d-mine"></div><div id="mine" class="fade"></div></div>

  <div class="panel"><div class="ttl">부산 보안 행사<small>세미나·교육·컨퍼런스</small></div><div id="events"></div></div>

  <div id="ticker" class="panel"><span class="live"><i></i>LIVE</span><div id="tkmask"><div id="tk"></div></div></div>

  <div id="foot"><span><i class="pulse"></i><span id="upd">데이터 확인 중...</span></span><span>BEE TECHNOLOGY Security Board</span></div>
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
 var h='<div class="now"><div class="ttl" style="margin-bottom:2px">부산 날씨</div><div style="display:flex;align-items:center">'+ico(w.code,52)+'<div class="big" style="margin-left:6px">'+w.temp+'°</div></div><div class="cond">'+label(w.code)+' · 최고 '+w.days[0].max+'° / 최저 '+w.days[0].min+'°</div></div><div class="week">';
 for(var i=0;i<w.days.length;i++){var d=w.days[i],dt=new Date(d.date+'T00:00:00'),rain=kind(d.code)=='rain'||kind(d.code)=='snow';
  h+='<div class="day'+(d.date==ts?' today':'')+(rain?' rain':'')+'"><div class="dn">'+(d.date==ts?'오늘':DAYS[dt.getDay()])+'</div><div class="dd">'+pad(dt.getMonth()+1)+'/'+pad(dt.getDate())+'</div>'+ico(d.code,38)+'<div class="tt">'+d.max+'° <i>'+d.min+'°</i></div><div class="pp">강수 '+d.pop+'%</div></div>'}
 $('wx').innerHTML=h+'</div>'}

/* ---------- 자동 순환 패널 (뉴스 / 긴급 취약점 / 우리 솔루션 뉴스) ---------- */
var LIST={news:[],kev:[],mine:[]};
var PER={news:3,kev:3,mine:1};
var MAXP={news:4,kev:3,mine:3};
var PAGE={news:0,kev:0,mine:0};
var EMPTY={news:'<div class="empty">뉴스 데이터 없음</div>',kev:'<div class="empty">KEV 데이터 없음</div>',mine:'<div class="empty">오늘 해당 키워드 뉴스가 없습니다</div>'};
var RENDER={
 news:function(n){return A('row',n.link,'<span class="src">'+esc(n.src)+'</span><div class="t">'+esc(n.title)+'</div><span class="ago">'+ago(n.ts)+'</span>')},
 mine:function(n){return A('row',n.link,'<span class="src">'+esc(n.src)+'</span><div class="t">'+esc(n.title)+'</div><span class="ago">'+ago(n.ts)+'</span>')},
 kev:function(v){return A('kev',NVD+v.cve,'<div class="cve">'+esc(v.cve)+'</div><div><div class="a">'+(v.ours?'<span class="tag our">취급</span>':'')+(v.ransom?'<span class="tag rw">랜섬웨어</span>':'')+'<span class="atk l'+(v.lvl||3)+'">'+esc(v.atk)+'</span>'+esc(v.vendor)+' '+esc(v.product)+'</div><div class="b">'+esc(v.cat)+' · '+esc(v.eff)+' <span class="sol">→ '+esc(v.sol)+'</span></div></div><div class="due">조치 '+esc(String(v.due).slice(5))+'</div>')}
};
function pages(name){return Math.max(1,Math.min(MAXP[name],Math.ceil(LIST[name].length/PER[name])))}
function paint(name){
 var n=pages(name);if(PAGE[name]>=n)PAGE[name]=0;
 var s=PAGE[name]*PER[name],items=LIST[name].slice(s,s+PER[name]),h='',i;
 for(i=0;i<items.length;i++)h+=RENDER[name](items[i]);
 $(name).innerHTML=h||EMPTY[name];
 var dd='';if(n>1){for(i=0;i<n;i++)dd+='<i'+(i==PAGE[name]?' class="on"':'')+'></i>'}
 $('d-'+name).innerHTML=dd}
function flip(name){
 if(pages(name)<2)return;
 var el=$(name);el.className='fade out';
 setTimeout(function(){PAGE[name]=(PAGE[name]+1)%pages(name);paint(name);el.className='fade'},420)}
setInterval(function(){flip('news')},14000);
setInterval(function(){flip('kev')},17000);
setInterval(function(){flip('mine')},11000);

/* ---------- 상태 바 / 긴급 알림 ---------- */
var ALERTS=[],AI=0;
function countTo(el,to){
 to=+to||0;
 var cur=el.getAttribute('data-v');
 if(cur==String(to))return;
 var from=cur==null?0:+cur;el.setAttribute('data-v',to);
 var step=0,steps=20;clearInterval(el._t);
 el._t=setInterval(function(){step++;el.textContent=Math.round(from+(to-from)*step/steps);if(step>=steps){clearInterval(el._t);el.textContent=to}},40)}
function paintAlert(){
 var s=$('status');
 if(!ALERTS.length){s.className='panel';return}
 s.className='panel alerting';
 $('alert').innerHTML='<span class="alchip">긴급</span><span class="altx">'+esc(ALERTS[AI])+'</span>'+(ALERTS.length>1?'<span class="alno">'+(AI+1)+'/'+ALERTS.length+'</span>':'')}
setInterval(function(){if(ALERTS.length>1){AI=(AI+1)%ALERTS.length;paintAlert()}},8000);
function renderStatus(st){
 st=st||{};
 var lv={'안정':0,'주의':1,'경계':2}[st.level];if(lv==null)lv=0;
 $('chip').className='chip lv'+lv;
 $('chip').innerHTML='위협 수준<b>'+esc(st.level||'-')+'</b><small>자체 산정</small>';
 countTo($('c1'),st.new2);countTo($('c2'),st.nvd);countTo($('c3'),st.ours7);
 ALERTS=st.alerts||[];if(AI>=ALERTS.length)AI=0;
 paintAlert()}

/* ---------- 추이 차트 (막대 + 도넛) ---------- */
var TSIG='',COLS=['#EF4444','#F97316','#FACC15','#22D3EE','#64748B'];
function renderTrend(st){
 var sig=JSON.stringify([st&&st.days,st&&st.types]);
 if(sig==TSIG)return;TSIG=sig;
 if(!st||!st.days){$('trend').innerHTML='<div class="empty">추이 데이터 없음</div>';$('donut').innerHTML='<div class="empty">데이터 없음</div>';return}
 var days=st.days,m=1,i,h='';
 for(i=0;i<days.length;i++)if(days[i].n>m)m=days[i].n;
 for(i=0;i<days.length;i++){var n=days[i].n,hg=n>0?Math.max(4,Math.round(n/m*72)):0;
  h+='<div class="bc"><span class="bv">'+n+'</span><div class="bar'+(i==days.length-1?' td':'')+'" data-h="'+hg+'"></div><span class="bl">'+days[i].d.slice(5).replace('-','/')+'</span></div>'}
 $('trend').innerHTML='<div class="bars">'+h+'</div>';
 var ty=st.types||[],t=0;
 for(i=0;i<ty.length;i++)t+=ty[i].n;
 if(!t){$('donut').innerHTML='<div class="empty">데이터 없음</div>'}
 else{
  var C=2*Math.PI*40,cum=0,segs='',lg='';
  for(i=0;i<ty.length;i++){var len=C*ty[i].n/t,col=COLS[i%COLS.length];
   segs+='<circle cx="52" cy="52" r="40" fill="none" stroke="'+col+'" stroke-width="14" transform="rotate(-90 52 52)" style="stroke-dasharray:0 '+C+';transition:stroke-dasharray 1s ease" stroke-dashoffset="'+(-cum)+'" data-d="'+len+' '+(C-len)+'"/>';
   cum+=len;
   lg+='<div class="lg"><i style="background:'+col+'"></i>'+esc(ty[i].name)+'<b>'+ty[i].n+'</b></div>'}
  $('donut').innerHTML='<div class="dn2"><div class="dnw"><svg width="104" height="104" viewBox="0 0 104 104"><circle cx="52" cy="52" r="40" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="14"/>'+segs+'</svg><div class="dnc"><b>'+t+'</b><span>30일</span></div></div><div>'+lg+'</div></div>'}
 setTimeout(function(){
  var bs=$('trend').getElementsByClassName('bar'),k;
  for(k=0;k<bs.length;k++)bs[k].style.height=bs[k].getAttribute('data-h')+'px';
  var cs=$('donut').getElementsByTagName('circle');
  for(k=0;k<cs.length;k++){var dd=cs[k].getAttribute('data-d');if(dd)cs[k].style.strokeDasharray=dd}
 },80)}

/* ---------- 하단 티커 ---------- */
var TK_LAST='';
function setTicker(html){
 if(html==TK_LAST)return;TK_LAST=html;
 var tk=$('tk');tk.style.animation='none';tk.innerHTML=html;
 var uw=tk.offsetWidth||1,mw=$('tkmask').offsetWidth||900;
 var n=Math.max(1,Math.ceil(mw/uw)),blk='',i;
 for(i=0;i<n;i++)blk+=html;
 tk.innerHTML=blk+blk;
 var bw=tk.offsetWidth/2;
 tk.style.animation='tkscroll '+Math.max(20,Math.round(bw/70))+'s linear infinite'}
function buildTicker(d){
 var u=[],st=d.stats||{},al=st.alerts||[],i;
 for(i=0;i<al.length;i++)u.push('<span class="ti"><b class="tg tgA">긴급</b>'+esc(al[i])+'</span>');
 var kv=(d.kev||[]).slice(0,5),nw=(d.news||[]).slice(0,8),ts=todayStr();
 var ev=(d.events||[]).filter(function(e){return e.kind=='event'&&e.end>=ts}).slice(0,2);
 for(i=0;i<nw.length;i++){
  u.push('<span class="ti"><b class="tg tgN">뉴스</b>'+esc(nw[i].title)+'</span>');
  if(kv[i])u.push('<span class="ti"><b class="tg tgC">CVE</b>'+esc(kv[i].cve)+' '+esc(kv[i].atk)+' · '+esc(kv[i].vendor)+' '+esc(kv[i].product)+'</span>')}
 for(i=0;i<ev.length;i++)u.push('<span class="ti"><b class="tg tgE">행사</b>'+md(ev[i].date)+' '+esc(ev[i].title)+'</span>');
 if(!u.length)u.push('<span class="ti">데이터를 불러오는 중입니다</span>');
 setTicker(u.join(''))}

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
 LIST.news=(d.news||[]).slice(0,12);
 LIST.kev=(d.kev||[]).slice(0,8);
 LIST.mine=(d.news||[]).filter(function(x){return x.mine}).slice(0,3);
 paint('news');paint('kev');paint('mine');

 var i,h='',nv=(d.nvd||[]).slice(0,2);
 for(i=0;i<nv.length;i++)h+=A('mini',NVD+nv[i].cve,'<b class="'+(nv[i].score>=9?'sc9':'sc7')+'">'+nv[i].score+'</b><span class="atk l'+(nv[i].lvl||3)+'">'+esc(nv[i].atk)+'</span><span style="color:#22D3EE;font-weight:700;font-size:17px">'+esc(nv[i].cve)+'</span><div style="font-size:18px;line-height:22px;color:#C7D6EA;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+esc(nv[i].cat)+' · '+esc(nv[i].eff)+'</div><div style="font-size:14px;line-height:17px;color:#7C93B2;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+esc(nv[i].prod)+'</div>');
 $('nvd').innerHTML=h||'<div class="empty">최근 2일간 신규 Critical 없음</div>';

 var ps=(d.psirt||[]).slice(0,2);h='';
 for(i=0;i<ps.length;i++)h+=A('mini',ps[i].link,'<span class="atk l'+(ps[i].lvl||3)+'">'+esc(ps[i].atk)+'</span>'+(ps[i].sev?'<span class="atk '+(ps[i].sev=='치명'||ps[i].sev=='높음'?'l1':'l3')+'">'+esc(ps[i].sev)+'</span>':'')+'<span style="font-size:18px;color:#C7D6EA">'+esc(ps[i].eff)+'</span><div style="font-size:15px;line-height:20px;color:#7C93B2;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+esc(ps[i].title)+' · '+ago(ps[i].ts)+'</div>');
 $('psirt').innerHTML=h||'<div class="empty">Cisco 권고 데이터 없음</div>';

 renderEvents(d.events);
 renderStatus(d.stats);
 renderTrend(d.stats);
 buildTicker(d);
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
