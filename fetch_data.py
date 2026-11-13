#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
비테크놀로지 보안 전광판 - 수집기 + 화면 생성기 (GitHub Actions 용)

실행하면 site/ 폴더에 두 파일을 만듭니다.
  site/data.json   : 보안뉴스 / CISA KEV / NVD / Cisco 권고 / 국내 보안행사 / 부산 날씨 / 통계
  site/index.html  : 1080x1920 세로 전광판 화면 (data.json 을 60초마다 다시 읽음)

국내 보안행사 (우선순위 순서로 표시)
  1) events.json 에 직접 등록한 행사 (확정 일정, 날짜가 지나면 자동 숨김)
  2) 벡스코 행사일정 중 보안 관련 행사 (날짜 포함, D-day 표시)
  3) 부산 기관 게시판(TARGET_SITES)의 보안 관련 교육·세미나·행사 공고 (게시일 표시, 일정은 원문 확인)
  4) (선택) 뉴스 검색 후보 - USE_NEWS_SEARCH = True 일 때만
  events.json 예시:
  [{"date":"2026-12-03","end":"2026-12-03","time":"14:00","title":"행사명","place":"장소","link":"https://...","type":"교육"}]
  - end, time, place, link, type 은 생략 가능. type 생략 시 제목으로 자동 분류합니다.

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
    ("KISA", "https://knvd.krcert.or.kr/rss/securityNotice.do"),  # 실패하면 이 줄을 지워도 됩니다
]
CISCO_PSIRT = "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
BUSAN = (35.1796, 129.0756)
EVENTS_FILE = Path("events.json")

# 위협 수준 (자체 산정 기준이며 국가 공식 경보 단계와 무관합니다)
#   점수 = 신규 악용(2일, 최대 8) + 취급 제품 해당(7일, 건당 3점, 최대 6) + Critical CVE 5건 이상(2점) + Cisco 치명·높음 권고(3점)
THREAT_MID = 5     # 이 점수 이상이면 "주의"
THREAT_HIGH = 10   # 이 점수 이상이면 "경계"

# 자동 넘김 간격(초). 0 이면 끔 (기본: 수동 넘김 - 버튼 또는 좌우 드래그)
AUTO = {"news": 0, "kev": 0, "nvd": 0, "psirt": 0, "events": 0}

# ---- 국내 보안행사 수집 대상 (부산 기관 게시판) ----
#   require_param : 게시글 링크(또는 속성)에 이 문자열이 있는 항목만 게시글로 인정
#   need_event    : True 면 제목에 행사 단어(세미나, 교육, 모집 등)도 있어야 통과
#   label         : 화면에 표시할 짧은 이름
TARGET_SITES = [
    {"name": "부산정보산업진흥원_ICT교육", "label": "BIPA 교육",
     "url": "https://bipa.kr/board/training/list", "domain": "https://bipa.kr",
     "require_param": "seq=", "need_event": False},
    {"name": "부산정보산업진흥원_일반공고", "label": "BIPA 공고",
     "url": "https://bipa.kr/board/notice/list", "domain": "https://bipa.kr",
     "require_param": "seq=", "need_event": True},
    {"name": "부산경제진흥원_소상공인디지털", "label": "BEPA",
     "url": "https://www.bepa.kr/kor/view.do?no=1502", "domain": "https://www.bepa.kr",
     "require_param": "idx=", "need_event": True},
    {"name": "부산경제진흥원_기업지원사업", "label": "BEPA",
     "url": "https://www.bepa.kr/kor/view.do?no=1505", "domain": "https://www.bepa.kr",
     "require_param": "idx=", "need_event": True},
    {"name": "부산과학기술고등교육진흥원_사업", "label": "BISTEP",
     "url": "https://www.bistep.re.kr/board.es?mid=a10301010000&bid=0002", "domain": "https://www.bistep.re.kr",
     "require_param": "nttSn=", "need_event": True},
    {"name": "부산상공회의소_교육행사", "label": "부산상의",
     "url": "https://www.bcci.or.kr/", "domain": "https://www.bcci.or.kr",
     "require_param": "seq=", "need_event": True},
    {"name": "부산지방중소벤처기업청_공고", "label": "부산중기청",
     "url": "https://www.mss.go.kr/site/busan/ex/bbs/List.do?cbIdx=277", "domain": "https://www.mss.go.kr",
     "require_param": "seq=", "need_event": True},
]
# 벡스코 행사일정 (보안 관련 제목만 표시)
BEXCO_URL = "https://www.bexco.co.kr/kor/CMS/EventScheduleMgr/list.do?mCode=MN214"

# 보안 관련 키워드 (제목에 하나라도 있어야 표시, 영문은 소문자로 비교). 필요하면 AI, 클라우드 등을 추가하세요.
SEC_KW = ["보안", "정보보호", "사이버", "해킹", "개인정보", "랜섬", "침해", "암호", "제로트러스트", "zero trust",
          "시큐리티", "security", "isms", "ciso", "망분리", "취약점", "포렌식", "위협", "방화벽"]
EXCLUDE_WORDS = ["입찰", "채용", "낙찰", "계약", "합격", "선정 결과", "결과 안내", "결과 공고", "용역"]
EVENT_WORDS = ["세미나", "교육", "컨퍼런스", "콘퍼런스", "워크숍", "웨비나", "설명회", "포럼", "아카데미",
               "해커톤", "강좌", "강연", "실습", "행사", "대회", "박람회", "전시"]
ACTION_WORDS = ["모집", "접수", "개최", "신청", "참가", "초청", "등록", "안내", "예정", "오픈"]
PAST_WORDS = ["성료", "마쳐", "마치", "성황", "폐막", "막내렸", "참가해", "참가했", "열렸", "진행했", "수료"]
EVENT_TYPES = [
    ("웨비나", ["웨비나", "온라인 강연"]),
    ("컨퍼런스", ["컨퍼런스", "콘퍼런스"]),
    ("교육", ["교육", "강좌", "아카데미", "실습", "훈련", "과정"]),
    ("세미나", ["세미나", "포럼", "설명회", "워크숍", "강연"]),
    ("전시", ["전시", "박람회", "엑스포"]),
]

# 뉴스 검색(Google 뉴스 RSS) 후보. 뉴스 기사가 섞이므로 기본은 끔
USE_NEWS_SEARCH = False
EVENT_SEARCH = [
    "https://news.google.com/rss/search?q=" + urllib.parse.quote(
        "보안 세미나 OR 정보보호 세미나 OR 사이버보안 세미나 OR 보안 컨퍼런스 OR 정보보호 컨퍼런스")
    + "&hl=ko&gl=KR&ceid=KR:ko",
    "https://news.google.com/rss/search?q=" + urllib.parse.quote(
        "보안 교육 모집 OR 사이버보안 교육 모집 OR 정보보호 교육 신청 OR 보안 웨비나 OR 정보보호 설명회")
    + "&hl=ko&gl=KR&ceid=KR:ko",
]

OUT = Path("site")
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
      "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.5"}
KST = dt.timezone(dt.timedelta(hours=9))

_KEV_CACHE = None   # KEV 원본 (한 번만 내려받아 재사용)
_NVD_TOTAL = None   # 최근 2일 Critical CVE 전체 건수


# ----------------------------- 유틸 -----------------------------
def http_get(url, timeout=25):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def decode_html(raw):
    for enc in ("utf-8", "cp949"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "ignore")


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
    s = re.sub(r"<[^>]+>", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def strip_source(title):
    """Google 뉴스 제목 끝의 ' - 언론사' 를 제거"""
    parts = title.rsplit(" - ", 1)
    if len(parts) == 2 and len(parts[1]) <= 20:
        return parts[0].strip()
    return title


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
            "desc": clean(it.
