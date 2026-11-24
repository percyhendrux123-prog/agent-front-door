"""Facts, read from the business's own human facts page.

The page is the only source. Each fact is an <h2> question and the text under it, copied word for
word (tags stripped, whitespace collapsed). Nothing is summarised, rewritten or generated, so an
agent can never be told something the page does not say.
"""
from __future__ import annotations

import hashlib
import html
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urljoin

STOP = set("""a an and are as at be by can do does for from how i in is it its me my of on or our
the their there they this to us we what when where which who why will with you your about
deploy axiom""".split())


def _ws(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


# Plain words a caller might use -> the page's own words. Only widens the match; answers are
# still the page's text.
SYN = {
    "cost": "priced", "costs": "priced", "price": "priced", "prices": "priced", "pricing": "priced",
    "fee": "priced", "fees": "priced", "much": "priced", "charge": "priced",
    "located": "where", "location": "where", "based": "where", "office": "where", "city": "where",
    "founder": "what", "owns": "what", "company": "what",
    "schedule": "book", "call": "book", "contact": "book", "hire": "book", "start": "book", "email": "book",
    "hipaa": "hipaa", "compliance": "hipaa", "compliant": "hipaa",
    "industries": "for", "who": "for", "dentists": "dental", "lawyers": "law", "attorneys": "law", "clients": "for", "serve": "for", "customers": "for",
    "approve": "not", "approval": "not", "own": "not",
    "host": "run", "hosted": "run", "data": "run", "cloud": "run", "live": "run", "computer": "run",
    "built": "built", "proof": "built", "examples": "built", "case": "built",
    "linkedin": "else", "instagram": "else", "social": "else", "youtube": "else", "github": "else",
}


class _FactsParser(HTMLParser):
    """Collects <h1>, the byline, and each <h2> with the block text after it, inside <article>."""

    BLOCK = {"p", "li"}

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.in_article = 0
        self.skip = 0
        self.cur_tag: Optional[str] = None
        self.buf: List[str] = []
        self.title = ""
        self.byline = ""
        self.sections: List[Dict] = []
        self.links: List[str] = []
        self.visible: List[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("script", "style"):
            self.skip += 1
            return
        if tag == "article":
            self.in_article += 1
        if not self.in_article:
            return
        if tag in ("h1", "h2") or tag in self.BLOCK:
            self.cur_tag, self.buf = tag, []
            self._cls = a.get("class", "")
        if tag == "a" and a.get("href") and self.sections:
            self.links.append(urljoin(self.base_url, a["href"]))

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.skip = max(0, self.skip - 1)
            return
        if tag == "article":
            self.in_article = max(0, self.in_article - 1)
        if not self.in_article or tag != self.cur_tag:
            return
        text = _ws("".join(self.buf))
        self.cur_tag = None
        if not text:
            return
        self.visible.append(text)
        if tag == "h1":
            self.title = text
        elif tag == "h2":
            self.links = []
            self.sections.append({"question": text, "blocks": [], "links": self.links})
        elif self.sections:
            self.sections[-1]["blocks"].append(("- " if tag == "li" else "") + text)
        elif "byline" in (self._cls or ""):
            self.byline = text

    def handle_data(self, data):
        if self.skip or not self.in_article or self.cur_tag is None:
            return
        self.buf.append(data)


class Facts:
    def __init__(self, page_html: str, source_url: str):
        p = _FactsParser(source_url)
        p.feed(page_html)
        self.source_url = source_url
        self.title = p.title
        self.byline = p.byline
        self.page_sha256 = hashlib.sha256(page_html.encode("utf-8")).hexdigest()
        self.visible_text = _ws(" ".join(p.visible))
        self.items = []
        for i, s in enumerate(p.sections, 1):
            answer = "\n".join(s["blocks"])
            self.items.append({
                "id": "f%02d" % i,
                "question": s["question"],
                "answer": answer,
                "links": sorted(set(s["links"])),
                "source": source_url,
            })

    @classmethod
    def from_file(cls, path: Path, source_url: str) -> "Facts":
        return cls(Path(path).read_text(encoding="utf-8"), source_url)

    def get(self, fact_id: str) -> Optional[Dict]:
        return next((f for f in self.items if f["id"] == fact_id), None)

    @staticmethod
    def _tokens(text: str) -> set:
        words = re.findall(r"[a-z0-9]+", (text or "").lower())
        return {w for w in words if w not in STOP and len(w) > 1}

    def search(self, question: str, min_score: float = 0.5) -> Optional[Dict]:
        """Best fact for a question, by word overlap with the page's own question line and answer.
        Each caller word counts once: 1.0 if it (or its plain-word synonym) is in the question
        line, 0.5 if only in the answer. No model is involved. Below the threshold we return None
        and say the page doesn't answer it, rather than stretch a fact."""
        q = self._tokens(question)
        if not q:
            return None
        best, best_score = None, 0.0
        for f in self.items:
            head_raw = set(re.findall(r"[a-z0-9]+", f["question"].lower()))
            head = self._tokens(f["question"]) | (head_raw & set(SYN.values()))
            body = self._tokens(f["answer"]) | set(re.findall(r"[a-z0-9]+", f["answer"].lower()))
            hits = 0.0
            for w in q:
                forms = {w, SYN.get(w, w), w.rstrip("s")}
                if forms & head:
                    hits += 1.0
                elif forms & body:
                    hits += 0.5
            score = hits / len(q)
            if score > best_score:
                best, best_score = f, score
        if best is None or best_score < min_score:
            return None
        return dict(best, match_score=round(best_score, 2))

    def is_verbatim(self, text: str) -> bool:
        """True when every line of ``text`` appears on the page word for word."""
        for line in (text or "").splitlines():
            line = line[2:] if line.startswith("- ") else line
            if _ws(line) and _ws(line) not in self.visible_text:
                return False
        return True
