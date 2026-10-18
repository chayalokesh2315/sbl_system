"""Pure-Python text similarity (TF-IDF + cosine) used for:
  * duplicate-bug warnings on the report form
  * "similar past bugs and solutions" on the bug page
No extra libraries needed."""
import math
import re
from collections import Counter

STOP = {
    "the", "and", "for", "are", "but", "not", "you", "all", "any", "can", "had", "her", "was",
    "one", "our", "out", "has", "have", "its", "this", "that", "with", "from", "when", "then",
    "than", "into", "onto", "over", "under", "after", "before", "while", "will", "would",
    "should", "could", "does", "did", "doing", "done", "been", "being", "were", "which",
    "who", "whom", "what", "where", "why", "how", "also", "just", "very", "too", "etc",
    "bug", "issue", "problem", "error", "please", "user", "page", "click", "clicking",
}


def _stem(w):
    """Tiny suffix stripper so 'crashes' / 'crashing' / 'crashed' all match 'crash'."""
    if w.endswith("es") and w[:-2].endswith(("s", "x", "z", "ch", "sh")) and len(w) > 4:
        return w[:-2]
    for suf in ("ing", "ed", "s"):
        if w.endswith(suf) and not w.endswith("ss") and len(w) - len(suf) >= 3:
            return w[: -len(suf)]
    return w


def tokens(text):
    words = re.findall(r"[a-z0-9]+", (text or "").lower())
    return [_stem(w) for w in words if len(w) >= 2 and w not in STOP]


def _vectorize(docs):
    toks = [tokens(d) for d in docs]
    n = len(docs)
    df = Counter()
    for t in toks:
        df.update(set(t))
    idf = {w: math.log((1 + n) / (1 + c)) + 1 for w, c in df.items()}
    vecs = []
    for t in toks:
        tf = Counter(t)
        v = {w: (1 + math.log(c)) * idf[w] for w, c in tf.items()}
        norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
        vecs.append({w: x / norm for w, x in v.items()})
    return vecs


def _cosine(a, b):
    if len(a) > len(b):
        a, b = b, a
    return sum(x * b.get(w, 0.0) for w, x in a.items())


def rank(query, docs):
    """Return a list of similarity scores (0..1), one per doc in `docs`."""
    if not docs or not tokens(query):
        return [0.0] * len(docs)
    vecs = _vectorize([query] + list(docs))
    q = vecs[0]
    return [_cosine(q, v) for v in vecs[1:]]


def bug_text(title, description="", steps=""):
    # The title is the strongest signal, so it is counted twice.
    return f"{title or ''} {title or ''} {description or ''} {steps or ''}"


def find_similar_bugs(db, title, description="", project_id=None, exclude_id=None,
                      limit=5, min_score=0.25, with_rca=False, scope=None):
    """`scope` = (sql, params) from access.bug_scope(user, "b"): only bugs the viewer may see are
    compared and returned, so nothing from other people's bugs can leak through suggestions."""
    sql = """SELECT b.id, b.title, b.description, b.reproduction_steps, b.status,
                    b.severity, b.project_id, p.name AS project_name
             FROM bugs b JOIN projects p ON p.id = b.project_id WHERE 1=1"""
    params = []
    if project_id:
        sql += " AND b.project_id = ?"
        params.append(project_id)
    if exclude_id:
        sql += " AND b.id != ?"
        params.append(exclude_id)
    if scope:
        sql += f" AND {scope[0]}"
        params.extend(scope[1])
    rows = db.execute(sql, params).fetchall()
    if not rows:
        return []
    docs = [bug_text(r["title"], r["description"], r["reproduction_steps"]) for r in rows]
    full_scores = rank(bug_text(title, description), docs)
    # Same (or nearly the same) title with a short description scores low on the full text,
    # so also compare titles alone and take the better of the two.
    title_scores = rank(title, [r["title"] for r in rows])
    scores = [max(f, 0.9 * t) for f, t in zip(full_scores, title_scores)]
    ranked = sorted(zip(scores, rows), key=lambda x: x[0], reverse=True)
    out = []
    for score, r in ranked:
        if score < min_score or len(out) >= limit:
            break
        item = dict(id=r["id"], title=r["title"], status=r["status"], severity=r["severity"],
                    project_name=r["project_name"], score=round(score, 3),
                    percent=int(round(score * 100)), rca=None)
        if with_rca:
            rca = db.execute(
                """SELECT category, root_cause, preventive_action, technical_recommendation
                   FROM root_cause_analysis WHERE bug_id = ? ORDER BY created_at DESC LIMIT 1""",
                (r["id"],),
            ).fetchone()
            if rca:
                item["rca"] = dict(rca)
        out.append(item)
    return out


def find_similar_kb(db, title, description="", limit=3, min_score=0.2):
    rows = db.execute(
        "SELECT id, title, problem_summary, solution, tags FROM knowledge_base"
    ).fetchall()
    if not rows:
        return []
    docs = [f"{r['title']} {r['title']} {r['problem_summary'] or ''} {r['solution'] or ''} {r['tags'] or ''}"
            for r in rows]
    scores = rank(bug_text(title, description), docs)
    ranked = sorted(zip(scores, rows), key=lambda x: x[0], reverse=True)
    out = []
    for score, r in ranked:
        if score < min_score or len(out) >= limit:
            break
        out.append(dict(id=r["id"], title=r["title"], solution=r["solution"],
                        percent=int(round(score * 100))))
    return out
