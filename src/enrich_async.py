# src/enrich_async.py
import asyncio, aiohttp, aiodns, ssl, socket
from datetime import datetime, timezone
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import tldextract
from src.utils_cache import cache_get, cache_set

resolver = aiodns.DNSResolver()

async def fetch_html(session, url, timeout=6):
    try:
        async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
            ctype = resp.headers.get("Content-Type","")
            if "html" in ctype.lower():
                return await resp.text()
            return ""
    except Exception:
        return ""

async def async_dns(domain):
    cached = cache_get("dns", domain)
    if cached is not None:
        return cached
    result = {"has_mx": False, "has_txt": False}
    try:
        await resolver.query(domain, 'MX')
        result["has_mx"] = True
    except Exception:
        pass
    try:
        await resolver.query(domain, 'TXT')
        result["has_txt"] = True
    except Exception:
        pass
    cache_set("dns", domain, result)
    return result

def parse_html_features(html: str, url: str):
    out = {"has_password":0, "external_links":0, "suspicious_forms":0, "hidden_iframes":0, "js_redirect":0}
    if not html:
        return out
    try:
        soup = BeautifulSoup(html, "html.parser")
        if soup.find("input", {"type":"password"}):
            out["has_password"] = 1
        links = [a.get("href") for a in soup.find_all("a", href=True)]
        domain = tldextract.extract(url).registered_domain
        out["external_links"] = sum(1 for l in links if l and domain not in (l or ""))
        for form in soup.find_all("form"):
            act = (form.get("action") or "").lower()
            if any(k in act for k in ("login","verify","secure","paypal","bank")):
                out["suspicious_forms"] = 1
                break
        for iframe in soup.find_all("iframe"):
            style = iframe.get("style","")
            if "display:none" in style or "visibility:hidden" in style:
                out["hidden_iframes"] = 1
        if "window.location" in html or "document.location" in html:
            out["js_redirect"] = 1
    except Exception:
        pass
    return out

def get_ssl_days(domain):
    cached = cache_get("ssl", domain)
    if cached is not None:
        return cached
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            cert = s.getpeercert()
            not_after = cert.get("notAfter")
            try:
                na = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days = (na.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
            except Exception:
                days = None
            cache_set("ssl", domain, days)
            return days
    except Exception:
        cache_set("ssl", domain, None)
        return None

async def enrich_url(url, session):
    parsed = urlparse(url)
    domain = tldextract.extract(url).registered_domain or parsed.netloc
    domain = domain.lower()
    cached = cache_get("enrich", domain)
    if cached is not None:
        # Backfill domain_age_days if missing in older cache entries
        if "domain_age_days" not in cached or "domain_registered_on" not in cached:
            try:
                age, reg = await asyncio.to_thread(_compute_domain_age_days, domain)
            except Exception:
                age, reg = None, None
            cached["domain_age_days"] = cached.get("domain_age_days", age)
            cached["domain_registered_on"] = cached.get("domain_registered_on", reg)
            cache_set("enrich", domain, cached)
        return cached
    dns_info = await async_dns(domain)
    html = await fetch_html(session, url)
    html_feats = parse_html_features(html, url)
    ssl_days = await asyncio.to_thread(get_ssl_days, domain)  # run blocking ssl in thread

    # Domain age via WHOIS (in days) and registered date
    def _compute_domain_age_days(d: str):
        cached_age = cache_get("domain_age", d)
        cached_reg = cache_get("domain_registered_on", d)
        if cached_age is not None and cached_reg is not None:
            return cached_age, cached_reg
        try:
            data = whois.whois(d)
            # Try known fields
            candidates = []
            created = getattr(data, 'creation_date', None)
            if created is not None:
                candidates.append(created)
            created2 = getattr(data, 'created', None)
            if created2 is not None:
                candidates.append(created2)
            registered = getattr(data, 'registered', None)
            if registered is not None:
                candidates.append(registered)

            # Flatten and parse into datetimes
            def _try_parse_dt(v):
                if isinstance(v, datetime):
                    return v
                if isinstance(v, str):
                    for fmt in (
                        "%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%d %H:%M:%S",
                        "%Y-%m-%d",
                        "%d-%b-%Y",
                        "%Y.%m.%d %H:%M:%S",
                        "%Y.%m.%d",
                        "%b %d %Y",
                        "%d/%m/%Y",
                        "%m/%d/%Y",
                    ):
                        try:
                            return datetime.strptime(v, fmt)
                        except Exception:
                            pass
                return None

            parsed = []
            for c in candidates:
                if isinstance(c, list):
                    for it in c:
                        dt = _try_parse_dt(it)
                        if isinstance(dt, datetime):
                            parsed.append(dt)
                else:
                    dt = _try_parse_dt(c)
                    if isinstance(dt, datetime):
                        parsed.append(dt)

            created_dt = min(parsed) if parsed else None
            if isinstance(created_dt, datetime):
                if created_dt.tzinfo is None:
                    created_dt = created_dt.replace(tzinfo=timezone.utc)
                age_days_local = (datetime.now(timezone.utc) - created_dt).days
                registered_iso = created_dt.astimezone(timezone.utc).strftime("%Y-%m-%d")
            else:
                age_days_local = None
                registered_iso = None
        except Exception:
            age_days_local = None
            registered_iso = None
        cache_set("domain_age", d, age_days_local, ttl=24*3600)
        cache_set("domain_registered_on", d, registered_iso, ttl=24*3600)
        return age_days_local, registered_iso

    domain_age_days, domain_registered_on = await asyncio.to_thread(_compute_domain_age_days, domain)

    result = {
        "domain": domain,
        "dns": dns_info,
        "html": html_feats,
        "ssl_days": ssl_days,
        "domain_age_days": domain_age_days,
        "domain_registered_on": domain_registered_on,
    }
    cache_set("enrich", domain, result)
    return result

async def enrich_many(urls, concurrency=40):
    out = {}
    sem = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession(headers={"User-Agent":"Mozilla/5.0"}) as session:
        tasks = []
        for u in urls:
            async def _task(u=u):
                async with sem:
                    return await enrich_url(u, session)
            tasks.append(_task())
        for fut in asyncio.as_completed(tasks):
            res = await fut
            out[res["domain"]] = res
    return out

def run_enrich_sync(urls, concurrency=40):
    return asyncio.run(enrich_many(urls, concurrency=concurrency))

# Convenience: single-URL async entrypoint used by predict.py
async def enrich_url_async(url: str):
    async with aiohttp.ClientSession(headers={"User-Agent":"Mozilla/5.0"}) as session:
        return await enrich_url(url, session)

# Example usage:
# results = run_enrich_sync(["https://example.com","https://phishingsite.test"], concurrency=30)
