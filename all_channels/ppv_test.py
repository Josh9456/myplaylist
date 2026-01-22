import re
import sys
import os
import json
import base64
import binascii
import urllib.parse
import requests
import random
import time

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
try:
    from playwright.sync_api import sync_playwright
except Exception:
    sync_playwright = None

# API Configuration
API_ENDPOINT = "https://ppv.to/api/streams"
TIMEOUT = 20
USE_PLAYWRIGHT = os.environ.get("USE_PLAYWRIGHT") == "1"
USE_FETCH = os.environ.get("USE_FETCH") == "1"

BASE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

SESSION = requests.Session()
SESSION.headers.update(BASE_HEADERS)

# Configure retry strategy
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS"]
)
adapter = HTTPAdapter(max_retries=retry_strategy)
SESSION.mount("https://", adapter)
SESSION.mount("http://", adapter)


def fetch_streams_data():
    print(f"Fetching API: {API_ENDPOINT}...")
    try:
        resp = SESSION.get(API_ENDPOINT, timeout=TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"API Fetch failed: {e}")
        if os.path.exists("ppv_api.json"):
            print("Falling back to local 'ppv_api.json' file.")
            with open("ppv_api.json", "r", encoding="utf-8") as f:
                return json.load(f)
        else:
            raise e


def extract_m3u8_flexible(text):
    r"""
    Robust extractor that handles:
    1. Plain text URLs
    2. JSON escaped slashes (https:\/\/...)
    3. Base64 encoded strings containing URLs
    """
    if not text:
        return None

    # 1. Clean JSON escaped slashes
    clean_text = text.replace(r"\/", "/")

    # Regex for standard http(s) .m3u8
    # We allow query parameters e.g. .m3u8?token=...
    url_pattern = r'(https?://[^\s"\'<>]+?\.m3u8(?:[\?&][^\s"\'<>]*)?)'

    # Try finding in plain text first
    match = re.search(url_pattern, clean_text)
    if match:
        return match.group(1)

    # 2. Try finding Base64 encoded URLs
    # Look for long strings that might be base64 (single or double quoted)
    base64_candidates = re.findall(r'["\']([a-zA-Z0-9+/=]{20,})["\']', clean_text)

    for candidate in base64_candidates:
        try:
            decoded_bytes = base64.b64decode(candidate)
            
            # Helper to check result
            def check_result(text):
                if ".m3u8" in text:
                    b64_match = re.search(url_pattern, text)
                    if b64_match:
                        return b64_match.group(1)
                return None

            # 1. Try standard UTF-8 decode
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            res = check_result(decoded_str)
            if res: return res

            # 2. Try XOR decryption (Modistreams pattern)
            # Key found: xR9tB2pL6q7MwVe
            key = "xR9tB2pL6q7MwVe"
            xor_result = []
            for i, byte in enumerate(decoded_bytes):
                xor_result.append(chr(byte ^ ord(key[i % len(key)])))
            
            decrypted_xor = "".join(xor_result)
            res = check_result(decrypted_xor)
            if res: 
                print("Found match with XOR decryption!")
                return res
                
        except (binascii.Error, UnicodeDecodeError):
            continue

    return None


def origin_of(url):
    try:
        u = urllib.parse.urlparse(url)
        return f"{u.scheme}://{u.netloc}"
    except Exception:
        return None



def get_modistreams_token(url):
    """
    Attempts to fetch the token from modistreams.org/fetch endpoint.
    This endpoint was observed to modify the session or return the token.
    """
    try:
        # The endpoint seems to be relative to the domain
        domain = urllib.parse.urlparse(url).netloc
        fetch_url = f"https://{domain}/fetch"
        
        headers = {
            "User-Agent": SESSION.headers["User-Agent"],
            "Referer": url,
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        }
        
        # Try finding the 'r' parameter from the page or url
        # Just sending empty body or simple payload might trigger it
        # Based on analysis, might need to POST
        print(f"Attempting to fetch token from {fetch_url}...")
        
        # payload guess - observed ?r=... in some ad requests, maybe it's passed here?
        # But commonly just Referer is enough or specific predictable body.
        # We try empty first
        resp = SESSION.post(fetch_url, headers=headers, data={"r": url}, timeout=5)
        
        if resp.status_code == 200:
            try:
                data = resp.json()
                if "data" in data and isinstance(data["data"], str):
                     return data["data"] 
                return json.dumps(data)
            except:
                return resp.text
        elif resp.status_code in [400, 500]:
             # Retry with referrer payload
             resp = SESSION.post(fetch_url, headers=headers, data={"referrer": url}, timeout=5)
             if resp.status_code == 200:
                 return resp.text
                 
    except Exception as e:
        print(f"Error fetching modistreams token: {e}")
    return None

def fetch_html(url, referer=None):

    headers = {}
    if referer:
        headers["Referer"] = referer
        # Important: Some embeds check Sec-Fetch headers
        headers["Sec-Fetch-Dest"] = "iframe"
        headers["Sec-Fetch-Mode"] = "navigate"
        headers["Sec-Fetch-Site"] = "cross-site"

    try:
        # Add a randomized delay to be polite and avoid rate limits
        delay = random.uniform(0.1, 0.3)
        time.sleep(delay) 
        
        print(f"Fetching {url} (wait: {delay:.2f}s)...")
        resp = SESSION.get(url, headers=headers, timeout=TIMEOUT)
        print(f"Status: {resp.status_code}, Length: {len(resp.text)}")
        
        if resp.status_code == 200:
            return resp.text
        elif resp.status_code == 429:
            print(f"Rate limited (429) on {url}, waiting 30s before continuing...")
            time.sleep(30)
            return ""
        elif resp.status_code == 403:
            # Just log and continue to next stream - don't stop the script
            print(f"403 Forbidden on {url}. Skipping this stream...")
            return ""
            
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        # Silently fail on network errors during scraping to keep moving
        pass
    return ""


def resolve_m3u8_with_playwright(embed_url):
    if not sync_playwright:
        print("Playwright not available; skipping browser-based resolution.")
        return None

    m3u8_url = None
    with sync_playwright() as p:
        args = [
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-blink-features=AutomationControlled",
            "--disable-infobars",
            "--window-size=1280,720",
            "--mute-audio",
        ]
        browser = p.chromium.launch(headless=True, args=args)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1280, "height": 720},
            device_scale_factor=1,
            locale="en-US",
            timezone_id="America/New_York",
        )
        page = context.new_page()

        def handle_request(req):
            nonlocal m3u8_url
            if ".m3u8" in req.url.lower():
                m3u8_url = req.url

        page.on("request", handle_request)

        try:
            print(f"Playwright resolving: {embed_url}")
            page.goto(embed_url, timeout=45000, wait_until="domcontentloaded")

            # Try to trigger playback so the player requests the stream URL.
            try:
                play_btn = page.locator(
                    ".jw-display-icon-container, .jw-icon-playback, #player, button[class*='play'], [aria-label='Play']"
                ).first
                play_btn.wait_for(state="visible", timeout=10000)
                play_btn.click(force=True, delay=250)
            except Exception:
                pass

            for _ in range(12):
                if m3u8_url:
                    break
                time.sleep(1)

            if not m3u8_url:
                try:
                    m3u8_url = page.evaluate(
                        "() => (window.jwplayer && jwplayer().getPlaylist ? jwplayer().getPlaylist()[0].file : null)"
                    )
                except Exception:
                    pass
        finally:
            browser.close()

    return m3u8_url


def get_m3u8_for_stream(stream):
    # Try scraping from embed pages to get the correct stream URL
    iframe_url = stream.get("iframe")
    targets = []

    if iframe_url:
        targets.append(iframe_url)

    # Additional fallback based on uri_name
    uri_name = stream.get("uri_name")
    if uri_name:
        targets.append(f"https://modistreams.org/embed/{uri_name}")
        targets.append(f"https://ppv.to/live/{uri_name}")

    # Deduplicate
    targets = list(dict.fromkeys(targets))

    for url in targets:
        # We assume the referer is the main site
        html = fetch_html(url, referer="https://ppv.to/")
        
        # 1. Try standard extraction
        m3u8 = extract_m3u8_flexible(html)
        if m3u8:
            print(f"FOUND (Direct): {m3u8}")
            return m3u8, url
            
        # 2. If modistreams, try a browser-based resolve (best chance)
        if "modistreams.org" in url:
            if USE_PLAYWRIGHT:
                m3u8 = resolve_m3u8_with_playwright(url)
                if m3u8:
                    print(f"FOUND (Playwright): {m3u8}")
                    return m3u8, url
            # 3. Optional: /fetch API trick (off by default)
            if USE_FETCH:
                token_data = get_modistreams_token(url)
                if token_data:
                    # Check if the token data itself IS the m3u8 or contains it
                    m3u8 = extract_m3u8_flexible(token_data)
                    if m3u8:
                        print(f"FOUND (via /fetch): {m3u8}")
                        return m3u8, url
                    # If it's a token string, we might need to construct the URL manually
                    # But we don't know the construction logic fully yet (poocloud...)
                    # So we hope extract_m3u8_flexible finds it in the response
                    if len(token_data) > 20 and " " not in token_data:
                        path = urllib.parse.urlparse(url).path
                        channel = path.split('/')[-1].replace('247-', '').replace('-', '') 
                        guessed_url = f"https://strm.poocloud.in/secure/{token_data.strip()}/{channel}/index.m3u8"
                        print(f"Constructed Guess: {guessed_url}")
                        return guessed_url, url

    # Could not find m3u8 URL
    return None, None


def generate_m3u_playlist(streams_data):
    out = ["#EXTM3U"]

    # Handle case where API returns empty or malformed data
    categories = streams_data.get("streams", [])
    if not categories:
        print("Warning: No 'streams' key found in API response.")
        return ""

    total_found = 0

    for category in categories:
        group = category.get("category", "Unknown")
        matches = category.get("streams", [])
        print(f"Processing Category: {group} ({len(matches)} streams)")

        for s in matches:
            name = s.get("name") or "Untitled"
            poster = s.get("poster") or ""

            m3u8_url, ref_page = get_m3u8_for_stream(s)

            if not m3u8_url:
                # Skip if we couldn't find a link
                continue

            total_found += 1
            ref_used = ref_page or "https://ppv.to/"

            out.append(f'#EXTINF:-1 tvg-logo="{poster}" group-title="{group.upper()}",{name}')
            out.append(f"#EXTVLCOPT:http-origin={origin_of(ref_used)}")
            out.append(f"#EXTVLCOPT:http-referrer={ref_used}")
            out.append(f"#EXTVLCOPT:http-user-agent={BASE_HEADERS['User-Agent']}")
            out.append(m3u8_url)

    print(f"\nTotal streams extracted: {total_found}")
    return "\n".join(out) + "\n"


def main():
    try:
        data = fetch_streams_data()
        playlist = generate_m3u_playlist(data)
        if playlist:
            with open("ppv.m3u8", "w", encoding="utf-8") as f:
                f.write(playlist)
            print("Success: M3U playlist generated: ppv.m3u8")
        else:
            print("Failed: No streams were extracted.")
    except Exception as e:
        print(f"Critical Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
