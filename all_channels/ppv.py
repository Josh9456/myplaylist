import re
import sys
import json
import base64
import binascii
import urllib.parse
import requests

# API Configuration
API_ENDPOINT = "https://ppv.to/api/streams"
TIMEOUT = 20

# Updated Headers to look like a real browser
BASE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

SESSION = requests.Session()
SESSION.headers.update(BASE_HEADERS)

def fetch_streams_data():
    print(f"Fetching API: {API_ENDPOINT}...")
    resp = SESSION.get(API_ENDPOINT, timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.json()

def extract_m3u8_flexible(text):
    # ADD THE letter 'r' BEFORE THE TRIPLE QUOTES BELOW
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
    # Look for long strings that might be base64
    base64_candidates = re.findall(r'"([a-zA-Z0-9+/=]{20,})"', clean_text)

    for candidate in base64_candidates:
        try:
            decoded_bytes = base64.b64decode(candidate)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            # Check if the decoded string contains an m3u8 link
            if ".m3u8" in decoded_str:
                b64_match = re.search(url_pattern, decoded_str)
                if b64_match:
                    return b64_match.group(1)
        except (binascii.Error, UnicodeDecodeError):
            continue

    return None

def origin_of(url):
    try:
        u = urllib.parse.urlparse(url)
        return f"{u.scheme}://{u.netloc}"
    except Exception:
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
        resp = SESSION.get(url, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            return resp.text
    except Exception as e:
        # Silently fail on network errors during scraping to keep moving
        pass
    return ""

def get_m3u8_for_stream(stream):
    # 1) Get the iframe URL from JSON
    iframe_url = stream.get("iframe")

    # List of URLs to try scraping
    targets = []

    if iframe_url:
        targets.append(iframe_url)

    # 2) Fallbacks based on uri_name
    uri_name = stream.get("uri_name")
    if uri_name:
        targets.append(f"https://ppv.to/live/{uri_name}")
        targets.append(f"https://watchlive.top/embed/{uri_name}")

    # Deduplicate
    targets = list(dict.fromkeys(targets))

    for url in targets:
        # We assume the referer is the main site
        html = fetch_html(url, referer="https://ppv.to/")
        m3u8 = extract_m3u8_flexible(html)
        if m3u8:
            # Success
            return m3u8, url

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
