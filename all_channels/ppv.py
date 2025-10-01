import requests
import re

# Correct API endpoint
API_ENDPOINT = "https://ppv.to/api/streams"

# Headers to mimic a browser
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
    'Referer': 'https://ppvs.su'
}

def fetch_streams_data():
    """Fetch and parse stream data from the API."""
    response = requests.get(API_ENDPOINT, headers=HEADERS)
    response.raise_for_status()  # Raise error for bad status codes
    return response.json()

def extract_m3u8_from_page(uri_name):
    """Extract the m3u8 URL from the embedded iframe without playing the video."""
    # Primary attempt: Fetch from live page (if m3u8 is there)
    live_url = f"https://ppv.to/live/{uri_name}"
    response = requests.get(live_url, headers=HEADERS)
    if response.status_code == 200:
        html_content = response.text
        m3u8_match = re.search(r'https?://[^\s"\']+\.m3u8', html_content)
        if m3u8_match:
            return m3u8_match.group(0)

    # Fallback: Fetch from iframe URL
    iframe_url = f"https://embednow.top/embed/{uri_name}"
    iframe_response = requests.get(iframe_url, headers=HEADERS)
    if iframe_response.status_code == 200:
        iframe_content = iframe_response.text
        m3u8_match = re.search(r'https?://[^\s"\']+\.m3u8', iframe_content)
        if m3u8_match:
            return m3u8_match.group(0)
    return None

def generate_m3u_playlist(streams_data):
    """Generate M3U playlist content from parsed data."""
    m3u_content = "#EXTM3U\n"
    for category in streams_data.get('streams', []):  # Access 'streams' key from JSON
        category_name = category.get("category", "Unknown")
        for stream in category.get("streams", []):
            uri_name = stream.get("uri_name")
            name = stream.get("name")
            poster = stream.get("poster")
            m3u8_url = extract_m3u8_from_page(uri_name)
            if m3u8_url:
                m3u_content += f'#EXTINF:-1 tvg-logo="{poster}" group-title="{category_name.upper()}",{name}\n'
                m3u_content += '#EXTVLCOPT:http-origin=https://ppv.to\n'
                m3u_content += '#EXTVLCOPT:http-referrer=https://ppv.to/\n'
                m3u_content += '#EXTVLCOPT:http-user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36\n'
                m3u_content += f'{m3u8_url}\n'
    return m3u_content

# Main execution
try:
    data = fetch_streams_data()
    playlist = generate_m3u_playlist(data)
    with open("ppv.m3u8", "w") as f:
        f.write(playlist)
    print("M3U playlist generated: ppv.m3u8")
except Exception as e:
    print(f"Error: {e}")
