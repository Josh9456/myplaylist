import requests
from bs4 import BeautifulSoup
import re

# Base URL and headers
BASE_URL = "https://streambtw.com/"
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Referer': 'https://streambtw.com'
}

def fetch_homepage():
    """Fetch the homepage HTML content."""
    response = requests.get(BASE_URL, headers=HEADERS)
    response.raise_for_status()
    return response.text

def parse_events(html_content):
    """Parse events from the homepage HTML."""
    soup = BeautifulSoup(html_content, 'html.parser')
    events = []

    # Find all card elements
    cards = soup.find_all('div', class_='card')

    for card in cards:
        try:
            # Extract category/league name
            category = card.find('h5', class_='card-title')
            if category:
                category = category.text.strip()
            else:
                category = "Unknown"

            # Extract event name
            event_name = card.find('p', class_='card-text')
            if event_name:
                event_name = event_name.text.strip()
            else:
                event_name = "Unknown Event"

            # Extract iframe URL
            link = card.find('a', class_='btn btn-primary')
            if link and 'href' in link.attrs:
                iframe_url = link['href']
                # Make sure it's a full URL
                if not iframe_url.startswith('http'):
                    iframe_url = f"https://streambtw.com{iframe_url}"
            else:
                iframe_url = None

            # Extract logo (optional)
            logo = card.find('img', class_='league-logo')
            logo_url = logo['src'] if logo and 'src' in logo.attrs else ""

            if iframe_url:
                events.append({
                    'category': category,
                    'name': event_name,
                    'iframe_url': iframe_url,
                    'logo': logo_url
                })
        except Exception as e:
            print(f"Error parsing card: {e}")
            continue

    return events

def extract_m3u8_from_iframe(iframe_url):
    """Extract the m3u8 URL from the iframe page."""
    try:
        response = requests.get(iframe_url, headers=HEADERS, timeout=10)
        if response.status_code == 200:
            html_content = response.text

            # Search for m3u8 URL in the page source
            m3u8_match = re.search(r'https?://[^\s"\']+\.m3u8[^\s"\'>]*', html_content)
            if m3u8_match:
                return m3u8_match.group(0)

            # Alternative pattern for playlist URLs
            m3u8_match = re.search(r'["\']([^"\'\s]+\.m3u8[^"\'\s]*)["\']', html_content)
            if m3u8_match:
                url = m3u8_match.group(1)
                if not url.startswith('http'):
                    # Try to construct full URL if relative
                    return url
                return url

    except Exception as e:
        print(f"Error fetching iframe {iframe_url}: {e}")

    return None

def generate_m3u_playlist(events):
    """Generate M3U playlist content from parsed events."""
    m3u_content = "#EXTM3U\n"

    # Group events by category
    categories = {}
    for event in events:
        category = event['category']
        if category not in categories:
            categories[category] = []
        categories[category].append(event)

    # Process each category
    for category, category_events in categories.items():
        print(f"\nProcessing category: {category}")
        for event in category_events:
            print(f"  - {event['name']}")
            m3u8_url = extract_m3u8_from_iframe(event['iframe_url'])

            if m3u8_url:
                print(f"    Found m3u8: {m3u8_url[:80]}...")
                m3u_content += f'#EXTINF:-1 tvg-logo="{event["logo"]}" group-title="{category.upper()}",{event["name"]}\n'
                m3u_content += '#EXTVLCOPT:http-origin=https://streambtw.com\n'
                m3u_content += '#EXTVLCOPT:http-referrer=https://streambtw.com/\n'
                m3u_content += '#EXTVLCOPT:http-user-agent=Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.166 Safari/537.36\n'
                m3u_content += f'{m3u8_url}\n'
            else:
                print(f"    No m3u8 found")

    return m3u_content

# Main execution
if __name__ == "__main__":
    try:
        print("Fetching homepage...")
        html = fetch_homepage()

        print("Parsing events...")
        events = parse_events(html)
        print(f"Found {len(events)} events")

        print("\nExtracting m3u8 URLs...")
        playlist = generate_m3u_playlist(events)

        with open("streambtw.m3u8", "w", encoding="utf-8") as f:
            f.write(playlist)

        print("\nM3U playlist generated: streambtw.m3u8")

    except Exception as e:
        print(f"Error: {e}")
