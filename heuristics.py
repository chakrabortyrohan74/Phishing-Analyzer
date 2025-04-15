from bs4 import BeautifulSoup
import Levenshtein
from urllib.parse import urlparse
import tldextract

SAFE_DOMAINS = [
    'amazon.com', 'microsoft.com', 'google.com', 'apple.com',
    'facebook.com', 'linkedin.com', 'instagram.com', 'paypal.com',
    'bankofamerica.com', 'wellsfargo.com', 'chase.com', 'citibank.com',
    'netflix.com', 'spotify.com', 'zoom.us', 'dropbox.com',
    'icloud.com', 'outlook.com', 'live.com', 'hotmail.com',
    'twitter.com', 'github.com', 'slack.com', 'tiktok.com'
]

def find_link_mismatches(html_body):
    soup = BeautifulSoup(html_body, 'html.parser')
    mismatches = []

    for link in soup.find_all('a', href=True):
        display_text = link.get_text().strip()
        actual_url = link['href'].strip()

        if display_text and display_text != actual_url and display_text not in actual_url:
            mismatches.append({
                'display_text': display_text,
                'actual_url': actual_url
            })

    return mismatches

def check_spoofed_headers(headers):
    from_header = headers.get('From', '')
    reply_to = headers.get('Reply-To', '')
    return_path = headers.get('Return-Path', '')

    spoof_flags = []

    if reply_to and reply_to not in from_header:
        spoof_flags.append(f"Reply-To ({reply_to}) doesn't match From ({from_header})")

    if return_path and return_path not in from_header:
        spoof_flags.append(f"Return-Path ({return_path}) doesn't match From ({from_header})")

    return spoof_flags

def extract_base_domain(url):
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

def extract_domains_from_urls(urls):
    domains = set()
    for url in urls:
        try:
            base = extract_base_domain(url)
            if base:
                domains.add(base)
        except:
            pass
    return list(domains)

def extract_domains_from_headers(headers):
    domains = set()
    full_domains = set()  # Store full domains for lookalike detection
    for key in ['From', 'Reply-To', 'Return-Path']:
        value = headers.get(key, '')
        if '<' in value and '>' in value:
            # Extract email address from "Name <email@domain>"
            addr = value.split('<')[1].split('>')[0]
        else:
            addr = value
        if '@' in addr:
            full_domain = addr.split('@')[1].strip()
            # Add the full domain for lookalike detection
            full_domains.add(full_domain)
            # Also add the base domain for other checks
            base = extract_base_domain(full_domain)
            if base:
                domains.add(base)
    # Combine both sets for comprehensive detection
    return list(domains.union(full_domains))

def detect_lookalike_domains(domains):
    suspicious = []
    for domain in domains:
        # Skip very short domains to avoid false positives
        if len(domain) < 4:
            continue

        # Check for lookalikes in the full domain
        for safe in SAFE_DOMAINS:
            # Standard Levenshtein distance check
            distance = Levenshtein.distance(domain.lower(), safe.lower())
            if distance < 4 and domain.lower() != safe.lower():
                suspicious.append({
                    'suspicious_domain': domain,
                    'similar_to': safe,
                    'distance': distance
                })
                continue

            # Check if the safe domain is contained within the domain with modifications
            # This catches domains like 'amaz0n-payments.net'
            safe_name = safe.split('.')[0].lower()  # e.g., 'amazon' from 'amazon.com'
            domain_parts = domain.lower().replace('-', '.').split('.')

            for part in domain_parts:
                # Check for character substitution (e.g., 'amaz0n' vs 'amazon')
                if part != safe_name and len(part) > 3 and Levenshtein.distance(part, safe_name) < 3:
                    suspicious.append({
                        'suspicious_domain': domain,
                        'similar_to': safe,
                        'distance': Levenshtein.distance(part, safe_name),
                        'detection_method': 'partial_match'
                    })
                    break
    return suspicious

def analyze_email_for_phishing(parsed_email):
    results = {}

    # Heuristic 1: Link mismatches
    results['link_mismatches'] = find_link_mismatches(parsed_email.get('Body', ''))

    # Heuristic 2: Spoofed headers
    results['header_flags'] = check_spoofed_headers(parsed_email.get('Headers', {}))

    # Heuristic 3: Suspicious domains (from URLs and headers)
    urls = parsed_email.get('URLs', [])
    url_domains = extract_domains_from_urls(urls)
    header_domains = extract_domains_from_headers(parsed_email.get('Headers', {}))
    all_domains = set(url_domains + header_domains)
    results['suspicious_domains'] = detect_lookalike_domains(all_domains)

    # Risk Score
    score = 0
    if results['header_flags']:
        score += 40
    if results['link_mismatches']:
        score += 30
    if results['suspicious_domains']:
        score += 30

    results['risk_score'] = min(score, 100)

    return results
