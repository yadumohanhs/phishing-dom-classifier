import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import tldextract


def extract_features(url: str, html_content: str) -> dict:
    """
    Extracts 12 aligned lexical (URL) and DOM (HTML) features.
    Keys match the exact column names of the PhiUSIIL Phishing Dataset.
    """
    # Normalize URL if scheme (http/https) is missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed_url = urlparse(url)
    ext = tldextract.extract(url)
    soup = BeautifulSoup(html_content, "html.parser")

    # ==========================================
    # PART A: LEXICAL FEATURES (URL String)
    # ==========================================
    url_length = len(url)
    
    # Reconstruct full domain (e.g., 'sub.example.co.uk')
    domain_parts = [part for part in [ext.subdomain, ext.domain, ext.suffix] if part]
    full_domain = ".".join(domain_parts)
    domain_length = len(full_domain)

    # Check if the domain is a raw IPv4 address (e.g., http://192.168.1.1/login)
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    is_domain_ip = 1 if ip_pattern.match(ext.domain) else 0

    # Count subdomains (e.g., 'login.secure.bank.com' -> 2 subdomains)
    no_of_subdomain = len(ext.subdomain.split(".")) if ext.subdomain else 0

    # Character counts and ratios inside the URL
    no_of_letters = sum(c.isalpha() for c in url)
    no_of_digits = sum(c.isdigit() for c in url)
    digit_ratio = round(no_of_digits / url_length, 4) if url_length > 0 else 0.0

    is_https = 1 if parsed_url.scheme == "https" else 0

    # ==========================================
    # PART B: DOM FEATURES (HTML Structure)
    # ==========================================
    has_title = 1 if (soup.title and soup.title.string and soup.title.string.strip()) else 0

    # Look for password inputs (<input type="password">)
    password_inputs = soup.find_all("input", {"type": re.compile(r"^password$", re.I)})
    has_password_field = 1 if len(password_inputs) > 0 else 0

    # Look for submit buttons (<input type="submit"> or <button type="submit">)
    submit_inputs = soup.find_all(["input", "button"], {"type": re.compile(r"^submit$", re.I)})
    has_submit_button = 1 if len(submit_inputs) > 0 else 0

    # Count hidden inputs (<input type="hidden">) often used in session/token spoofing
    hidden_inputs = soup.find_all("input", {"type": re.compile(r"^hidden$", re.I)})
    has_hidden_fields = 1 if len(hidden_inputs) > 0 else 0

    # Count total <iframe> tags
    no_of_iframe = len(soup.find_all("iframe"))

    # Count external hyperlinks (<a href="..."> pointing to a different root domain)
    all_links = soup.find_all("a", href=True)
    no_of_external_ref = 0
    for link in all_links:
        href = link["href"].strip()
        if href.startswith(("http://", "https://")):
            link_ext = tldextract.extract(href)
            # If the registered domain of the link differs from the page's domain, it's external
            if link_ext.domain and link_ext.domain != ext.domain:
                no_of_external_ref += 1

    # Return in the exact order expected by the ML model
    return {
        "URLLength": url_length,
        "DomainLength": domain_length,
        "IsDomainIP": is_domain_ip,
        "NoOfSubDomain": no_of_subdomain,
        "NoOfLettersInURL": no_of_letters,
        "NoOfDegitsInURL": no_of_digits,     # Note: Spelled 'Degits' to match PhiUSIIL dataset typo!
        "DegitRatioInURL": digit_ratio,      # Spelled 'Degit' to match dataset column name
        "IsHTTPS": is_https,
        "HasTitle": has_title,
        "HasSubmitButton": has_submit_button,
        "HasHiddenFields": has_hidden_fields,
        "HasPasswordField": has_password_field,
        "NoOfiFrame": no_of_iframe,
        "NoOfExternalRef": no_of_external_ref,
    }
