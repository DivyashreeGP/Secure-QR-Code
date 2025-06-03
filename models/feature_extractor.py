import re
import socket
import requests
import tldextract
import whois
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime
import numpy as np
import pandas as pd

def is_ip(hostname):
    try:
        socket.inet_aton(hostname)
        return True
    except:
        return False

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        expiration_date = w.expiration_date
        if isinstance(creation_date, list): creation_date = creation_date[0]
        if isinstance(expiration_date, list): expiration_date = expiration_date[0]
        domain_age = (datetime.now() - creation_date).days if creation_date else -1
        reg_length = (expiration_date - creation_date).days if creation_date and expiration_date else -1
        return 1, domain_age, reg_length
    except:
        return 0, -1, -1

def extract_features_from_url(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    ext = tldextract.extract(url)
    subdomain = ext.subdomain
    domain = ext.domain
    suffix = ext.suffix
    full_domain = f"{domain}.{suffix}"

    # Basic stats
    length_url = len(url)
    length_hostname = len(hostname)
    ip = int(is_ip(hostname))
    port = 1 if parsed.port else 0

    # Count characters
    counts = {char: url.count(char) for char in ['.', '-', '@', '?', '&', '|', '=', '_', '~', '%', '/', '*', ':', ',', ';', '$', ' ']}
    nb_www = int("www" in hostname)
    nb_com = url.count(".com")
    nb_dslash = url.count("//")
    https_token = int("https" in url and not url.startswith("https"))
    http_in_path = int("http" in path)

    # Ratios
    ratio_digits_url = sum(c.isdigit() for c in url) / len(url)
    ratio_digits_host = sum(c.isdigit() for c in hostname) / len(hostname) if hostname else 0

    # DNS and WHOIS
    dns_record, domain_age, domain_registration_length = get_whois_info(full_domain)

    # Abnormalities
    punycode = int("xn--" in hostname)
    tld_in_path = int(suffix in path)
    tld_in_subdomain = int(suffix in subdomain)
    abnormal_subdomain = int(len(subdomain) > 1 and '-' in subdomain)
    nb_subdomains = subdomain.count('.') + 1 if subdomain else 0
    prefix_suffix = int('-' in domain)
    random_domain = int(bool(re.search(r'[0-9]{4,}', domain)))
    shortening_services = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly']
    shortening_service = int(any(svc in url for svc in shortening_services))

    # Path info
    path_ext_match = re.search(r"\.([a-zA-Z0-9]+)$", path)
    path_extension = path_ext_match.group(1) if path_ext_match else ""
    path_words = re.split(r"[^\w]", path)
    raw_words = re.split(r"[^\w]", url)

    length_words_raw = len(raw_words)
    shortest_words_raw = min(map(len, raw_words)) if raw_words else 0
    shortest_word_host = min(map(len, hostname.split('.'))) if hostname else 0
    shortest_word_path = min(map(len, path_words)) if path_words else 0
    longest_words_raw = max(map(len, raw_words)) if raw_words else 0
    longest_word_host = max(map(len, hostname.split('.'))) if hostname else 0
    longest_word_path = max(map(len, path_words)) if path_words else 0
    avg_words_raw = np.mean([len(w) for w in raw_words]) if raw_words else 0
    avg_word_host = np.mean([len(w) for w in hostname.split('.')]) if hostname else 0
    avg_word_path = np.mean([len(w) for w in path_words]) if path_words else 0

    # Heuristic
    phish_keywords = ['login', 'verify', 'secure', 'account', 'banking']
    phish_hints = int(any(keyword in url.lower() for keyword in phish_keywords))
    char_repeat = int(bool(re.search(r'(.)\1{3,}', url)))

    # Brand-related (optional static example brand list)
    brands = ['google', 'facebook', 'apple', 'paypal', 'amazon']
    domain_in_brand = int(any(brand in domain.lower() for brand in brands))
    brand_in_subdomain = int(any(brand in subdomain.lower() for brand in brands))
    brand_in_path = int(any(brand in path.lower() for brand in brands))

    # Suspicious TLDs
    suspecious_tld = int(suffix in ['tk', 'ml', 'ga', 'cf', 'gq'])

    # Page analysis
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.content, "html.parser")
        hyperlinks = soup.find_all('a')
        nb_hyperlinks = len(hyperlinks)
        int_links = [a for a in hyperlinks if domain in (a.get("href") or "")]
        ext_links = [a for a in hyperlinks if domain not in (a.get("href") or "")]
        null_links = [a for a in hyperlinks if not a.get("href")]

        ratio_intHyperlinks = len(int_links) / nb_hyperlinks if nb_hyperlinks else 0
        ratio_extHyperlinks = len(ext_links) / nb_hyperlinks if nb_hyperlinks else 0
        ratio_nullHyperlinks = len(null_links) / nb_hyperlinks if nb_hyperlinks else 0

        nb_extCSS = len(soup.find_all('link', rel="stylesheet"))

        ratio_intRedirection = 0  # not tracked
        ratio_extRedirection = 0
        ratio_intErrors = 0
        ratio_extErrors = 0

        login_form = int(bool(soup.find('input', {'type': 'password'})))
        external_favicon = int("favicon" in (soup.find("link", rel="icon") or {}).get("href", "") and domain not in url)
        links_in_tags = int(bool(soup.find_all(['script', 'link'])))
        submit_email = int(bool(re.search(r'mailto:', str(soup))))
        ratio_intMedia = 0
        ratio_extMedia = 0
        sfh = int(bool(soup.find('form', {'action': '#'})))
        iframe = int(bool(soup.find('iframe')))
        popup_window = 0
        safe_anchor = int(all(a.get("href") not in ["#", ""] for a in hyperlinks))
        onmouseover = int('onmouseover' in res.text)
        right_clic = int('contextmenu' in res.text)
        empty_title = int(not bool(soup.title and soup.title.string.strip()))
        domain_in_title = int(domain in (soup.title.string.lower() if soup.title and soup.title.string else ""))
        domain_with_copyright = int('©' in res.text or 'copyright' in res.text.lower())

    except:
        nb_hyperlinks = ratio_intHyperlinks = ratio_extHyperlinks = ratio_nullHyperlinks = nb_extCSS = 0
        ratio_intRedirection = ratio_extRedirection = ratio_intErrors = ratio_extErrors = 0
        login_form = external_favicon = links_in_tags = submit_email = 0
        ratio_intMedia = ratio_extMedia = sfh = iframe = popup_window = safe_anchor = 0
        onmouseover = right_clic = empty_title = domain_in_title = domain_with_copyright = 0

    # Final label
    status = "unknown"

    features_dict= {
        "url": url,
        "length_url": length_url,
        "length_hostname": length_hostname,
        "ip": ip,
        "nb_dots": counts['.'],
        "nb_hyphens": counts['-'],
        "nb_at": counts['@'],
        "nb_qm": counts['?'],
        "nb_and": counts['&'],
        "nb_or": counts['|'],
        "nb_eq": counts['='],
        "nb_underscore": counts['_'],
        "nb_tilde": counts['~'],
        "nb_percent": counts['%'],
        "nb_slash": counts['/'],
        "nb_star": counts['*'],
        "nb_colon": counts[':'],
        "nb_comma": counts[','],
        "nb_semicolumn": counts[';'],
        "nb_dollar": counts['$'],
        "nb_space": counts[' '],
        "nb_www": nb_www,
        "nb_com": nb_com,
        "nb_dslash": nb_dslash,
        "http_in_path": http_in_path,
        "https_token": https_token,
        "ratio_digits_url": ratio_digits_url,
        "ratio_digits_host": ratio_digits_host,
        "punycode": punycode,
        "port": port,
        "tld_in_path": tld_in_path,
        "tld_in_subdomain": tld_in_subdomain,
        "abnormal_subdomain": abnormal_subdomain,
        "nb_subdomains": nb_subdomains,
        "prefix_suffix": prefix_suffix,
        "random_domain": random_domain,
        "shortening_service": shortening_service,
        "path_extension": path_extension,
        "nb_redirection": 0,  # hard to measure without redirect tracking
        "nb_external_redirection": 0,
        "length_words_raw": length_words_raw,
        "char_repeat": char_repeat,
        "shortest_words_raw": shortest_words_raw,
        "shortest_word_host": shortest_word_host,
        "shortest_word_path": shortest_word_path,
        "longest_words_raw": longest_words_raw,
        "longest_word_host": longest_word_host,
        "longest_word_path": longest_word_path,
        "avg_words_raw": avg_words_raw,
        "avg_word_host": avg_word_host,
        "avg_word_path": avg_word_path,
        "phish_hints": phish_hints,
        "domain_in_brand": domain_in_brand,
        "brand_in_subdomain": brand_in_subdomain,
        "brand_in_path": brand_in_path,
        "suspecious_tld": suspecious_tld,
        "statistical_report": 0,
        "nb_hyperlinks": nb_hyperlinks,
        "ratio_intHyperlinks": ratio_intHyperlinks,
        "ratio_extHyperlinks": ratio_extHyperlinks,
        "ratio_nullHyperlinks": ratio_nullHyperlinks,
        "nb_extCSS": nb_extCSS,
        "ratio_intRedirection": ratio_intRedirection,
        "ratio_extRedirection": ratio_extRedirection,
        "ratio_intErrors": ratio_intErrors,
        "ratio_extErrors": ratio_extErrors,
        "login_form": login_form,
        "external_favicon": external_favicon,
        "links_in_tags": links_in_tags,
        "submit_email": submit_email,
        "ratio_intMedia": ratio_intMedia,
        "ratio_extMedia": ratio_extMedia,
        "sfh": sfh,
        "iframe": iframe,
        "popup_window": popup_window,
        "safe_anchor": safe_anchor,
        "onmouseover": onmouseover,
        "right_clic": right_clic,
        "empty_title": empty_title,
        "domain_in_title": domain_in_title,
        "domain_with_copyright": domain_with_copyright,
        "whois_registered_domain": dns_record,
        "domain_registration_length": domain_registration_length,
        "domain_age": domain_age,
        "web_traffic": 0,  # deprecated
        "dns_record": dns_record,
        "google_index": 0,  # not accessed
        "page_rank": 0,
        "status": status
    }
    return pd.DataFrame([features_dict])