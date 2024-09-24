import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import requests
from googlesearch import search
import whois
from datetime import date
from urllib.parse import urlparse

class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.domain = ""
        self.whois_response = None
        self.parsed_url = None
        self.response = None
        self.soup = None
        self.features = []

        # Initialize URL response and domain parsing
        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except requests.RequestException:
            pass

        try:
            self.parsed_url = urlparse(url)
            self.domain = self.parsed_url.netloc
        except Exception:
            pass

        try:
            if self.domain:
                self.whois_response = whois.whois(self.domain)
        except Exception:
            pass

        # Add features
        self.features.append(self.using_ip())
        self.features.append(self.long_url())
        self.features.append(self.short_url())
        self.features.append(self.has_symbol_at())
        self.features.append(self.is_redirecting())
        self.features.append(self.prefix_suffix())
        self.features.append(self.count_subdomains())
        self.features.append(self.is_https())
        self.features.append(self.domain_registration_length())
        self.features.append(self.has_favicon())
        self.features.append(self.is_non_standard_port())
        self.features.append(self.https_in_domain_url())
        self.features.append(self.request_url_analysis())
        self.features.append(self.anchor_url_analysis())
        self.features.append(self.links_in_script_tags())
        self.features.append(self.server_form_handler())
        self.features.append(self.has_info_email())
        self.features.append(self.abnormal_url())
        self.features.append(self.website_forwarding())
        self.features.append(self.status_bar_customization())
        self.features.append(self.disable_right_click())
        self.features.append(self.using_popup_window())
        self.features.append(self.iframe_redirection())
        self.features.append(self.age_of_domain())
        self.features.append(self.dns_recording())
        self.features.append(self.website_traffic())
        self.features.append(self.page_rank())
        self.features.append(self.google_index())
        self.features.append(self.links_pointing_to_page())
        self.features.append(self.stats_report())

    # Add the getFeaturesList method to return the list of features
    def getFeaturesList(self):
        return self.features

    # 1. Using IP
    def using_ip(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except ValueError:
            return 1

    # 2. Long URL
    def long_url(self):
        if self.url:
            length = len(self.url)
            if length < 54:
                return 1
            elif 54 <= length <= 75:
                return 0
            else:  # This else statement was missing
                return -1

    # 3. Short URL
    def short_url(self):
        if self.url:
            shortening_services = re.search(r'bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co', self.url)
            if shortening_services:
                return -1
            else:
                return 1
        return -1

    # 4. Symbol '@'
    def has_symbol_at(self):
        if self.url and '@' in self.url:
            return -1
        else:
            return 1

    # 5. Redirecting with //
    def is_redirecting(self):
        if self.url and self.url.rfind('//') > 6:
            return -1
        else:
            return 1

    # 6. Prefix-Suffix in Domain
    def prefix_suffix(self):
        if self.domain and '-' in self.domain:
            return -1
        else:
            return 1

    # 7. HTTPS in Domain URL
    def https_in_domain_url(self):
        if self.domain and 'https' in self.domain:
            return -1
        else:
            return 1

    # 8. Subdomains Count
    def count_subdomains(self):
        if self.url:
            dot_count = self.url.count('.')
            if dot_count == 1:
                return 1
            elif dot_count == 2:
                return 0
            else:
                return -1

    # 9. HTTPS Check
    def is_https(self):
        if self.parsed_url and self.parsed_url.scheme == 'https':
            return 1
        else:
            return -1

    # 10. Domain Registration Length
    def domain_registration_length(self):
        try:
            if self.whois_response and self.whois_response.expiration_date and self.whois_response.creation_date:
                expiration_date = self.whois_response.expiration_date[0] if isinstance(self.whois_response.expiration_date, list) else self.whois_response.expiration_date
                creation_date = self.whois_response.creation_date[0] if isinstance(self.whois_response.creation_date, list) else self.whois_response.creation_date
                age_in_months = (expiration_date.year - creation_date.year) * 12 + (expiration_date.month - creation_date.month)
                if age_in_months >= 12:
                    return 1
                else:
                    return -1
        except Exception:
            return -1

    # 11. Favicon
    def has_favicon(self):
        try:
            if self.soup:
                for link in self.soup.find_all('link', href=True):
                    if self.url in link['href'] or len(re.findall(r'\.', link['href'])) == 1:
                        return 1
        except Exception:
            pass
        return -1

    # 12. Non-Standard Port
    def is_non_standard_port(self):
        if self.domain and ':' in self.domain:
            return -1
        else:
            return 1

    # 13. Request URL Analysis
    def request_url_analysis(self):
        try:
            success, total = 0, 0
            if self.soup:
                for element in self.soup.find_all(['img', 'audio', 'embed', 'iframe'], src=True):
                    total += 1
                    if self.url in element['src'] or self.domain in element['src'] or len(re.findall(r'\.', element['src'])) == 1:
                        success += 1
            percentage = (success / total) * 100 if total > 0 else 0
            if percentage < 22:
                return 1
            elif 22 <= percentage < 61:
                return 0
            else:
                return -1
        except Exception:
            return -1
 
    # 14. Anchor URL Analysis
    def anchor_url_analysis(self):
        try:
            total, unsafe = 0, 0
            if self.soup:
                for a in self.soup.find_all('a', href=True):
                    total += 1
                    if not (self.url in a['href'] or self.domain in a['href']):
                        unsafe += 1
            percentage = (unsafe / total) * 100 if total > 0 else 0
            if percentage < 31:
                return 1
            elif 31 <= percentage < 67:
                return 0
            return -1
        except Exception:
            return -1

    # 15. Links in Script Tags
    def links_in_script_tags(self):
        try:
            total, success = 0, 0
            if self.soup:
                for element in self.soup.find_all(['link', 'script'], href=True):
                    total += 1
                    if self.url in element['href'] or self.domain in element['href'] or len(re.findall(r'\.', element['href'])) == 1:
                        success += 1
            percentage = (success / total) * 100 if total > 0 else 0
            if percentage < 17:
                return 1
            elif 17 <= percentage < 81:
                return 0
            return -1
        except Exception:
            return -1

    # 16. Server Form Handler
    def server_form_handler(self):
        try:
            if self.soup:
                forms = self.soup.find_all('form', action=True)
                if not forms:
                    return 1
                for form in forms:
                    if form['action'] in ("", "about:blank"):
                        return -1
                    if self.url not in form['action'] and self.domain not in form['action']:
                        return 0
                return 1
        except Exception:
            return -1

    # 17. Info Email
    def has_info_email(self):
        return -1 if self.soup and re.search(r"mail\(\)|mailto", str(self.soup)) else 1

    # 18. Abnormal URL
    def abnormal_url(self):
        return 1 if self.response and self.response.text == self.whois_response else -1

    # 19. Website Forwarding
    def website_forwarding(self):
        try:
            if self.response:
                history_count = len(self.response.history)
                if history_count <= 1:
                    return 1
                elif history_count <= 4:
                    return 0
            return -1
        except Exception:
            return -1

    # 20. Status Bar Customization
    def status_bar_customization(self):
        return -1 if self.response and re.search("<script>.+onmouseover.+</script>", self.response.text) else 1

    # 21. Disable Right Click
    def disable_right_click(self):
        return -1 if self.response and re.search(r"event.button ?== ?2", self.response.text) else 1

    # 22. Popup Window
    def using_popup_window(self):
        return -1 if self.response and re.search(r"alert\(", self.response.text) else 1

    # 23. Iframe Redirection
    def iframe_redirection(self):
        return -1 if self.response and re.search(r"<iframe>|<frameBorder>", self.response.text) else 1

    # 24. Age of Domain
    def age_of_domain(self):
        try:
            if self.whois_response and self.whois_response.creation_date:
                creation_date = self.whois_response.creation_date[0] if isinstance(self.whois_response.creation_date, list) else self.whois_response.creation_date
                age = (date.today() - creation_date).days // 30
                return 1 if age >= 6 else -1
        except Exception:
            return -1

    # 25. DNS Recording
    def dns_recording(self):
        try:
            if self.domain:
                dns = whois.whois(self.domain)
                return 1 if dns else -1
        except Exception:
            return -1

    # 26. Website Traffic
    def website_traffic(self):
        try:
            rank = BeautifulSoup(urllib.request.urlopen(f"http://data.alexa.com/data?cli=10&dat=s&url={self.url}").read(), "xml").find("REACH")['RANK']
            return 1 if int(rank) < 100000 else 0
        except Exception:
            return -1

    # 27. Page Rank
    def page_rank(self):
        return 1  # Placeholder for actual PageRank calculation

    # 28. Google Index
    def google_index(self):
        try:
            site_search = search(self.url, num_results=10)
            return 1 if site_search else -1
        except Exception:
            return -1

    # 29. Links Pointing to Page
    def links_pointing_to_page(self):
        try:
            if self.soup:
                return 1 if len(self.soup.find_all('a')) > 0 else -1
        except Exception:
            return -1

    # 30. Stats Report
    def stats_report(self):
        return -1 if self.response and "blacklist" in self.response.text else 1
