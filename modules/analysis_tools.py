# modules/analysis_tools.py
import requests, whois, base64, logging
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup

from config import BLOCK_EXPLORER_API_KEY, VIRUSTOTAL_API_KEY, DEBANK_API_KEY

logger = logging.getLogger(__name__)

def check_honeypot(contract_address):
    try:
        r = requests.get(f"https://api.honeypot.is/v1/IsHoneypot?address={contract_address}")
        r.raise_for_status()
        return r.json().get('honeypotResult', {}).get('isHoneypot', False)
    except Exception as e:
        logger.error(f"Error cek honeypot: {e}")
        return False

def get_contract_verification(contract_address, network='bsc'):
    api_url = f"https://api.bscscan.com/api" if network == 'bsc' else f"https://api.etherscan.io/api"
    params = {"module": "contract", "action": "getsourcecode", "address": contract_address, "apikey": BLOCK_EXPLORER_API_KEY}
    try:
        r = requests.get(api_url, params=params); r.raise_for_status()
        return r.json()['result'][0]['SourceCode'] != ''
    except Exception as e:
        logger.error(f"Error cek verifikasi kontrak: {e}")
        return False

def scrape_token_holders(contract_address, network='bsc'):
    url = f"https://bscscan.com/token/generic-tokenholders2?m=normal&a={contract_address}"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        page = requests.get(url, headers=headers, timeout=10); page.raise_for_status()
        soup = BeautifulSoup(page.content, "lxml")
        percentages = [float(p.text.strip().replace('%', '')) for p in soup.select("td:nth-of-type(3)")[:10] if p.text.strip().endswith('%')]
        return {"top_10_hold_percentage": sum(percentages)}
    except Exception as e:
        logger.error(f"Error scraping holders: {e}")
        return {"top_10_hold_percentage": 0}

def get_domain_age(url):
    try:
        domain = urlparse(url).netloc
        info = whois.whois(domain)
        created = info.creation_date
        if isinstance(created, list): created = created[0]
        return (datetime.now() - created).days if created else -1
    except Exception as e:
        logger.error(f"Error cek umur domain: {e}")
        return -1

def check_virustotal(url: str):
    if not VIRUSTOTAL_API_KEY or 'ANDA_DI_SINI' in VIRUSTOTAL_API_KEY: return {'malicious': 0, 'suspicious': 0}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(api_endpoint, headers=headers)
        if response.status_code == 404: return {'malicious': 0, 'suspicious': 0}
        response.raise_for_status()
        stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        return {'malicious': stats.get('malicious', 0), 'suspicious': stats.get('suspicious', 0)}
    except requests.exceptions.RequestException as e:
        logger.error(f"Error saat menghubungi VirusTotal API: {e}")
        return {'malicious': 0, 'suspicious': 0}

def scrape_page_content(url):
    results = {"seed_phrase_mention": False}
    try:
        page = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10); page.raise_for_status()
        if any(k in page.text.lower() for k in ['seed phrase', 'private key', 'recovery phrase', '12 words', '24 words']):
            results['seed_phrase_mention'] = True
        return results
    except Exception as e:
        logger.error(f"Error scraping halaman: {e}")
        return results
        
def get_debank_info(contract_address: str, chain_id: str = 'bsc'):
    if not DEBANK_API_KEY or 'ANDA_DI_SINI' in DEBANK_API_KEY: return None
    api_endpoint = "https://pro-openapi.debank.com/v1/token"
    headers = {"accept": "application/json", "AccessKey": DEBANK_API_KEY}
    params = {"chain": chain_id, "id": contract_address}
    try:
        response = requests.get(api_endpoint, headers=headers, params=params); response.raise_for_status()
        data = response.json()
        return {"is_core": data.get('is_core', False), "chain_count": len(data.get('chains', [])), "price": data.get('price', 0)}
    except requests.exceptions.RequestException as e:
        logger.error(f"Error saat menghubungi DeBank API: {e}")
        return None
