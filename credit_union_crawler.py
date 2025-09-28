import requests
from bs4 import BeautifulSoup
import re
import time
import logging
from urllib.parse import urljoin, urlparse
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class CreditUnionFormCrawler:
    def __init__(self, base_url):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.visited = set()
        self.forms = []
        self.session = requests.Session()
        
        # User agents to rotate
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0'
        ]
        
        # Common form keywords and patterns for credit unions
        self.form_keywords = [
            'application', 'disclosure', 'agreement', 'authorization', 'request',
            'enrollment', 'membership', 'deposit', 'withdrawal', 'loan',
            'checking', 'savings', 'card', 'statement', 'credit',
            'mortgage', 'wire', 'transfer', 'signature', 'consent'
        ]
        
        # Special patterns for credit union sites
        self.form_patterns = [
            r'/forms?/', r'/applications?/', r'/docs?/', r'/documents?/',
            r'/pdfs?/', r'/downloads?/', r'resource', r'member'
        ]

    def get_random_user_agent(self):
        return random.choice(self.user_agents)
        
    def make_request(self, url, allow_redirects=True):
        """Make a request with proper headers and error handling"""
        headers = {
            'User-Agent': self.get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
        
        try:
            response = self.session.get(url, headers=headers, timeout=20, allow_redirects=allow_redirects)
            if response.status_code == 200:
                return response
            else:
                logger.warning(f"Got status {response.status_code} for {url}")
                return None
        except Exception as e:
            logger.error(f"Request failed for {url}: {str(e)}")
            return None
            
    def extract_form_links(self, soup, page_url):
        """Extract potential form links from the page"""
        form_links = []
        
        # 1. Look for direct PDF links
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            if not href or href.startswith('#') or href.startswith('javascript:'):
                continue
                
            full_url = urljoin(page_url, href)
            
            # Direct PDF links
            if href.lower().endswith('.pdf'):
                form_links.append(full_url)
                continue
                
            # Check for form-related text
            link_text = a.get_text().lower()
            if any(keyword in link_text for keyword in self.form_keywords):
                form_links.append(full_url)
                continue
                
            # Check URL patterns
            lower_url = full_url.lower()
            if any(re.search(pattern, lower_url) for pattern in self.form_patterns):
                form_links.append(full_url)
                continue
                
            # Look for application/form IDs in URLs
            if re.search(r'(form|application|doc)[-_]?id=', lower_url):
                form_links.append(full_url)
                
        # 2. Check for specialized widgets, tabs and other common UI elements
        for elem in soup.find_all(['div', 'section', 'article']):
            class_attr = elem.get('class', [])
            id_attr = elem.get('id', '')
            
            # Convert class list to string for easier checking
            class_str = ' '.join(class_attr) if isinstance(class_attr, list) else str(class_attr)
            
            # Check for common form container patterns
            form_containers = ['form', 'document', 'resource', 'download', 'pdf', 'application']
            if any(container in class_str.lower() for container in form_containers) or \
               any(container in id_attr.lower() for container in form_containers):
                # Look for links within these containers
                for a in elem.find_all('a', href=True):
                    href = a['href'].strip()
                    if href and not href.startswith('#') and not href.startswith('javascript:'):
                        full_url = urljoin(page_url, href)
                        form_links.append(full_url)
                        
        # 3. Look for specific credit union form patterns in onclick handlers
        for elem in soup.find_all(['a', 'button', 'div'], onclick=True):
            onclick = elem.get('onclick', '')
            url_match = re.search(r'(["\'](https?://[^"\']+\.pdf|/[^"\']+\.pdf)["\']+)', onclick)
            if url_match:
                pdf_url = url_match.group(2)
                full_url = urljoin(page_url, pdf_url)
                form_links.append(full_url)
                
        # 4. Find data-* attributes that might contain PDF URLs
        for elem in soup.find_all(attrs=True):
            for attr_name, attr_val in elem.attrs.items():
                if attr_name.startswith('data-') and isinstance(attr_val, str):
                    url_match = re.search(r'(https?://[^\s"\']+\.pdf|/[^\s"\']+\.pdf)', attr_val)
                    if url_match:
                        pdf_url = url_match.group(1)
                        full_url = urljoin(page_url, pdf_url)
                        form_links.append(full_url)
                        
        # Return unique links
        return list(set(form_links))
        
    def should_visit(self, url):
        """Determine if a URL should be visited"""
        parsed_url = urlparse(url)
        
        # Only visit pages on the same domain
        if parsed_url.netloc != self.domain:
            return False
            
        # Skip media files and non-HTML content (except PDFs for form collection)
        lower_path = parsed_url.path.lower()
        if any(lower_path.endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js']):
            return False
            
        # Don't revisit pages
        if url in self.visited:
            return False
            
        # Always visit potential form/resource pages
        if any(re.search(pattern, lower_path) for pattern in self.form_patterns):
            return True
            
        return True
        
    def verify_pdf_link(self, url):
        """Verify if a URL is actually a PDF"""
        if url.lower().endswith('.pdf'):
            return True
            
        # Try a HEAD request to check content type
        try:
            response = self.make_request(url, allow_redirects=True)
            if response and 'application/pdf' in response.headers.get('Content-Type', '').lower():
                return True
        except Exception:
            # If we can't verify, but it has PDF indicators, assume it might be a PDF
            if any(keyword in url.lower() for keyword in ['pdf', 'form', 'application']):
                return True
                
        return False
        
    def extract_filename(self, url):
        """Extract a meaningful filename from the URL or headers"""
        # Try to get from URL path
        parsed = urlparse(url)
        path = parsed.path
        filename = path.split('/')[-1]
        
        # If filename has a valid name with extension
        if '.' in filename and len(filename) > 5:
            return filename
            
        # Try to get from Content-Disposition header
        try:
            response = self.make_request(url, allow_redirects=False)
            if response:
                cd_header = response.headers.get('Content-Disposition', '')
                if 'filename=' in cd_header:
                    match = re.search(r'filename=["\'](.*?)["\']', cd_header)
                    if match:
                        return match.group(1)
        except Exception:
            pass
            
        # Generate a filename based on URL parts
        parts = [p for p in path.split('/') if p]
        meaningful_parts = []
        
        for part in reversed(parts):
            if any(keyword in part.lower() for keyword in self.form_keywords):
                meaningful_parts.insert(0, part)
                
        if meaningful_parts:
            return '_'.join(meaningful_parts) + '.pdf'
        
        # Default fallback
        return f"form_{hash(url) % 10000}.pdf"
        
    def crawl(self, max_depth=3, max_pages=100):
        """Crawl the website to find forms"""
        to_visit = [(self.base_url, 0)]  # (url, depth)
        pages_visited = 0
        
        logger.info(f"Starting crawl at {self.base_url}")
        
        while to_visit and pages_visited < max_pages:
            url, depth = to_visit.pop(0)
            
            # Skip if we've reached max depth
            if depth > max_depth:
                continue
                
            # Skip if we've already visited
            if url in self.visited:
                continue
                
            # Visit the page
            logger.info(f"Visiting page {pages_visited+1}: {url}")
            response = self.make_request(url)
            if not response:
                continue
                
            self.visited.add(url)
            pages_visited += 1
            
            # Parse the page content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract potential form links
            form_links = self.extract_form_links(soup, url)
            
            # Process form links
            for form_url in form_links:
                # Skip if already found
                if form_url in [f['url'] for f in self.forms]:
                    continue
                    
                # If it's a PDF or potential form page
                if form_url.lower().endswith('.pdf') or self.verify_pdf_link(form_url):
                    # For PDFs, add to forms list
                    form_title = self.extract_filename(form_url)
                    logger.info(f"Found form: {form_title} at {form_url}")
                    
                    self.forms.append({
                        'title': form_title,
                        'url': form_url,
                        'found_on': url
                    })
                elif self.should_visit(form_url) and depth < max_depth:
                    # For non-PDFs that should be visited, add to visit queue
                    to_visit.append((form_url, depth + 1))
            
            # Extract all links for further crawling
            for a in soup.find_all('a', href=True):
                href = a['href'].strip()
                if not href or href.startswith('#') or href.startswith('javascript:'):
                    continue
                    
                full_url = urljoin(url, href)
                
                if self.should_visit(full_url) and full_url not in self.visited and full_url not in [u for u, _ in to_visit]:
                    # Prioritize potential form/resource pages (add to beginning of queue)
                    if any(pattern in full_url.lower() for pattern in self.form_patterns):
                        to_visit.insert(0, (full_url, depth + 1))
                    else:
                        to_visit.append((full_url, depth + 1))
            
            # Be nice to the server
            time.sleep(1)
        
        logger.info(f"Crawl complete. Visited {pages_visited} pages, found {len(self.forms)} forms.")
        return self.forms

def main():
    # Credit union website to crawl
    base_url = "https://www.cuwest.org/resources/member-services/forms-and-applications"
    
    # Create and run crawler
    crawler = CreditUnionFormCrawler(base_url)
    forms = crawler.crawl(max_depth=4, max_pages=100)
    
    # Print results
    if forms:
        print(f"\nFound {len(forms)} forms:")
        for i, form in enumerate(forms, 1):
            print(f"{i}. {form['title']}")
            print(f"   URL: {form['url']}")
            print(f"   Found on: {form['found_on']}")
            print()
    else:
        print("No forms found. Try adjusting the crawler settings or checking the site structure.")

if __name__ == "__main__":
    main()