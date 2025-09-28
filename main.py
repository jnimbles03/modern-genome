from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS
import requests
import PyPDF2
import re
import io
import logging
import os
import sys

# Ensure that the embedded form_analyzer module is discoverable.  The
# form_analyzer module lives under ``forms-analyzer-pro-nigo/forms-analyzer-pro-nigo`` in
# this distribution.  Append that directory to sys.path so that
# ``import form_analyzer`` succeeds when running ``main.py`` from the project root.
base_module_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                'forms-analyzer-pro-nigo',
                                'forms-analyzer-pro-nigo')
if os.path.isdir(base_module_path) and base_module_path not in sys.path:
    sys.path.append(base_module_path)
import uuid
import json
import time
import threading
import asyncio
import random
from urllib.parse import urljoin, urlparse
from datetime import datetime

# Import specialized credit union crawler
try:
    # The CreditUnionFormCrawler class encapsulates logic for discovering PDF forms
    # on credit union websites. It searches for links and patterns specific to
    # common form pages and returns a list of dictionaries containing form
    # titles, URLs, and the page on which they were found. We use it in
    # conjunction with our general crawler to provide targeted discovery
    # capabilities.
    from credit_union_crawler import CreditUnionFormCrawler  # type: ignore
except Exception as e:
    # Log a warning if the crawler is unavailable; the enhanced crawler will still work
    logging.warning(f"Could not import CreditUnionFormCrawler: {e}")

# Import for crawler
try:
    from bs4 import BeautifulSoup
except ImportError:
    logging.warning("BeautifulSoup not installed. Run: pip install beautifulsoup4")

# Configure more detailed logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Initialize Flask with static folder configuration
app = Flask(__name__, static_folder='static', static_url_path='')
CORS(app)  # Enable CORS for all routes

# Feature flags
DASHBOARD_FEATURE_ENABLED = True

# Global crawler rate limiting
crawl_lock = threading.Lock()
last_request_time = {}
REQUEST_DELAY = 2  # seconds between requests to same domain (increased from 1)

# Domain-based rate limiting
domain_rate_limits = {}
DEFAULT_RATE_LIMIT = {
    'max_requests': 5,  # Maximum requests per time window
    'window': 60,       # Time window in seconds
    'requests': [],     # List of timestamps of recent requests
    'backoff_factor': 1.0,  # Current backoff factor, increases with 429 errors
}

# Store analyzed forms in memory
analyzed_forms = []

def get_analyzed_forms():
    """Get the list of analyzed forms"""
    global analyzed_forms
    return analyzed_forms

def check_rate_limit(domain):
    """Check if we're allowed to make a request to this domain"""
    global domain_rate_limits
    
    # Initialize rate limit data for this domain if it doesn't exist
    if domain not in domain_rate_limits:
        domain_rate_limits[domain] = DEFAULT_RATE_LIMIT.copy()
        domain_rate_limits[domain]['requests'] = []
    
    # Get rate limit data for this domain
    rate_limit = domain_rate_limits[domain]
    now = time.time()
    
    # Remove timestamps older than the window
    rate_limit['requests'] = [t for t in rate_limit['requests'] if now - t < rate_limit['window']]
    
    # Check if we're allowed to make a request
    if len(rate_limit['requests']) >= rate_limit['max_requests']:
        wait_time = rate_limit['window'] - (now - rate_limit['requests'][0])
        wait_time = max(wait_time, 0) * rate_limit['backoff_factor']
        return False, wait_time
    
    # Add timestamp for this request
    rate_limit['requests'].append(now)
    return True, 0

def rate_limit_exceeded(domain):
    """Handle rate limit exceeded for a domain"""
    global domain_rate_limits
    
    # Increase backoff factor for this domain
    if domain in domain_rate_limits:
        domain_rate_limits[domain]['backoff_factor'] = min(
            domain_rate_limits[domain]['backoff_factor'] * 2,
            10.0  # Cap at 10x
        )
        logger.warning(f"Rate limit exceeded for {domain}, backoff increased to {domain_rate_limits[domain]['backoff_factor']}x")

class PDFFormAnalyzer:
    def __init__(self):
        self.signature_patterns = [
            r'\bsignature\b', r'\bsign\b', r'\bsigned\b',
            r'\bsignatory\b', r'\bexecuted\b', r'\bexecute\b'
        ]
        self.witness_patterns = [
            r'\bwitness\b', r'\bwitnessed\b', r'\bwitnessing\b',
            r'\bwitness signature\b', r'\battested\b'
        ]
        self.notary_patterns = [
            r'\bnotary\b', r'\bnotarized\b', r'\bnotarization\b',
            r'\backnowledged\b', r'\bsworn\b', r'\baffirmed\b'
        ]
        self.current_url = None
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
        ]
        
    def download_pdf(self, url):
        """Download PDF from URL with proper headers, validation, and rate limiting"""
        try:
            logger.info(f"Downloading PDF from URL: {url}")
            
            # Extract domain for rate limiting
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Check rate limit
            allowed, wait_time = check_rate_limit(domain)
            if not allowed:
                logger.warning(f"Rate limit exceeded for {domain}, waiting {wait_time:.1f} seconds")
                time.sleep(wait_time)
            
            # Randomize user agent and set more realistic headers
            user_agent = random.choice(self.user_agents)
            headers = {
                'User-Agent': user_agent,
                'Accept': 'application/pdf,*/*;q=0.9',
                'Accept-Language': 'en-US,en;q=0.8',
                'Accept-Encoding': 'gzip, deflate, br',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Cache-Control': 'max-age=0',
                'Referer': f"{parsed_url.scheme}://{parsed_url.netloc}/",
            }
            
            # Add random parameter to bypass caching
            cache_buster = f"nocache={uuid.uuid4()}"
            if '?' in url:
                download_url = f"{url}&{cache_buster}"
            else:
                download_url = f"{url}?{cache_buster}"
            
            logger.info(f"Sending request with cache busting: {download_url}")
            
            # Make request with retry logic
            max_retries = 5
            retry_delay = 1
            
            for attempt in range(max_retries):
                try:
                    response = requests.get(download_url, headers=headers, timeout=30, stream=True)
                    
                    # Log response details for debugging
                    logger.info(f"Response status: {response.status_code}")
                    logger.info(f"Response headers: {response.headers}")
                    
                    # Handle rate limiting (429)
                    if response.status_code == 429:
                        rate_limit_exceeded(domain)
                        
                        # Check for Retry-After header
                        retry_after = response.headers.get('Retry-After')
                        if retry_after:
                            try:
                                wait_seconds = int(retry_after)
                            except ValueError:
                                # Retry-After can also be a HTTP date
                                wait_seconds = 30  # Default if we can't parse it
                        else:
                            # Exponential backoff
                            wait_seconds = retry_delay * (2 ** attempt)
                        
                        if attempt < max_retries - 1:
                            logger.warning(f"Rate limited (429). Waiting {wait_seconds} seconds before retry.")
                            time.sleep(wait_seconds)
                            continue
                        else:
                            raise ValueError(f"Failed to download PDF after {max_retries} retries due to rate limiting (429)")
                    
                    # Handle other non-200 responses
                    if response.status_code != 200:
                        if attempt < max_retries - 1:
                            wait_seconds = retry_delay * (2 ** attempt)
                            logger.warning(f"Request failed with status {response.status_code}. Waiting {wait_seconds} seconds before retry.")
                            time.sleep(wait_seconds)
                            continue
                        else:
                            raise ValueError(f"Failed to download PDF. Status code: {response.status_code}")
                    
                    # We got a successful response
                    content = response.content
                    content_length = len(content)
                    logger.info(f"Downloaded content size: {content_length} bytes")
                    
                    if content_length < 1000:  # Very small files are probably not valid PDFs
                        logger.warning(f"Downloaded content is suspiciously small ({content_length} bytes)")
                        logger.debug(f"Content start: {content[:100]}")
                    
                    # Verify it's a PDF
                    if not content.startswith(b'%PDF'):
                        logger.error(f"Content is not PDF. First 100 bytes: {content[:100]}")
                        raise ValueError("Downloaded content is not a valid PDF")
                        
                    pdf_stream = io.BytesIO(content)
                    
                    # Validate PDF structure and get basic info
                    try:
                        test_reader = PyPDF2.PdfReader(pdf_stream)
                        page_count = len(test_reader.pages)
                        logger.info(f"PDF validated successfully with {page_count} pages")
                        
                        # Test text extraction from first page
                        if page_count > 0:
                            first_page = test_reader.pages[0]
                            sample_text = first_page.extract_text()
                            if sample_text:
                                logger.info(f"First page text sample: {sample_text[:200].replace(chr(10), ' ')}")
                            else:
                                logger.warning("First page contains no extractable text")
                        
                        # Reset stream position after validation
                        pdf_stream.seek(0)
                    except Exception as e:
                        logger.error(f"PDF validation failed: {str(e)}")
                        raise ValueError(f"Invalid PDF structure: {str(e)}")
                        
                    # Success! Return the stream
                    return pdf_stream
                    
                except requests.RequestException as e:
                    # Handle network-related errors
                    if attempt < max_retries - 1:
                        wait_seconds = retry_delay * (2 ** attempt)
                        logger.warning(f"Request attempt {attempt+1} failed: {str(e)}. Waiting {wait_seconds} seconds before retry.")
                        time.sleep(wait_seconds)
                    else:
                        logger.error(f"All {max_retries} request attempts failed: {str(e)}")
                        raise Exception(f"Failed to download PDF after {max_retries} attempts: {str(e)}")
            
        except requests.RequestException as e:
            logger.error(f"Request failed: {str(e)}", exc_info=True)
            raise Exception(f"Failed to download PDF: {str(e)}")
        except Exception as e:
            logger.error(f"Error processing PDF: {str(e)}", exc_info=True)
            raise Exception(f"Error processing PDF: {str(e)}")
    
    def extract_text_from_pdf(self, pdf_stream):
        """Extract all text from PDF with better error handling"""
        try:
            logger.info("Extracting text from PDF")
            pdf_stream.seek(0)  # Ensure we're at the start of the stream
            reader = PyPDF2.PdfReader(pdf_stream)
            full_text = ""
            
            page_count = len(reader.pages)
            logger.info(f"PDF has {page_count} pages")
            
            if page_count == 0:
                logger.warning("PDF has no pages")
                return ""
            
            for i, page in enumerate(reader.pages):
                try:
                    page_text = page.extract_text()
                    if page_text:
                        full_text += page_text + "\n"
                        logger.info(f"Page {i+1}: Extracted {len(page_text)} characters")
                    else:
                        logger.warning(f"Page {i+1}: No text extracted")
                except Exception as e:
                    logger.warning(f"Error extracting text from page {i+1}: {str(e)}")
            
            text_length = len(full_text)
            logger.info(f"Total extracted text: {text_length} characters")
            
            if text_length < 100:
                logger.warning(f"Very little text extracted! Full text: '{full_text}'")
            else:
                logger.info(f"First 200 chars: '{full_text[:200].replace(chr(10), ' ')}'")
            
            return full_text.lower()  # Convert to lowercase for pattern matching
        except Exception as e:
            logger.error(f"Failed to extract text from PDF: {str(e)}", exc_info=True)
            raise Exception(f"Failed to extract text from PDF: {str(e)}")
    
    def count_form_fields(self, pdf_stream):
        """Analyze form fields in PDF with better error handling"""
        try:
            logger.info("Analyzing form fields")
            pdf_stream.seek(0)  # Reset stream position
            reader = PyPDF2.PdfReader(pdf_stream)
            
            total_fields = 0
            text_fields = 0
            checkboxes = 0
            dropdowns = 0
            
            # Try to get form fields from PDF
            has_acroform = False
            form_fields_found = False
            
            try:
                if reader.trailer is not None and "/Root" in reader.trailer:
                    root = reader.trailer["/Root"]
                    if "/AcroForm" in root:
                        has_acroform = True
                        form = root["/AcroForm"]
                        if "/Fields" in form:
                            fields = form["/Fields"]
                            field_count = len(fields) if fields else 0
                            logger.info(f"AcroForm detected with {field_count} fields")
                            
                            if field_count > 0:
                                form_fields_found = True
                                total_fields = field_count
                                
                                # Analyze field types
                                for field_ref in fields:
                                    try:
                                        field = field_ref.get_object()
                                        field_type = field.get("/FT", "")
                                        
                                        logger.debug(f"Field type: {field_type}")
                                        
                                        if field_type == "/Tx":  # Text field
                                            text_fields += 1
                                        elif field_type == "/Btn":  # Button/checkbox
                                            checkboxes += 1
                                        elif field_type == "/Ch":  # Choice/dropdown
                                            dropdowns += 1
                                    except Exception as field_err:
                                        logger.warning(f"Error analyzing field: {str(field_err)}")
            except Exception as acro_err:
                logger.warning(f"Error analyzing AcroForm: {str(acro_err)}")
            
            logger.info(f"AcroForm detected: {has_acroform}, Form fields found: {form_fields_found}")
            
            # If no form fields detected, estimate from text patterns
            if not form_fields_found:
                logger.info("No form fields found, estimating from text patterns")
                pdf_stream.seek(0)
                text = self.extract_text_from_pdf(pdf_stream)
                
                # Look for common form patterns
                field_patterns = [
                    r'_+', r'\.\.\.+', r'\[.*?\]', r'\(.*?\)',
                    r'name:', r'date:', r'address:', r'signature:'
                ]
                
                pattern_counts = {}
                for pattern in field_patterns:
                    matches = re.findall(pattern, text, re.IGNORECASE)
                    pattern_counts[pattern] = len(matches)
                    total_fields += len(matches)
                
                logger.info(f"Pattern counts: {pattern_counts}")
                
                # Look for dropdown indicators
                dropdown_patterns = [
                    r'select one', r'choose one', r'drop.?down', 
                    r'select.*option', r'check one'
                ]
                
                for pattern in dropdown_patterns:
                    matches = re.findall(pattern, text, re.IGNORECASE)
                    dropdowns += len(matches)
                
                # Estimate text fields vs checkboxes (accounting for dropdowns)
                remaining_fields = max(total_fields - dropdowns, 0)
                text_fields = int(remaining_fields * 0.7)  # Assume 70% are text fields
                checkboxes = remaining_fields - text_fields
            
            # Ensure minimum values for forms (avoid zero-fields)
            if total_fields == 0:
                # Don't assume defaults, but ensure at least 1 field if we found any text
                pdf_stream.seek(0)
                text = self.extract_text_from_pdf(pdf_stream)
                if len(text) > 0:
                    logger.info("No fields detected but document contains text. Setting minimum field count.")
                    total_fields = 1
                    text_fields = 1
            
            result = {
                'total': total_fields,
                'text_fields': text_fields,
                'checkboxes': checkboxes,
                'dropdowns': dropdowns
            }
            
            logger.info(f"Field analysis results: {result}")
            return result
            
        except Exception as e:
            logger.error(f"Field analysis failed: {str(e)}", exc_info=True)
            # Don't return default values - either raise the exception or return an error indicator
            raise Exception(f"Field analysis failed: {str(e)}")
    
    def analyze_signatures(self, text):
        """Analyze signature requirements with better pattern matching"""
        logger.info("Analyzing signature requirements")
        signature_count = 0
        conditional_signatures = 0
        witness_signatures = 0
        
        # Count signature references
        sig_pattern_counts = {}
        for pattern in self.signature_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            sig_pattern_counts[pattern] = len(matches)
            signature_count += len(matches)
        
        logger.info(f"Signature pattern matches: {sig_pattern_counts}")
        
        # Look for conditional signature language
        conditional_patterns = [
            r'if.*sign', r'when.*sign', r'unless.*sign',
            r'provided.*sign', r'subject to.*sign'
        ]
        
        conditional_pattern_counts = {}
        for pattern in conditional_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            conditional_pattern_counts[pattern] = len(matches)
            conditional_signatures += len(matches)
            
        logger.info(f"Conditional signature pattern matches: {conditional_pattern_counts}")
        
        # Count witness signature requirements
        witness_pattern_counts = {}
        for pattern in self.witness_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            witness_pattern_counts[pattern] = len(matches)
            witness_signatures += len(matches)
            
        logger.info(f"Witness signature pattern matches: {witness_pattern_counts}")
        
        # Ensure reasonable results - if text exists but no signatures found,
        # assume at least one signature for most form documents
        if signature_count == 0 and len(text) > 500:
            words = text.split()
            if len(words) > 100:  # Only for substantial documents
                logger.info("No signatures detected in substantial document. Assuming minimum signature.")
                signature_count = 1
        
        result = {
            'signature_count': signature_count,
            'conditional_signature_count': conditional_signatures,
            'witness_signature_count': witness_signatures
        }
        
        logger.info(f"Signature analysis results: {result}")
        return result
    
    def check_special_requirements(self, text):
        """Check for witnesses, notarization, and conditional logic"""
        logger.info("Checking special requirements")
        witnesses_required = "No"
        notarization_required = "No"
        conditional_logic = "No"
        
        # Check for witness requirements
        witness_required_patterns = [
            r'witness.*required', r'must be witnessed', r'witnessed by',
            r'in the presence of', r'witness signature'
        ]
        
        for pattern in witness_required_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                witnesses_required = "Yes"
                logger.info(f"Witness requirement found with pattern: {pattern}")
                break
        
        # Check for notarization requirements
        for pattern in self.notary_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                notarization_required = "Yes"
                logger.info(f"Notarization requirement found with pattern: {pattern}")
                break
        
        # Check for conditional logic
        conditional_patterns = [
            r'if.*then', r'provided that', r'subject to', r'unless',
            r'conditional', r'depends on', r'only if'
        ]
        for pattern in conditional_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                conditional_logic = "Yes"
                logger.info(f"Conditional logic found with pattern: {pattern}")
                break
        
        result = {
            'witnesses_required': witnesses_required,
            'notarization_required': notarization_required,
            'conditional_logic': conditional_logic
        }
        
        logger.info(f"Special requirements results: {result}")
        return result
    
    def extract_form_title(self, text, metadata):
        """Extract form title from PDF text or metadata"""
        logger.info("Extracting form title")
        # Try to get from metadata
        if metadata and metadata.get('/Title'):
            # Some PDF libraries may return an IndirectObject here, which isn't JSON serialisable.
            # Convert to string explicitly to avoid serialization errors later on.
            title = metadata.get('/Title')
            try:
                title_str = str(title)
            except Exception:
                title_str = ''
            logger.info(f"Title found in metadata: {title_str}")
            return title_str
        
        # Look for title patterns in first few lines
        lines = text.split('\n')[:10]
        for line in lines:
            line = line.strip()
            if len(line) > 5 and len(line) < 100:  # Reasonable title length
                title_patterns = [
                    r'^(.*form.*|.*application.*|.*request.*|.*agreement.*|.*contract.*|.*disclosure.*|.*authorization.*)',
                    r'^(.*[A-Z][A-Z\s]+)$'  # All caps lines are often titles
                ]
                
                for pattern in title_patterns:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        title = match.group(1).strip()
                        logger.info(f"Title found in text: {title}")
                        return title
        
        # Extract filename from URL as fallback
        if self.current_url:
            try:
                parsed_url = urlparse(self.current_url)
                path = parsed_url.path
                filename = os.path.basename(path)
                if filename:
                    logger.info(f"Using filename as title: {filename}")
                    return filename
            except Exception as e:
                logger.warning(f"Error extracting filename from URL: {str(e)}")
            
        # Default title
        logger.info("No title found, using default")
        return "Unknown Form"

    def extract_entity_name_financial(self, text, metadata, url):
        """Specialized entity extraction for financial forms"""
        # Financial institution patterns in URLs
        financial_domains = {
            'fidelity': 'Fidelity Investments',
            'vanguard': 'Vanguard',
            'schwab': 'Charles Schwab',
            'americanfunds': 'American Funds',
            'tiaa': 'TIAA',
            'troweprice': 'T. Rowe Price',
            'etrade': 'E*TRADE',
            'tdameritrade': 'TD Ameritrade',
            'merrilledge': 'Merrill Edge',
            'wellsfargo': 'Wells Fargo',
            'chase': 'JPMorgan Chase',
            'citi': 'Citibank',
            'bankofamerica': 'Bank of America',
            'morgan': 'Morgan Stanley',
            'pnc': 'PNC Bank'
        }
        
        # Check URL first - most reliable for financial institutions
        url_lower = url.lower()
        for key, name in financial_domains.items():
            if key in url_lower:
                logger.info(f"Financial institution found in URL: {name}")
                return name
        
        # Try standard extraction
        entity = self.extract_entity_name(text, metadata)
        
        # If we found a good entity, return it
        if entity != "Unknown Entity":
            return entity
        
        # Financial-specific patterns for common forms
        financial_patterns = [
            r'(?:offered|managed|administered|sponsored)\s+by\s+([A-Z][A-Za-z\s&,.]+)',
            r'(?:return|send|mail)\s+to\s+([A-Z][A-Za-z\s&,.]+)',
            r'([A-Z][A-Za-z\s&,.]+)\s+(?:account|retirement|plan|fund|benefits)',
            r'(?:contact|call)\s+([A-Z][A-Za-z\s&,.]+)\s+at'
        ]
        
        for pattern in financial_patterns:
            match = re.search(pattern, text)
            if match:
                entity = match.group(1).strip()
                if len(entity) > 3 and len(entity) < 50:
                    logger.info(f"Financial entity found with pattern: {entity}")
                    return entity
        
        # Extract from URL as fallback
        return self.extract_entity_name_from_url(url)

    def extract_entity_name_from_url(self, url):
        """Extract entity name from URL when other methods fail"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Handle financial institutions
            if 'fidelity' in domain:
                return 'Fidelity Investments'
            if 'vanguard' in domain:
                return 'Vanguard'
            # Add more financial institutions as needed
            
            # Generic extraction
            domain_parts = domain.split('.')
            if len(domain_parts) > 1:
                name_part = domain_parts[-2]
                # Clean up common domain prefixes
                if name_part.startswith('nb') or name_part.startswith('www'):
                    if len(domain_parts) > 2:
                        name_part = domain_parts[-3]
                
                # Convert to title case and clean up
                entity_name = ' '.join(word.capitalize() for word in re.findall(r'[a-zA-Z]+', name_part))
                if len(entity_name) > 2:
                    return entity_name
                
        except Exception as e:
            logger.warning(f"Error extracting from URL: {str(e)}")
        
        return "Unknown Entity"

    def extract_entity_name(self, text, metadata):
        """Extract entity/organization name with improved accuracy"""
        logger.info("Extracting entity name")
        
        # Check PDF metadata first (most reliable source)
        if metadata:
            for key in ['/Author', '/Creator', '/Producer', '/Company', '/Title']:
                if metadata.get(key) and len(str(metadata.get(key))) > 2:
                    # Clean up common metadata values that aren't organization names
                    meta_value = str(metadata.get(key))
                    if not any(x in meta_value.lower() for x in ['adobe', 'microsoft', 'word', 'acrobat', 'pdf', 'writer']):
                        logger.info(f"Entity found in metadata {key}: {meta_value}")
                        return meta_value
        
        # Look for letterhead in first page (widened from first 500 chars)
        first_page = text[:1000] if len(text) > 1000 else text
        
        # Enhanced organization patterns
        org_patterns = [
            # Standard corporate suffixes
            r'([A-Z][A-Za-z0-9\s,\.&\'-]+?)\s+(Inc\.?|Corp\.?|Corporation|LLC|LLP|Ltd\.?|Limited|Co\.?|Company|GmbH|S\.A\.|P\.C\.|Foundation|Association|Group|Partners)',
            
            # Forms/letterhead headers often start with org name
            r'^([A-Z][A-Z\s\.&,]+)$',
            
            # Copyright notices
            r'[©Cc]opyright\s*(?:\d{4})?(?:-?\d{4})?\s*(?:by)?\s*([A-Z][A-Za-z0-9\s,\.&\'-]+?)(?:[.,]|\s+All|\s+Rights)',
            
            # Common form headers
            r'(By|From|For|Prepared by|Issued by|Provided by):\s*([A-Z][A-Za-z0-9\s,\.&\'-]+?)(?:[.,]|\s+\d|\s*$)',
            
            # "Company Name:" format often used in forms
            r'(?:Company|Organization|Entity|Business|Firm)\s+Name:?\s+([A-Z][A-Za-z0-9\s,\.&\'-]+?)(?:[.,]|\s+\d|\s*$)',
        ]
        
        # First check the beginning of the document
        for pattern in org_patterns:
            for match in re.finditer(pattern, first_page, re.MULTILINE):
                # Get the correct capture group (some patterns have multiple groups)
                entity = match.group(1) if pattern.startswith(r'([A-Z]') else match.group(2)
                entity = entity.strip()
                
                # Validate extracted entity (avoid false positives)
                if len(entity) > 2 and len(entity) < 65 and not re.match(r'^(http|www|Please|I|We|This|That|If|When|Do|Does)', entity):
                    logger.info(f"Entity found with pattern '{pattern}': {entity}")
                    return entity
        
        # Check for logos/letterhead across entire document
        # Look for lines that appear to be standalone organization names
        lines = text.split('\n')[:20]  # Check first 20 lines, likely to contain letterhead
        for line in lines:
            line = line.strip()
            if 4 < len(line) < 40 and line.isupper() and not any(x in line.lower() for x in ['page', 'date', 'form', 'application', 'please']):
                logger.info(f"Entity found in uppercase line: {line}")
                return line
        
        # Look for domain in form URLs
        url_pattern = r'https?://(?:www\.)?([a-zA-Z0-9-]+)\.(?:com|org|net|edu|gov|io|co)/[a-zA-Z0-9_/-]+'
        for match in re.finditer(url_pattern, text):
            domain_name = match.group(1)
            if len(domain_name) > 3 and domain_name not in ['google', 'adobe', 'microsoft', 'example']:
                domain_entity = domain_name.capitalize()
                logger.info(f"Entity found from URL in text: {domain_entity}")
                return domain_entity
                
        # Try to extract from PDF URL as last resort
        if self.current_url:
            try:
                domain = urlparse(self.current_url).netloc
                if 'acrobat' not in domain and 'adobe' not in domain:
                    domain_parts = domain.split('.')
                    if len(domain_parts) > 1:
                        domain_entity = domain_parts[-2].capitalize()
                        if len(domain_entity) > 3:
                            logger.info(f"Using domain name as entity: {domain_entity}")
                            return domain_entity
            except Exception as e:
                logger.warning(f"Error extracting domain: {str(e)}")
        
        logger.info("No entity found, using default")
        return "Unknown Entity"

    def determine_document_type(self, text):
        """Determine document type and subtype"""
        logger.info("Determining document type")
        # Map of keywords to document types
        type_keywords = {
            'application': 'Application',
            'agreement': 'Agreement',
            'contract': 'Contract',
            'authorization': 'Authorization',
            'consent': 'Consent',
            'disclosure': 'Disclosure',
            'form': 'Form',
            'request': 'Request',
            'order': 'Order',
            'certificate': 'Certificate',
            'beneficiary': 'Beneficiary Form'  # Added for financial forms
        }
        
        # Map of keywords to document subtypes
        subtype_keywords = {
            'employment': 'Employment',
            'financial': 'Financial',
            'medical': 'Medical',
            'insurance': 'Insurance',
            'loan': 'Loan',
            'credit': 'Credit',
            'tax': 'Tax',
            'legal': 'Legal',
            'service': 'Service',
            'account': 'Account',
            'retirement': 'Retirement',  # Added for financial forms
            'beneficiary': 'Beneficiary' # Added for financial forms
        }
        
        doc_type = 'Unknown'
        doc_subtype = 'Unknown'
        
        # Count occurrences of each keyword
        type_counts = {}
        for keyword, type_value in type_keywords.items():
            count = text.lower().count(keyword)
            if count > 0:
                type_counts[type_value] = count
        
        # Choose the type with the highest count
        if type_counts:
            doc_type = max(type_counts.items(), key=lambda x: x[1])[0]
            logger.info(f"Document type determined: {doc_type} (counts: {type_counts})")
        
        # Count occurrences of subtype keywords
        subtype_counts = {}
        for keyword, subtype_value in subtype_keywords.items():
            count = text.lower().count(keyword)
            if count > 0:
                subtype_counts[subtype_value] = count
        
        # Choose the subtype with the highest count
        if subtype_counts:
            doc_subtype = max(subtype_counts.items(), key=lambda x: x[1])[0]
            logger.info(f"Document subtype determined: {doc_subtype} (counts: {subtype_counts})")
        
        return {'type': doc_type, 'subtype': doc_subtype}

    def classify_industry(self, text):
        """Classify the industry vertical and subvertical"""
        logger.info("Classifying industry")
        # Industry classification by keyword
        industries = {
            'FINS': ['bank', 'investment', 'loan', 'mortgage', 'credit', 'finance', 'retirement', 'beneficiary'],
            'HLS': ['medical', 'health', 'hospital', 'patient', 'doctor', 'insurance'],
            'PubSec': ['government', 'agency', 'federal', 'state', 'municipal','school', 'university', 'student', 'education', 'academic'],
        }
        
        # Subverticals with expanded keyword coverage
        subverticals = {
            'FINS': {
                'banking': ['checking', 'savings', 'account', 'bank', 'deposit', 'withdrawal', 'transfer', 
                           'statement', 'branch', 'atm', 'banking', 'teller', 'transaction', 'balance','loan', 'credit', 'mortgage', 'borrower', 'interest', 'principal', 'term', 
                           'refinance', 'amortization', 'collateral', 'underwriting', 'origination', 'lender'],
                'wealth_management': ['investment', 'portfolio', 'securities', 'stocks', 'bonds', 'mutual fund', 
                                     'asset management', 'financial advisor', 'retirement', 'estate planning',
                                     'trust', 'fiduciary', 'wealth', 'brokerage', 'dividend'],
                'insurance': ['insurance', 'policy', 'coverage', 'claim', 'premium', 'deductible', 'beneficiary',
                             'underwriter', 'actuary', 'risk', 'insured', 'carrier', 'indemnity', 'liability'],
            },
            
            'HLS': {
                'provider': ['provider', 'doctor', 'physician', 'hospital', 'clinic', 'medical center', 
                            'practice', 'practitioner', 'nurse', 'specialist', 'healthcare provider',
                            'facility', 'care center', 'medical staff'],
                'payer': ['claim', 'coverage', 'policy', 'insurer', 'premium', 'benefits', 'eligibility', 
                         'adjudication', 'reimbursement', 'copay', 'deductible', 'member', 'plan', 'network'],
                'life_sciences': ['patient', 'treatment', 'care', 'pharmaceutical', 'clinical', 'drug', 
                                 'therapy', 'biotech', 'research', 'trial', 'medical device', 'diagnostic',
                                 'therapeutic', 'laboratory'],
            },
            
            'PubSec': {
                'federal': ['federal', 'government', 'agency', 'administration', 'department', 'bureau',
                           'commission', 'federal agency', 'regulatory', 'national', 'cabinet', 'federal program',
                           'executive', 'congressional'],
                'state_local': ['state', 'local', 'county', 'municipal', 'city', 'town', 'district', 
                               'jurisdiction', 'governor', 'mayor', 'council', 'board', 'regional', 'community'],
                'education': ['school', 'education', 'student', 'teacher', 'faculty', 'university', 'college',
                             'academic', 'district', 'campus', 'enrollment', 'curriculum', 'educational', 'classroom'],
            }
        }
        
        # Default result
        result = {'vertical': 'Unknown', 'subvertical': 'Unknown'}
        
        # Classify vertical
        text_lower = text.lower()
        max_matches = 0
        
        industry_matches = {}
        for industry, keywords in industries.items():
            matches = 0
            for keyword in keywords:
                keyword_count = text_lower.count(keyword)
                matches += keyword_count
            
            industry_matches[industry] = matches
            if matches > max_matches:
                max_matches = matches
                result['vertical'] = industry
        
        logger.info(f"Industry match counts: {industry_matches}")
        logger.info(f"Selected industry: {result['vertical']}")
        
        # Classify subvertical if vertical is known
        if result['vertical'] != 'Unknown' and result['vertical'] in subverticals:
            max_matches = 0
            
            subvertical_matches = {}
            for subvertical, keywords in subverticals[result['vertical']].items():
                matches = 0
                for keyword in keywords:
                    keyword_count = text_lower.count(keyword)
                    matches += keyword_count
                
                subvertical_matches[subvertical] = matches
                if matches > max_matches:
                    max_matches = matches
                    result['subvertical'] = subvertical
            
            logger.info(f"Subvertical match counts: {subvertical_matches}")
            logger.info(f"Selected subvertical: {result['subvertical']}")
        
        return result

    def calculate_complexity(self, text, field_info, page_count, signature_analysis):
        """Calculate form complexity score (0-100)"""
        logger.info("Calculating complexity score")
        score = 0
        
        # Page count factor (0-20 points)
        if page_count <= 1:
            score += 5
            logger.info("Page count factor: +5 (1 page)")
        elif page_count <= 3:
            score += 10
            logger.info(f"Page count factor: +10 ({page_count} pages)")
        elif page_count <= 5:
            score += 15
            logger.info(f"Page count factor: +15 ({page_count} pages)")
        else:
            score += 20
            logger.info(f"Page count factor: +20 ({page_count} pages)")
        
        # Field count factor (0-25 points)
        field_count = field_info['total']
        if field_count <= 5:
            score += 5
            logger.info(f"Field count factor: +5 ({field_count} fields)")
        elif field_count <= 15:
            score += 10
            logger.info(f"Field count factor: +10 ({field_count} fields)")
        elif field_count <= 30:
            score += 15
            logger.info(f"Field count factor: +15 ({field_count} fields)")
        elif field_count <= 50:
            score += 20
            logger.info(f"Field count factor: +20 ({field_count} fields)")
        else:
            score += 25
            logger.info(f"Field count factor: +25 ({field_count} fields)")
        
        # Signature complexity (0-15 points)
        sig_count = signature_analysis['signature_count']
        witness_count = signature_analysis['witness_signature_count']
        
        if sig_count > 0:
            score += 5
            logger.info(f"Signature factor: +5 ({sig_count} signatures)")
        if sig_count > 3:
            score += 5
            logger.info("Multiple signatures factor: +5")
        if witness_count > 0:
            score += 5
            logger.info("Witness signatures factor: +5")
        
        # Text complexity (0-20 points)
        # Approximate reading level by sentence length and word length
        sentences = re.split(r'[.!?]+', text)
        valid_sentences = [s for s in sentences if len(s.strip()) > 0]
        
        if valid_sentences:
            avg_sentence_length = sum(len(s.split()) for s in valid_sentences) / len(valid_sentences)
            logger.info(f"Average sentence length: {avg_sentence_length:.1f} words")
            
            if avg_sentence_length > 25:
                score += 20
                logger.info("Text complexity factor: +20 (very complex)")
            elif avg_sentence_length > 20:
                score += 15
                logger.info("Text complexity factor: +15 (complex)")
            elif avg_sentence_length > 15:
                score += 10
                logger.info("Text complexity factor: +10 (moderate)")
            elif avg_sentence_length > 10:
                score += 5
                logger.info("Text complexity factor: +5 (simple)")
        else:
            logger.warning("No valid sentences found for complexity analysis")
        
        # Special requirements (0-20 points)
        requirements_score = 0
        
        if "notarize" in text.lower() or "notary" in text.lower():
            requirements_score += 5
            logger.info("Special requirement - notarization: +5")
        if "witness" in text.lower():
            requirements_score += 5
            logger.info("Special requirement - witness: +5")
        if "attach" in text.lower() or "attachment" in text.lower():
            requirements_score += 5
            logger.info("Special requirement - attachments: +5")
        if "deadline" in text.lower() or "due date" in text.lower():
            requirements_score += 5
            logger.info("Special requirement - deadlines: +5")
        
        score += requirements_score
        
        final_score = min(score, 100)  # Cap at 100
        logger.info(f"Final complexity score: {final_score}")
        return final_score

    def analyze_advanced_requirements(self, text):
        """Analyze advanced form requirements"""
        logger.info("Analyzing advanced requirements")
        text_lower = text.lower()
        
        # Initialize results
        results = {
            'attachment_count': 0,
            'validation_count': 0,
            'id_required': 'No',
            'third_party': 'No',
            'dependencies': 'No',
            'deadlines': 'No',
            'language_count': 1,
            'click_to_agree': 'No',
            'same_domain': 'Yes',
            'special_requirements': []
        }
        
        # Check for attachments
        attachment_patterns = [
            r'attach', r'include', r'submit.*with', r'provide.*copy',
            r'supporting.*document', r'additional.*document'
        ]
        
        for pattern in attachment_patterns:
            matches = re.findall(pattern, text_lower)
            attachment_count = len(matches)
            if attachment_count > 0:
                logger.info(f"Attachment pattern '{pattern}' found {attachment_count} times")
                results['attachment_count'] += attachment_count
        
        # Limit to reasonable number
        results['attachment_count'] = min(results['attachment_count'], 10)
        
        # Check for ID requirements
        id_patterns = [
            r'identification', r'driver.*license', r'passport', 
            r'government.*id', r'photo.*id', r'proof.*identity'
        ]
        
        for pattern in id_patterns:
            if re.search(pattern, text_lower):
                results['id_required'] = 'Yes'
                logger.info(f"ID requirement found with pattern: {pattern}")
                break
        
        # Check for data validation requirements
        validation_patterns = [
            r'must match', r'confirm.*same', r'valid', r'format', r'required format'
        ]
        
        for pattern in validation_patterns:
            matches = re.findall(pattern, text_lower)
            validation_count = len(matches)
            if validation_count > 0:
                logger.info(f"Validation pattern '{pattern}' found {validation_count} times")
                results['validation_count'] += validation_count
        
        # Check for third party involvement
        third_party_patterns = [
            r'third party', r'third-party', r'on behalf of', r'agent', 
            r'representative', r'authorize.*person'
        ]
        
        for pattern in third_party_patterns:
            if re.search(pattern, text_lower):
                results['third_party'] = 'Yes'
                logger.info(f"Third party involvement found with pattern: {pattern}")
                break
        
        # Check for form dependencies
        dependency_patterns = [
            r'form.*\d+', r'along with form', r'together with', r'accompanied by',
            r'in addition to.*form', r'supplement.*form'
        ]
        
        for pattern in dependency_patterns:
            if re.search(pattern, text_lower):
                results['dependencies'] = 'Yes'
                logger.info(f"Form dependency found with pattern: {pattern}")
                break
        
        # Check for deadlines
        deadline_patterns = [
            r'deadline', r'due date', r'due by', r'submit by', r'no later than',
            r'within \d+ days', r'by \w+ \d+', r'\d{1,2}/\d{1,2}/\d{2,4}'
        ]
        
        for pattern in deadline_patterns:
            if re.search(pattern, text_lower):
                results['deadlines'] = 'Yes'
                logger.info(f"Deadline found with pattern: {pattern}")
                break
        
        # Check for multiple languages
        language_patterns = [
            r'english.*spanish', r'español', r'français', r'deutsche',
            r'\(en\).*\(es\)', r'\(en\).*\(fr\)'
        ]
        
        language_count = 1  # Default to English
        for pattern in language_patterns:
            if re.search(pattern, text_lower):
                language_count += 1
                logger.info(f"Additional language found with pattern: {pattern}")
        
        results['language_count'] = min(language_count, 5)  # Cap at 5 languages
        
        # Check for click-to-agree
        click_patterns = [
            r'click.*agree', r'click.*accept', r'electronic.*signature',
            r'digital.*signature', r'e-sign', r'docusign'
        ]
        
        for pattern in click_patterns:
            if re.search(pattern, text_lower):
                results['click_to_agree'] = 'Yes'
                logger.info(f"Click-to-agree found with pattern: {pattern}")
                break
        
        # Special requirements
        special_patterns = {
            'Certified Copy': r'certified copy',
            'Original Document': r'original document',
            'Corporate Seal': r'corporate seal',
            'Fingerprints': r'fingerprint',
            'Legal Review': r'legal review',
            'Manager Approval': r'manager.*approval',
            'Executive Signature': r'executive.*signature',
            'Board Approval': r'board.*approval'
        }
        
        for name, pattern in special_patterns.items():
            if re.search(pattern, text_lower):
                results['special_requirements'].append(name)
                logger.info(f"Special requirement found: {name}")
        
        logger.info(f"Advanced requirements results: {results}")
        return results

    def estimate_signer_time(self, field_info, complexity_score):
        """Estimate time required for signing (in minutes)"""
        # Base time - 1 minute plus 30 seconds per field
        base_time = 1 + (field_info['total'] * 0.5 / 60)
        
        # Complexity factor - more complex forms take more time to understand
        complexity_factor = 1 + (complexity_score / 100)
        
        # Estimated time in minutes
        estimated_time = base_time * complexity_factor
        
        # Round to nearest minute with minimum of 1
        result = max(1, round(estimated_time))
        logger.info(f"Estimated signer time: {result} minutes")
        return result

    def estimate_processing_time(self, field_info, complexity_score):
        """Estimate time for processing (in minutes)"""
        # Base processing time - 5 minutes plus 15 seconds per field
        base_time = 5 + (field_info['total'] * 0.25 / 60)
        
        # Complexity factor
        complexity_factor = 1 + (complexity_score / 50)  # Higher impact than signing
        
        # Estimated time in minutes
        estimated_time = base_time * complexity_factor
        
        # Round to nearest minute with minimum of 5
        result = max(5, round(estimated_time))
        logger.info(f"Estimated processing time: {result} minutes")
        return result

    def identify_key_drivers(self, text, field_info, complexity_score):
        """Identify key factors driving complexity"""
        logger.info("Identifying key drivers")
        drivers = []
        text_lower = text.lower()
        
        # Potential drivers with detection patterns
        driver_patterns = {
            'High Field Count': field_info['total'] > 30,
            'Complex Signature Requirements': 'witness' in text_lower or 'notary' in text_lower,
            'Legal Complexity': any(term in text_lower for term in ['legal', 'law', 'statute', 'regulation']),
            'Attachments Required': 'attach' in text_lower or 'upload' in text_lower,
            'Regulatory Compliance': any(term in text_lower for term in ['compliance', 'regulatory', 'regulation']),
            'Multi-party Agreement': any(term in text_lower for term in ['both parties', 'all parties', 'counter-sign']),
            'Financial Disclosure': any(term in text_lower for term in ['financial', 'disclosure', 'asset', 'liability']),
            'Identification Verification': any(term in text_lower for term in ['identification', 'verify', 'id']),
            'Time Sensitivity': any(term in text_lower for term in ['deadline', 'due date', 'time-sensitive']),
            'Beneficiary Designation': any(term in text_lower for term in ['beneficiary', 'designation', 'successor'])
        }
        
        # Log which drivers were detected
        detected_drivers = {}
        for driver, is_present in driver_patterns.items():
            if is_present:
                detected_drivers[driver] = True
                drivers.append(driver)
                
        logger.info(f"Detected drivers: {detected_drivers}")
        
        # If less than 3 drivers, add complexity-based generic drivers
        if len(drivers) < 3:
            if complexity_score > 70 and 'High Complexity' not in drivers:
                drivers.append('High Complexity')
            if complexity_score > 50 and 'Medium Complexity' not in drivers and len(drivers) < 3:
                drivers.append('Medium Complexity')
            if complexity_score > 30 and 'Standard Complexity' not in drivers and len(drivers) < 3:
                drivers.append('Standard Complexity')
        
        # Return top 3 drivers
        result = drivers[:3]
        logger.info(f"Key drivers: {result}")
        return result
    
    def analyze_form(self, pdf_url):
        """Main analysis function with expanded attributes and better error handling"""
        request_id = str(uuid.uuid4())
        logger.info(f"Starting analysis for URL: {pdf_url} (ID: {request_id})")
        
        # Store the URL for later use
        self.current_url = pdf_url
        
        try:
            # Download PDF with timeout and retries
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    pdf_stream = self.download_pdf(pdf_url)
                    break
                except requests.RequestException as e:
                    if attempt == max_retries - 1:
                        raise
                    logger.warning(f"Download attempt {attempt+1} failed: {str(e)}. Retrying...")
                    time.sleep(2)
            
            # Extract text with additional error handling
            try:
                text = self.extract_text_from_pdf(pdf_stream)
            except Exception as e:
                logger.error(f"Text extraction failed: {str(e)}")
                text = ""  # Continue with empty text rather than failing
            
            # If text extraction failed or returned minimal text, log the issue
            if len(text.strip()) < 50:
                logger.warning(f"Minimal text extracted ({len(text.strip())} chars), analysis may be unreliable")
            
            # Get PDF metadata
            pdf_stream.seek(0)
            reader = PyPDF2.PdfReader(pdf_stream)
            metadata = reader.metadata
            page_count = len(reader.pages)
            logger.info(f"PDF metadata: {metadata}")
            logger.info(f"Page count: {page_count}")
            
            # Basic form analysis
            field_info = self.count_form_fields(pdf_stream)
            signature_analysis = self.analyze_signatures(text)
            special_requirements = self.check_special_requirements(text)
            
            # Extract form title
            form_title = self.extract_form_title(text, metadata)
            
            # Extract entity name with enhanced method for financial institutions
            entity_name = self.extract_entity_name_financial(text, metadata, pdf_url)
            
            # Document type analysis
            doc_type = self.determine_document_type(text)
            
            # Industry classification
            industry_info = self.classify_industry(text)
            
            # Calculate complexity score
            complexity_score = self.calculate_complexity(
                text, 
                field_info, 
                page_count, 
                signature_analysis
            )
            
            # Advanced requirements analysis
            advanced_requirements = self.analyze_advanced_requirements(text)
            
            # Key drivers identification
            key_drivers = self.identify_key_drivers(text, field_info, complexity_score)
            
            # Time estimates
            signer_time = self.estimate_signer_time(field_info, complexity_score)
            processing_time = self.estimate_processing_time(field_info, complexity_score)
            
            # Compile comprehensive results
            results = {
                'url': pdf_url,
                'analysis_id': request_id,
                'timestamp': datetime.now().isoformat(),
                'entity_name': entity_name,
                'form_title': form_title,
                'document_type': doc_type.get('type', 'Unknown'),
                'document_subtype': doc_type.get('subtype', 'Unknown'),
                'industry_vertical': industry_info.get('vertical', 'Unknown'),
                'industry_subvertical': industry_info.get('subvertical', 'Unknown'),
                'complexity_score': complexity_score,
                'page_count': page_count,
                'field_count': field_info['total'],
                'text_fields': field_info['text_fields'],
                'checkboxes': field_info['checkboxes'],
                'dropdowns': field_info.get('dropdowns', 0),
                'signature_analysis': signature_analysis,
                'attachment_count': advanced_requirements.get('attachment_count', 0),
                'data_validation_count': advanced_requirements.get('validation_count', 0),
                'identification_required': advanced_requirements.get('id_required', 'No'),
                'notarization_required': special_requirements['notarization_required'],
                'witnesses_required': special_requirements['witnesses_required'],
                'third_party_involved': advanced_requirements.get('third_party', 'No'),
                'conditional_logic': special_requirements['conditional_logic'],
                'form_dependencies': advanced_requirements.get('dependencies', 'No'),
                'deadlines_present': advanced_requirements.get('deadlines', 'No'),
                'language_count': advanced_requirements.get('language_count', 1),
                'click_to_agree': advanced_requirements.get('click_to_agree', 'No'),
                'same_domain': advanced_requirements.get('same_domain', 'Yes'),
                'estimated_signer_time': signer_time,
                'estimated_processing_time': processing_time,
                'key_drivers': key_drivers,
                'special_requirements': advanced_requirements.get('special_requirements', []),
                'text_sample': text[:300].replace('\n', ' ') if len(text) > 0 else "No text extracted",
                'notes': "",
                'status': 'success'  # Explicitly set status to success
            }
            
            logger.info(f"Analysis complete for URL: {pdf_url} (ID: {request_id})")
            return results
            
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}", exc_info=True)
            # Return a partial result with error info and proper error status
            return {
                'url': pdf_url,
                'status': 'error',  # Always set status to error when there's an error
                'error_message': str(e),
                'entity_name': self.extract_entity_name_from_url(pdf_url),
                'analysis_id': request_id,
                'timestamp': datetime.now().isoformat()
            }
    
    def generate_dashboard_html(self, results_list):
        """Generate a beautiful HTML dashboard for form analysis results"""
        if not results_list or len(results_list) == 0:
            return "<p>No forms have been analyzed. Please analyze forms first.</p>"
            
        # Filter out error results to avoid skewing stats
        valid_results = [r for r in results_list if r.get('status') != 'error']
        total_forms = len(valid_results)
        
        if total_forms == 0:
            return "<p>All form analyses resulted in errors. Please try again with different forms.</p>"
            
        # Count forms requiring ID verification
        id_forms = sum(1 for r in valid_results if r.get('identification_required') == 'Yes')
        id_percent = round((id_forms / total_forms) * 100, 1) if total_forms > 0 else 0
        id_progress = int((id_forms / total_forms) * 360) if total_forms > 0 else 0
        
        # Count forms requiring notarization
        notary_forms = sum(1 for r in valid_results if r.get('notarization_required') == 'Yes')
        notary_percent = round((notary_forms / total_forms) * 100, 1) if total_forms > 0 else 0
        notary_progress = int((notary_forms / total_forms) * 360) if total_forms > 0 else 0
        
        # Count forms with dependencies
        depend_forms = sum(1 for r in valid_results if r.get('form_dependencies') == 'Yes')
        depend_percent = round((depend_forms / total_forms) * 100, 1) if total_forms > 0 else 0
        depend_progress = int((depend_forms / total_forms) * 360) if total_forms > 0 else 0
        
        # Count payment forms, conditional logic, third-party, time constraints
        payment_forms = 0
        conditional_forms = 0
        third_party_forms = 0
        time_forms = 0
        
        for form in valid_results:
            # Look for payment-related keywords in sample text
            if form.get('text_sample') and any(keyword in form.get('text_sample', '').lower() for keyword in 
                                           ['payment', 'fee', 'cost', 'charge', 'pay', 'paid']):
                payment_forms += 1
                
            # Check for conditional logic
            if form.get('conditional_logic') == 'Yes':
                conditional_forms += 1
                
            # Check for third party
            if form.get('third_party_involved') == 'Yes':
                third_party_forms += 1
                
            # Check for time constraints
            if form.get('deadlines_present') == 'Yes':
                time_forms += 1
                
        # Calculate percentages
        payment_percent = round((payment_forms / total_forms) * 100, 1) if total_forms > 0 else 0
        conditional_percent = round((conditional_forms / total_forms) * 100, 1) if total_forms > 0 else 0
        third_party_percent = round((third_party_forms / total_forms) * 100, 1) if total_forms > 0 else 0
        time_percent = round((time_forms / total_forms) * 100, 1) if total_forms > 0 else 0
        
        # Average complexity score
        avg_complexity = round(sum(r.get('complexity_score', 0) for r in valid_results) / total_forms, 1) if total_forms > 0 else 0
        
        # Get complex forms (top 10 by complexity)
        complex_forms = sorted(valid_results, key=lambda r: r.get('complexity_score', 0), reverse=True)[:10]
        
        # Count document types
        doc_types = {}
        for r in valid_results:
            doc_type = r.get('document_type', 'Unknown')
            doc_types[doc_type] = doc_types.get(doc_type, 0) + 1
            
        # Find the top 2 document types
        if len(doc_types) > 0:
            top_types = sorted(doc_types.items(), key=lambda x: x[1], reverse=True)[:2]
            cat1_name = top_types[0][0] if len(top_types) > 0 else "Unknown"
            cat1_count = top_types[0][1] if len(top_types) > 0 else 0
            cat1_percent = round((cat1_count / total_forms) * 100, 1) if total_forms > 0 else 0
            cat1_angle = round((cat1_count / total_forms) * 360, 1) if total_forms > 0 else 0
            
            cat2_name = top_types[1][0] if len(top_types) > 1 else "Other Documents"
            cat2_count = top_types[1][1] if len(top_types) > 1 else total_forms - cat1_count
            cat2_percent = round((cat2_count / total_forms) * 100, 1) if total_forms > 0 else 0
            cat2_angle = round((cat2_count / total_forms) * 360, 1) if total_forms > 0 else 0
        else:
            cat1_name = "Unknown"
            cat1_count = 0
            cat1_percent = 0
            cat1_angle = 0
            cat2_name = "Other Documents"
            cat2_count = 0
            cat2_percent = 0
            cat2_angle = 0
            
        # Generate HTML with the new template
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Form Analytics Dashboard</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');
        
        :root {{
            --primary: #4F46E5;
            --secondary: #8B5CF6;
            --accent: #F59E0B;
            --error: #EF4444;
            --success: #10B981;
            --dark: #0F172A;
            --darker: #020617;
            --light: #F8FAFC;
            --text: #CBD5E1;
            --muted: #64748B;
            --border: #1E293B;
            --card: #0F172A;
            --glow: #4F46E5;
        }}

        * {{ 
            box-sizing: border-box; 
            margin: 0; 
            padding: 0; 
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #020617 0%, #0F172A 50%, #020617 100%);
            color: var(--text);
            line-height: 1.6;
            overflow-x: hidden;
        }}

        /* Animated background */
        body::before {{
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: 
                radial-gradient(circle at 20% 50%, rgba(79, 70, 229, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 80% 80%, rgba(139, 92, 246, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 40% 20%, rgba(245, 158, 11, 0.08) 0%, transparent 50%);
            pointer-events: none;
            animation: float 20s ease-in-out infinite;
        }}

        @keyframes float {{
            0%, 100% {{ transform: translate(0, 0) scale(1); }}
            33% {{ transform: translate(-20px, -20px) scale(1.02); }}
            66% {{ transform: translate(20px, -10px) scale(0.98); }}
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 3rem 2rem;
            position: relative;
            z-index: 1;
        }}

        /* Header */
        header {{
            background: linear-gradient(135deg, rgba(79, 70, 229, 0.1) 0%, rgba(139, 92, 246, 0.05) 100%);
            border: 1px solid var(--border);
            border-radius: 24px;
            padding: 3rem;
            text-align: center;
            margin-bottom: 3rem;
            position: relative;
            overflow: hidden;
        }}

        header::before {{
            content: '';
            position: absolute;
            top: -50%;
            right: -10%;
            width: 500px;
            height: 500px;
            background: radial-gradient(circle, var(--glow) 0%, transparent 70%);
            opacity: 0.1;
            animation: pulse 4s ease-in-out infinite;
        }}

        @keyframes pulse {{
            0%, 100% {{ transform: scale(1); opacity: 0.1; }}
            50% {{ transform: scale(1.1); opacity: 0.2; }}
        }}

        h1 {{
            font-size: 3rem;
            font-weight: 800;
            margin-bottom: 1rem;
            background: linear-gradient(135deg, var(--light) 0%, var(--text) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .subtitle {{
            font-size: 1.25rem;
            color: var(--muted);
        }}

        /* Style for the CX-facing report button shown in the dashboard header */
        .cx-report-button {{
            display: inline-block;
            margin-top: 1rem;
            padding: 0.75rem 1.5rem;
            background: var(--secondary);
            color: var(--light);
            border-radius: 8px;
            font-weight: 600;
            text-decoration: none;
            transition: background 0.3s;
        }}
        .cx-report-button:hover {{
            background: var(--primary);
        }}

        /* Icon styles */
        .icon {{
            width: 24px;
            height: 24px;
            fill: currentColor;
            margin-right: 0.5rem;
        }}

        .large-icon {{
            width: 48px;
            height: 48px;
            margin-bottom: 1rem;
        }}

        /* Sections */
        section {{
            background: linear-gradient(135deg, rgba(15, 23, 42, 0.6) 0%, rgba(30, 41, 59, 0.3) 100%);
            border: 1px solid var(--border);
            border-radius: 24px;
            padding: 2.5rem;
            margin-bottom: 2rem;
            position: relative;
        }}

        h2 {{
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 1.5rem;
            color: var(--light);
            padding-bottom: 1rem;
            border-bottom: 2px solid var(--border);
            display: flex;
            align-items: center;
        }}

        h3 {{
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--primary);
            margin: 1.5rem 0 1rem;
            display: flex;
            align-items: center;
        }}

        /* Executive Priority Cards */
        .exec-priority {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}

        .priority-card {{
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(15, 23, 42, 0.95) 100%);
            border: 2px solid var(--error);
            border-radius: 16px;
            padding: 1.5rem;
            text-align: center;
            position: relative;
            overflow: hidden;
        }}

        .priority-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(135deg, transparent 0%, rgba(239, 68, 68, 0.1) 100%);
            pointer-events: none;
        }}

        .priority-metric {{
            font-size: 3rem;
            font-weight: 800;
            background: linear-gradient(135deg, var(--error) 0%, var(--accent) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            position: relative;
            z-index: 1;
        }}

        .priority-label {{
            color: var(--light);
            font-weight: 600;
            margin-top: 0.5rem;
            font-size: 1.1rem;
            position: relative;
            z-index: 1;
        }}

        .priority-detail {{
            color: var(--muted);
            font-size: 0.875rem;
            margin-top: 0.5rem;
            position: relative;
            z-index: 1;
        }}

        /* Circular Progress Indicators */
        .circular-progress {{
            position: relative;
            width: 120px;
            height: 120px;
            margin: 0 auto 1rem;
        }}

        .progress-circle {{
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background: conic-gradient(var(--error) 0deg, var(--error) var(--progress), rgba(30, 41, 59, 0.3) var(--progress), rgba(30, 41, 59, 0.3) 360deg);
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
        }}

        .progress-circle::before {{
            content: '';
            width: 80px;
            height: 80px;
            background: var(--dark);
            border-radius: 50%;
            position: absolute;
        }}

        .progress-text {{
            position: absolute;
            font-size: 1.5rem;
            font-weight: 800;
            color: var(--error);
            z-index: 1;
        }}

        /* Workflow Blockers Grid */
        .blockers-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
        }}

        .blocker-card {{
            background: linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(30, 41, 59, 0.4) 100%);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.5rem;
            text-align: center;
            transition: all 0.3s ease;
            position: relative;
        }}

        .blocker-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--error), var(--accent));
            border-radius: 16px 16px 0 0;
        }}

        .blocker-card:hover {{
            transform: translateY(-4px);
            box-shadow: 0 15px 30px rgba(0, 0, 0, 0.3);
            border-color: var(--error);
        }}

        .blocker-value {{
            font-size: 2.5rem;
            font-weight: 800;
            color: var(--error);
            margin-bottom: 0.25rem;
        }}

        .blocker-percent {{
            font-size: 1.1rem;
            font-weight: 600;
            background: linear-gradient(135deg, var(--accent) 0%, var(--error) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}

        .blocker-label {{
            font-size: 0.875rem;
            color: var(--text);
            font-weight: 500;
        }}

        /* Progress bars for blockers */
        .blocker-bar {{
            width: 100%;
            height: 6px;
            background: rgba(30, 41, 59, 0.5);
            border-radius: 3px;
            margin-top: 1rem;
            overflow: hidden;
        }}

        .blocker-fill {{
            height: 100%;
            background: linear-gradient(90deg, var(--error), var(--accent));
            border-radius: 3px;
            transition: width 0.5s ease;
        }}

        /* Complexity Gauge */
        .complexity-gauge {{
            display: flex;
            flex-direction: column;
            align-items: center;
            margin: 2rem 0;
            gap: 1rem;
        }}

        .gauge-container {{
            position: relative;
            width: 240px;
            height: 120px;
        }}

        .gauge-bg {{
            width: 240px;
            height: 120px;
            border-radius: 120px 120px 0 0;
            background: conic-gradient(from 180deg at 50% 100%, var(--success) 0deg, var(--success) 60deg, var(--accent) 60deg, var(--accent) 120deg, var(--error) 120deg, var(--error) 180deg);
            position: relative;
        }}

        .gauge-bg::before {{
            content: '';
            position: absolute;
            width: 180px;
            height: 90px;
            background: var(--dark);
            border-radius: 90px 90px 0 0;
            top: 15px;
            left: 30px;
        }}

        .gauge-needle {{
            position: absolute;
            width: 3px;
            height: 85px;
            background: white;
            left: 50%;
            bottom: 0;
            transform-origin: bottom center;
            transform: translateX(-50%) rotate({min(avg_complexity / 100 * 180 - 90, 90)}deg);
            border-radius: 2px;
            box-shadow: 0 0 10px rgba(255, 255, 255, 0.5);
        }}

        .gauge-value {{
            position: absolute;
            bottom: 25px;
            left: 50%;
            transform: translateX(-50%);
            font-size: 1.8rem;
            font-weight: 800;
            color: var(--accent);
        }}

        .gauge-labels {{
            display: flex;
            justify-content: space-between;
            width: 240px;
            font-size: 0.75rem;
            color: var(--muted);
            margin-top: 0.5rem;
        }}

        .gauge-scale {{
            display: flex;
            justify-content: center;
            gap: 2rem;
            margin-top: 1rem;
            font-size: 0.875rem;
        }}

        .scale-item {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        .scale-dot {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }}

        .scale-dot.low {{ background: var(--success); }}
        .scale-dot.medium {{ background: var(--accent); }}
        .scale-dot.high {{ background: var(--error); }}

        /* Complex Forms Table */
        .complex-forms-table {{
            background: rgba(15, 23, 42, 0.8);
            border-radius: 16px;
            padding: 2rem;
            margin: 2rem 0;
            overflow-x: auto;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th {{
            background: linear-gradient(135deg, var(--darker) 0%, var(--dark) 100%);
            padding: 1.25rem;
            text-align: left;
            color: var(--light);
            font-weight: 600;
            border-bottom: 2px solid var(--border);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        td {{
            padding: 1.25rem;
            border-bottom: 1px solid var(--border);
            color: var(--text);
            vertical-align: middle;
        }}

        tr:hover {{
            background: rgba(79, 70, 229, 0.05);
        }}

        td:first-child {{
            font-weight: 600;
            color: var(--light);
            width: 25%;
        }}

        td:nth-child(2) {{
            width: 15%;
        }}

        td:nth-child(3), td:nth-child(4) {{
            width: 8%;
            text-align: center;
        }}

        td:last-child {{
            width: 44%;
            line-height: 1.6;
        }}

        .complexity-badge {{
            background: linear-gradient(135deg, var(--error), var(--accent));
            color: white;
            padding: 0.4rem 0.8rem;
            border-radius: 20px;
            font-size: 0.875rem;
            font-weight: 700;
            display: inline-block;
            margin-bottom: 0.5rem;
            min-width: 40px;
            text-align: center;
        }}

        /* Mini bar charts in table */
        .mini-bar {{
            display: block;
            width: 80px;
            height: 6px;
            background: rgba(30, 41, 59, 0.5);
            border-radius: 3px;
            overflow: hidden;
            margin: 0;
        }}

        .mini-bar-fill {{
            height: 100%;
            background: linear-gradient(90deg, var(--error), var(--accent));
            border-radius: 3px;
            transition: width 0.5s ease;
        }}

        /* Key drivers styling */
        td:last-child strong {{
            color: var(--error);
            font-weight: 700;
        }}

        /* Form Categories */
        .categories-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1.5rem;
            margin: 2rem 0;
        }}

        .category-card {{
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.5rem;
            position: relative;
        }}

        .category-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }}

        .category-name {{
            color: var(--light);
            font-weight: 600;
            font-size: 1.1rem;
            display: flex;
            align-items: center;
        }}

        .category-count {{
            background: var(--secondary);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.875rem;
            font-weight: 600;
        }}

        /* Donut chart style */
        .category-visual {{
            display: flex;
            align-items: center;
            gap: 1.5rem;
        }}

        .donut-chart {{
            width: 80px;
            height: 80px;
            border-radius: 50%;
            background: conic-gradient(var(--secondary) 0deg, var(--secondary) var(--angle), rgba(30, 41, 59, 0.3) var(--angle), rgba(30, 41, 59, 0.3) 360deg);
            position: relative;
            display: flex;
            align-items: center;
            justify-content: center;
        }}

        .donut-chart::before {{
            content: '';
            width: 40px;
            height: 40px;
            background: var(--dark);
            border-radius: 50%;
            position: absolute;
        }}

        .donut-text {{
            position: absolute;
            font-size: 0.875rem;
            font-weight: 700;
            color: var(--secondary);
            z-index: 1;
        }}

        /* Automation Opportunities */
        .opportunities-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
        }}

        .opportunity-card {{
            background: linear-gradient(135deg, rgba(79, 70, 229, 0.1) 0%, rgba(15, 23, 42, 0.9) 100%);
            border: 2px solid var(--primary);
            border-radius: 16px;
            padding: 1.5rem;
            position: relative;
            transition: all 0.3s ease;
        }}

        .opportunity-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(79, 70, 229, 0.3);
        }}

        .opportunity-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }}

        .opportunity-title {{
            color: var(--light);
            font-weight: 600;
            font-size: 1.1rem;
            display: flex;
            align-items: center;
        }}

        .opportunity-impact {{
            background: var(--primary);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.875rem;
            font-weight: 600;
        }}

        .opportunity-desc {{
            color: var(--text);
            font-size: 0.875rem;
            margin-bottom: 1rem;
        }}

        .opportunity-metrics {{
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }}

        .metric-tag {{
            background: rgba(79, 70, 229, 0.2);
            border: 1px solid var(--primary);
            padding: 0.25rem 0.5rem;
            border-radius: 8px;
            font-size: 0.75rem;
            color: var(--primary);
        }}

        /* Visual impact indicators */
        .impact-indicator {{
            display: flex;
            align-items: center;
            margin-top: 1rem;
            gap: 0.5rem;
        }}

        .impact-dot {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: var(--primary);
            animation: pulse-dot 2s ease-in-out infinite;
        }}

        @keyframes pulse-dot {{
            0%, 100% {{ opacity: 1; transform: scale(1); }}
            50% {{ opacity: 0.7; transform: scale(1.2); }}
        }}

        /* Footer */
        footer {{
            text-align: center;
            padding: 2rem;
            color: var(--muted);
            font-size: 0.875rem;
            border-top: 1px solid var(--border);
            margin-top: 3rem;
        }}

        /* Responsive */
        @media (max-width: 768px) {{
            h1 {{ font-size: 2rem; }}
            .exec-priority {{ grid-template-columns: 1fr; }}
            .blockers-grid {{ grid-template-columns: repeat(2, 1fr); }}
            .categories-grid {{ grid-template-columns: 1fr; }}
            .opportunities-grid {{ grid-template-columns: 1fr; }}
            .category-visual {{ flex-direction: column; }}
        }}
        
        /* Error count summary */
        .error-summary {{
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid var(--error);
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 2rem;
            display: flex;
            align-items: center;
            gap: 1rem;
        }}
        
        .error-count {{
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--error);
        }}
        
        .error-message {{
            color: var(--text);
            font-size: 0.875rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Form Analytics Dashboard</h1>
            <p class="subtitle">Enterprise Form Analysis & Digital Transformation Insights</p>
            <!-- Button linking to the CX-facing report. When clicked, it navigates to the /cx_report endpoint -->
            <a href="/cx_report" class="cx-report-button">Generate CX Facing Report</a>
        </header>
        
        <!-- Error summary if there were errors -->
        {f'<div class="error-summary"><div class="error-count">{len(results_list) - total_forms}</div><div class="error-message">forms failed to analyze due to rate limiting or other errors. Results below are based on successfully analyzed forms only.</div></div>' if len(results_list) - total_forms > 0 else ''}

        <!-- Executive Priority Section -->
        <section>
            <h2>
                <svg class="icon" viewBox="0 0 24 24">
                    <path d="M12 9a3.02 3.02 0 0 0-3 3c0 1.642 1.358 3 3 3 1.641 0 3-1.358 3-3 0-1.641-1.359-3-3-3z"/>
                    <path d="M12 5c-7.633 0-9.927 6.617-9.948 6.684L1.946 12l.105.316C2.073 12.383 4.367 19 12 19s9.927-6.617 9.948-6.684L22.054 12l-.105-.316C21.927 11.617 19.633 5 12 5zm0 12c-2.757 0-5-2.243-5-5s2.243-5 5-5 5 2.243 5 5-2.243 5-5 5z"/>
                </svg>
                Critical Business Impact
            </h2>
            <div class="exec-priority">
                <div class="priority-card">
                    <div class="circular-progress">
                        <div class="progress-circle" style="--progress: {id_progress}deg">
                            <div class="progress-text">{id_forms}</div>
                        </div>
                    </div>
                    <div class="priority-label">Forms Requiring Identity Verification</div>
                    <div class="priority-detail">{id_percent}% of all forms require identity verification</div>
                </div>
                <div class="priority-card">
                    <div class="circular-progress">
                        <div class="progress-circle" style="--progress: {notary_progress}deg">
                            <div class="progress-text">{notary_forms}</div>
                        </div>
                    </div>
                    <div class="priority-label">Forms Requiring Notarization</div>
                    <div class="priority-detail">{notary_percent}% require physical presence & notary</div>
                </div>
                <div class="priority-card">
                    <div class="circular-progress">
                        <div class="progress-circle" style="--progress: {depend_progress}deg">
                            <div class="progress-text">{depend_forms}</div>
                        </div>
                    </div>
                    <div class="priority-label">Forms with Dependencies</div>
                    <div class="priority-detail">{depend_percent}% linked to other forms/processes</div>
                </div>
            </div>
        </section>

        <!-- Workflow Blockers -->
        <section>
            <h2>
                <svg class="icon" viewBox="0 0 24 24">
                    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
                </svg>
                Process Optimization Barriers
            </h2>
            <div class="blockers-grid">
                <div class="blocker-card">
                    <div class="blocker-value">{payment_forms}</div>
                    <div class="blocker-percent">{payment_percent}%</div>
                    <div class="blocker-label">Payment Processing</div>
                    <div class="blocker-bar">
                        <div class="blocker-fill" style="width: {payment_percent}%"></div>
                    </div>
                </div>
                <div class="blocker-card">
                    <div class="blocker-value">{conditional_forms}</div>
                    <div class="blocker-percent">{conditional_percent}%</div>
                    <div class="blocker-label">Conditional Logic</div>
                    <div class="blocker-bar">
                        <div class="blocker-fill" style="width: {conditional_percent}%"></div>
                    </div>
                </div>
                <div class="blocker-card">
                    <div class="blocker-value">{third_party_forms}</div>
                    <div class="blocker-percent">{third_party_percent}%</div>
                    <div class="blocker-label">Third Party Involvement</div>
                    <div class="blocker-bar">
                        <div class="blocker-fill" style="width: {third_party_percent}%"></div>
                    </div>
                </div>
                <div class="blocker-card">
                    <div class="blocker-value">{time_forms}</div>
                    <div class="blocker-percent">{time_percent}%</div>
                    <div class="blocker-label">Time Constraints</div>
                    <div class="blocker-bar">
                        <div class="blocker-fill" style="width: {time_percent}%"></div>
                    </div>
                </div>
            </div>

            <h3>
                <svg class="icon" viewBox="0 0 24 24">
                    <path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zM9 17H7v-7h2v7zm4 0h-2V7h2v10zm4 0h-2v-4h2v4z"/>
                </svg>
                Form Complexity Distribution
            </h3>
            <div class="complexity-gauge">
                <div class="gauge-container">
                    <div class="gauge-bg">
                        <div class="gauge-needle"></div>
                        <div class="gauge-value">{avg_complexity}</div>
                    </div>
                    <div class="gauge-labels">
                        <span>0</span>
                        <span>25</span>
                        <span>50</span>
                        <span>75</span>
                        <span>100</span>
                    </div>
                </div>
                <div class="gauge-scale">
                    <div class="scale-item">
                        <div class="scale-dot low"></div>
                        <span>Low (0-33)</span>
                    </div>
                    <div class="scale-item">
                        <div class="scale-dot medium"></div>
                        <span>Medium (34-66)</span>
                    </div>
                    <div class="scale-item">
                        <div class="scale-dot high"></div>
                        <span>High (67-100)</span>
                    </div>
                </div>
            </div>
            <p style="color: var(--text); text-align: center; margin-top: 1rem;">{avg_complexity}% average complexity score, indicating significant automation opportunities</p>
        </section>

        <!-- Most Complex Forms -->
        <section>
            <h2>
                <svg class="icon" viewBox="0 0 24 24">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                    <polyline points="14,2 14,8 20,8"/>
                    <line x1="16" y1="13" x2="8" y2="13"/>
                    <line x1="16" y1="17" x2="8" y2="17"/>
                    <polyline points="10,9 9,9 8,9"/>
                </svg>
                Top {len(complex_forms)} Most Complex Forms
            </h2>
            <div class="complex-forms-table">
                <table>
                    <thead>
                        <tr>
                            <th>Form Title</th>
                            <th>Complexity</th>
                            <th>Pages</th>
                            <th>Fields</th>
                            <th>Key Drivers & Special Requirements</th>
                        </tr>
                    </thead>
                    <tbody>
"""

        # Add table rows for complex forms
        for form in complex_forms:
            complexity = form.get('complexity_score', 0)
            pages = form.get('page_count', 0)
            fields = form.get('field_count', 0)
            title = form.get('form_title', 'Unknown Form')
            
            # Get key drivers
            drivers = form.get('key_drivers', [])
            driver_text = ""
            if len(drivers) > 0:
                driver_text = f"<strong>{drivers[0]}</strong>"
                if len(drivers) > 1:
                    requirements_list = []
                    for req in form.get('special_requirements', [])[:3]:
                        requirements_list.append(req)
                    driver_text += " + " + ", ".join(requirements_list) if requirements_list else ""
            
            html += f"""
                        <tr>
                            <td>{title}</td>
                            <td>
                                <span class="complexity-badge">{int(complexity)}</span>
                                <div class="mini-bar">
                                    <div class="mini-bar-fill" style="width: {complexity}%"></div>
                                </div>
                            </td>
                            <td>{pages}</td>
                            <td>{fields}</td>
                            <td>{driver_text}</td>
                        </tr>
"""
        
        # Continue with the HTML
        html += f"""
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Form Categories -->
        <section>
            <h2>
                <svg class="icon" viewBox="0 0 24 24">
                    <path d="M10 4H4c-1.11 0-2 .89-2 2v12c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V8c0-1.11-.89-2-2-2h-8l-2-2z"/>
                </svg>
                Form Categories Distribution
            </h2>
            <div class="categories-grid">
                <div class="category-card">
                    <div class="category-header">
                        <span class="category-name">
                            <svg class="icon" viewBox="0 0 24 24">
                                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                                <polyline points="14,2 14,8 20,8"/>
                            </svg>
                            {cat1_name}
                        </span>
                        <span class="category-count">{cat1_count} forms</span>
                    </div>
                    <div class="category-visual">
                        <div class="donut-chart" style="--angle: {cat1_angle}deg">
                            <div class="donut-text">{cat1_percent}%</div>
                        </div>
                        <div style="color: var(--text); font-size: 0.875rem;">
                            {cat1_name} category forms with high complexity requiring compliance documentation
                        </div>
                    </div>
                </div>
                <div class="category-card">
                    <div class="category-header">
                        <span class="category-name">
                            <svg class="icon" viewBox="0 0 24 24">
                                <path d="M9 11H3v4h6v-4zM21 11h-6v4h6v-4zM15 7H9v4h6V7z"/>
                            </svg>
                            {cat2_name}
                        </span>
                        <span class="category-count">{cat2_count} forms</span>
                    </div>
                    <div class="category-visual">
                        <div class="donut-chart" style="--angle: {cat2_angle}deg">
                            <div class="donut-text">{cat2_percent}%</div>
                        </div>
                        <div style="color: var(--text); font-size: 0.875rem;">
                            Standard operational forms with moderate complexity requirements
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- Automation Opportunities -->
        <section>
            <h2>
                <svg class="icon" viewBox="0 0 24 24">
                    <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/>
                </svg>
                Digital Transformation Opportunities
            </h2>
            <div class="opportunities-grid">
                <div class="opportunity-card">
                    <div class="opportunity-header">
                        <span class="opportunity-title">
                            <svg class="icon" viewBox="0 0 24 24">
                                <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                            </svg>
                            Remote Notarization
                        </span>
                        <span class="opportunity-impact">{notary_forms} forms</span>
                    </div>
                    <div class="opportunity-desc">
                        Digital notarization to eliminate physical presence requirements for {notary_percent}% of forms
                    </div>
                    <div class="opportunity-metrics">
                        <span class="metric-tag">Time savings: 2-3 days</span>
                        <span class="metric-tag">Reduces abandonment</span>
                    </div>
                    <div class="impact-indicator">
                        <div class="impact-dot"></div>
                        <span style="font-size: 0.875rem; color: var(--primary);">High Impact Opportunity</span>
                    </div>
                </div>

                <div class="opportunity-card">
                    <div class="opportunity-header">
                        <span class="opportunity-title">
                            <svg class="icon" viewBox="0 0 24 24">
                                <path d="M13 3a9 9 0 0 0-9 9H1l3.89 3.89.07.14L9 12H6c0-3.87 3.13-7 7-7s7 3.13 7 7-3.13 7-7 7c-1.93 0-3.68-.79-4.94-2.06l-1.42 1.42A8.954 8.954 0 0 0 13 21a9 9 0 0 0 0-18z"/>
                            </svg>
                            Dynamic Form Logic
                        </span>
                        <span class="opportunity-impact">{conditional_forms} forms</span>
                    </div>
                    <div class="opportunity-desc">
                        Adaptive forms that display only relevant fields based on previous answers
                    </div>
                    <div class="opportunity-metrics">
                        <span class="metric-tag">{conditional_percent}% of forms</span>
                        <span class="metric-tag">90% error reduction</span>
                    </div>
                    <div class="impact-indicator">
                        <div class="impact-dot"></div>
                        <span style="font-size: 0.875rem; color: var(--primary);">High Impact Opportunity</span>
                    </div>
                </div>

                <div class="opportunity-card">
                    <div class="opportunity-header">
                        <span class="opportunity-title">
                            <svg class="icon" viewBox="0 0 24 24">
                                <path d="M4 6h16v2H4V6zM4 11h16v2H4v-2zM4 16h16v2H4v-2z"/>
                            </svg>
                            Workflow Automation
                        </span>
                        <span class="opportunity-impact">{depend_forms} forms</span>
                    </div>
                    <div class="opportunity-desc">
                        Automated sequencing for forms with dependencies to ensure proper completion
                    </div>
                    <div class="opportunity-metrics">
                        <span class="metric-tag">{depend_percent}% of forms</span>
                        <span class="metric-tag">Eliminates rework</span>
                    </div>
                    <div class="impact-indicator">
                        <div class="impact-dot"></div>
                        <span style="font-size: 0.875rem; color: var(--primary);">High Impact Opportunity</span>
                    </div>
                </div>

                <div class="opportunity-card">
                    <div class="opportunity-header">
                        <span class="opportunity-title">
                            <svg class="icon" viewBox="0 0 24 24">
                                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
                            </svg>
                            Digital ID Verification
                        </span>
                        <span class="opportunity-impact">{id_forms} forms</span>
                    </div>
                    <div class="opportunity-desc">
                        API-based identity verification to replace manual ID checks for {id_percent}% of forms
                    </div>
                    <div class="opportunity-metrics">
                        <span class="metric-tag">Instant verification</span>
                        <span class="metric-tag">Enhanced security</span>
                    </div>
                    <div class="impact-indicator">
                        <div class="impact-dot"></div>
                        <span style="font-size: 0.875rem; color: var(--primary);">Highest Impact Opportunity</span>
                    </div>
                </div>

                <div class="opportunity-card">
                    <div class="opportunity-header">
                        <span class="opportunity-title">
                            <svg class="icon" viewBox="0 0 24 24">
                                <path d="M20 4H4c-1.11 0-2 .89-2 2v12c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4V8h16v10z"/>
                            </svg>
                            Integrated Payments
                        </span>
                        <span class="opportunity-impact">{payment_forms} forms</span>
                    </div>
                    <div class="opportunity-desc">
                        Seamless payment processing for forms requiring fees, eliminating separate transactions
                    </div>
                    <div class="opportunity-metrics">
                        <span class="metric-tag">{payment_percent}% of forms</span>
                        <span class="metric-tag">Unified workflow</span>
                    </div>
                    <div class="impact-indicator">
                        <div class="impact-dot"></div>
                        <span style="font-size: 0.875rem; color: var(--primary);">High Impact Opportunity</span>
                    </div>
                </div>

                <div class="opportunity-card">
                    <div class="opportunity-header">
                        <span class="opportunity-title">
                            <svg class="icon" viewBox="0 0 24 24">
                                <circle cx="12" cy="12" r="10"/>
                                <polyline points="12,6 12,12 16,14"/>
                            </svg>
                            Deadline Management
                        </span>
                        <span class="opportunity-impact">{time_forms} forms</span>
                    </div>
                    <div class="opportunity-desc">
                        Automated reminders and escalations for time-sensitive forms ({time_percent}% of library)
                    </div>
                    <div class="opportunity-metrics">
                        <span class="metric-tag">Prevents expiration</span>
                        <span class="metric-tag">Automatic tracking</span>
                    </div>
                    <div class="impact-indicator">
                        <div class="impact-dot"></div>
                        <span style="font-size: 0.875rem; color: var(--primary);">Medium Impact Opportunity</span>
                    </div>
                </div>
            </div>
        </section>

        <footer>
            <p>Form Analytics Dashboard | Enterprise Form Library ({total_forms} forms) | Generated: {datetime.now().strftime('%B %d, %Y')}</p>
        </footer>
    </div>
</body>
</html>
"""

        return html

class WebCrawler:
    def __init__(self, base_url, include_subpages=True, max_depth=2, max_pdfs=10, enable_js=False):
        self.base_url = base_url
        self.include_subpages = include_subpages
        self.max_depth = max_depth
        self.max_pdfs = max_pdfs
        self.enable_js = enable_js
        
        # Extract domain for same-domain checking
        parsed = urlparse(base_url)
        self.domain = parsed.netloc
        
        # Track visited URLs to avoid loops
        self.visited = set()
        self.pdf_urls = []
        self.pages_crawled = 0
        
        # For JavaScript rendering
        self.playwright = None
        self.browser = None
        
        # For rate limiting
        self.domain_requests = {}
    
    def _is_same_domain(self, url):
        """Check if URL is on the same domain as base_url"""
        parsed = urlparse(url)
        return parsed.netloc == self.domain
    
    def _is_pdf_url(self, url):
        """Check if URL likely points to a PDF"""
        # Check file extension
        if url.lower().endswith('.pdf'):
            return True
        
        # Check for PDF in path
        if '/pdf/' in url.lower() or 'document' in url.lower():
            return True
            
        # Check for PDF in query parameters
        if 'pdf=' in url.lower() or 'file=pdf' in url.lower() or 'format=pdf' in url.lower():
            return True
            
        return False
    
    async def _init_playwright(self):
        """Initialize Playwright for JavaScript rendering"""
        try:
            from playwright.async_api import async_playwright
            
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(headless=True)
            return True
        except ImportError:
            logger.error("Playwright not installed. Run: pip install playwright")
            return False
        except Exception as e:
            logger.error(f"Failed to initialize Playwright: {str(e)}")
            return False
    
    async def _close_playwright(self):
        """Close Playwright browser"""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
    
    async def _get_page_with_js(self, url):
        """Get page content with JavaScript rendering"""
        if not self.browser:
            success = await self._init_playwright()
            if not success:
                return None, []
            
        # Check rate limit for this domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        allowed, wait_time = check_rate_limit(domain)
        if not allowed:
            logger.warning(f"Rate limit exceeded for {domain}, waiting {wait_time:.1f} seconds")
            await asyncio.sleep(wait_time)
            
        page = await self.browser.new_page()
        try:
            await page.goto(url, wait_until='networkidle', timeout=30000)
            
            # Look for PDF links in onclick handlers and data attributes
            await page.evaluate('''() => {
                // Click handlers that might reveal PDF links
                document.querySelectorAll('a[onclick], button[onclick]').forEach(el => {
                    if (el.onclick && el.onclick.toString().includes('pdf')) {
                        try { el.click(); } catch (e) {}
                    }
                });
                
                // Expand accordions or tabs that might contain PDF links
                document.querySelectorAll('.accordion, .tab, .collapse').forEach(el => {
                    try { 
                        el.classList.add('active', 'show', 'open');
                        el.style.display = 'block';
                    } catch (e) {}
                });
            }''')
            
            # Wait for any dynamically loaded content
            await page.wait_for_timeout(2000)
            
            content = await page.content()
            
            # Also check for PDF downloads in network events
            pdf_resources = []
            page.on('response', lambda response: 
                pdf_resources.append(response.url) if response.headers.get('content-type', '').lower().find('pdf') != -1 else None
            )
            
            await page.close()
            return content, pdf_resources
        except Exception as e:
            logger.error(f"Error rendering page with JavaScript: {str(e)}")
            await page.close()
            return None, []
    
    def _get_page_without_js(self, url):
        """Get page content without JavaScript rendering with better error handling"""
        # Check rate limit for this domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        allowed, wait_time = check_rate_limit(domain)
        if not allowed:
            logger.warning(f"Rate limit exceeded for {domain}, waiting {wait_time:.1f} seconds")
            time.sleep(wait_time)
        
        # Randomize user agent
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
        ]
        
        headers = {
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
        }
        
        # Add retry logic
        max_retries = 3
        retry_delay = 1
        
        for attempt in range(max_retries):
            try:
                response = requests.get(url, headers=headers, timeout=30)
                
                # Handle rate limiting (429)
                if response.status_code == 429:
                    rate_limit_exceeded(domain)
                    
                    # Check for Retry-After header
                    retry_after = response.headers.get('Retry-After')
                    if retry_after:
                        try:
                            wait_seconds = int(retry_after)
                        except ValueError:
                            # Retry-After can also be a HTTP date
                            wait_seconds = 30  # Default if we can't parse it
                    else:
                        # Exponential backoff
                        wait_seconds = retry_delay * (2 ** attempt)
                    
                    if attempt < max_retries - 1:
                        logger.warning(f"Rate limited (429). Waiting {wait_seconds} seconds before retry.")
                        time.sleep(wait_seconds)
                        continue
                    else:
                        return None, []
                
                # Handle other non-200 responses
                if response.status_code != 200:
                    if attempt < max_retries - 1:
                        wait_seconds = retry_delay * (2 ** attempt)
                        logger.warning(f"Request failed with status {response.status_code}. Waiting {wait_seconds} seconds before retry.")
                        time.sleep(wait_seconds)
                        continue
                    else:
                        return None, []
                
                return response.text, []
            except requests.exceptions.RequestException as e:
                logger.warning(f"Attempt {attempt+1} failed for URL {url}: {str(e)}")
                if attempt == max_retries - 1:
                    logger.error(f"All {max_retries} attempts failed for URL {url}")
                    # Return empty content instead of failing
                    return None, []
                # Exponential backoff
                wait_seconds = retry_delay * (2 ** attempt)
                time.sleep(wait_seconds)
    
    def _check_robots_txt(self, url):
        """Simple robots.txt check without reppy dependency"""
        try:
            parsed = urlparse(url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            
            # Check rate limit for this domain
            domain = parsed.netloc
            allowed, wait_time = check_rate_limit(domain)
            if not allowed:
                logger.warning(f"Rate limit exceeded for {domain} robots.txt, waiting {wait_time:.1f} seconds")
                time.sleep(wait_time)
            
            response = requests.get(robots_url, timeout=10)
            
            if response.status_code == 200:
                robot_content = response.text.lower()
                user_agent_sections = robot_content.split("user-agent:")
                
                # Check rules for our user agent or any user agent
                for section in user_agent_sections:
                    if "python" in section or "*" in section:
                        # Check if the URL path is disallowed
                        for line in section.split('\n'):
                            if line.strip().startswith('disallow:'):
                                disallow_path = line.split(':', 1)[1].strip()
                                if disallow_path and parsed.path.startswith(disallow_path):
                                    return False
            
            return True
        except Exception:
            # If we can't fetch or parse robots.txt, we'll proceed anyway
            return True
    
    def _extract_links_and_pdfs(self, url, html_content):
        """Extract links and PDF URLs from HTML content"""
        if not html_content:
            return [], []
        
        links = []
        pdfs = []
        
        try:
            soup = BeautifulSoup(html_content, 'lxml')
            
            # Extract all links
            for a_tag in soup.find_all('a', href=True):
                link = a_tag['href'].strip()
                
                # Skip empty links, anchors, javascript, and mailto
                if not link or link.startswith('#') or link.startswith('javascript:') or link.startswith('mailto:'):
                    continue
                
                # Convert relative URLs to absolute
                full_url = urljoin(url, link)
                
                # Check if it's a PDF
                if self._is_pdf_url(full_url):
                    pdfs.append(full_url)
                # Only add links from the same domain if we're not including subpages
                elif self.include_subpages or self._is_same_domain(full_url):
                    links.append(full_url)
            
            # Also look for PDF links in other elements
            pdf_patterns = [
                r'href=["\']([^"\']*\.pdf)["\']',
                r'data-url=["\']([^"\']*\.pdf)["\']',
                r'data-file=["\']([^"\']*\.pdf)["\']',
                r'(https?://[^"\']+\.pdf)',
                r'(/[^"\']+\.pdf)'
            ]
            
            for pattern in pdf_patterns:
                for match in re.finditer(pattern, html_content, re.IGNORECASE):
                    pdf_url = match.group(1)
                    if pdf_url:
                        full_pdf_url = urljoin(url, pdf_url)
                        pdfs.append(full_pdf_url)
            
        except Exception as e:
            logger.error(f"Error parsing HTML: {str(e)}")
        
        # Remove duplicates
        return list(set(links)), list(set(pdfs))
    
    async def _crawl_with_js(self):
        """Crawl with JavaScript rendering enabled"""
        urls_to_visit = [(self.base_url, 0)]  # (url, depth)
        
        while urls_to_visit and len(self.pdf_urls) < self.max_pdfs and self.pages_crawled < 100:
            url, depth = urls_to_visit.pop(0)
            
            # Skip if already visited or exceeds max depth
            if url in self.visited or depth > self.max_depth:
                continue
            
            # Check robots.txt
            if not self._check_robots_txt(url):
                logger.info(f"Skipping {url} (disallowed by robots.txt)")
                continue
            
            logger.info(f"Crawling {url} (depth: {depth})")
            self.visited.add(url)
            self.pages_crawled += 1
            
            # Get page content with JavaScript rendering
            html_content, js_pdfs = await self._get_page_with_js(url)
            
            if html_content:
                # Extract links and PDFs
                links, pdfs = self._extract_links_and_pdfs(url, html_content)
                
                # Add JavaScript-discovered PDFs
                pdfs.extend(js_pdfs)
                
                # Add found PDFs
                for pdf_url in pdfs:
                    if pdf_url not in self.pdf_urls and len(self.pdf_urls) < self.max_pdfs:
                        logger.info(f"Found PDF: {pdf_url}")
                        self.pdf_urls.append(pdf_url)
                
                # Add links to visit
            # Add links to visit
                if depth < self.max_depth:
                    for link in links:
                        if link not in self.visited:
                            urls_to_visit.append((link, depth + 1))
        
        await self._close_playwright()
    
    def _crawl_without_js(self):
        """Crawl without JavaScript rendering"""
        urls_to_visit = [(self.base_url, 0)]  # (url, depth)
        
        while urls_to_visit and len(self.pdf_urls) < self.max_pdfs and self.pages_crawled < 100:
            url, depth = urls_to_visit.pop(0)
            
            # Skip if already visited or exceeds max depth
            if url in self.visited or depth > self.max_depth:
                continue
            
            # Check robots.txt
            if not self._check_robots_txt(url):
                logger.info(f"Skipping {url} (disallowed by robots.txt)")
                continue
            
            logger.info(f"Crawling {url} (depth: {depth})")
            self.visited.add(url)
            self.pages_crawled += 1
            
            # Get page content without JavaScript rendering
            html_content, _ = self._get_page_without_js(url)
            
            # Only process if content was retrieved successfully
            if html_content:
                # Extract links and PDFs
                links, pdfs = self._extract_links_and_pdfs(url, html_content)
                
                # Add found PDFs
                for pdf_url in pdfs:
                    if pdf_url not in self.pdf_urls and len(self.pdf_urls) < self.max_pdfs:
                        logger.info(f"Found PDF: {pdf_url}")
                        self.pdf_urls.append(pdf_url)
                
                # Add links to visit
                if depth < self.max_depth:
                    for link in links:
                        if link not in self.visited:
                            urls_to_visit.append((link, depth + 1))
    
    def crawl(self):
        """Start the crawling process"""
        try:
            if self.enable_js:
                # Run asynchronous JavaScript-enabled crawling
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(self._crawl_with_js())
                loop.close()
            else:
                # Run synchronous crawling without JavaScript
                self._crawl_without_js()
            
            # Return results
            return self.pdf_urls, {
                'pages_crawled': self.pages_crawled,
                'pdfs_found': len(self.pdf_urls),
                'js_enabled': self.enable_js
            }
        
        except Exception as e:
            logger.error(f"Crawl error: {str(e)}", exc_info=True)
            # Return any PDFs found so far instead of failing completely
            return self.pdf_urls, {
                'pages_crawled': self.pages_crawled,
                'pdfs_found': len(self.pdf_urls),
                'js_enabled': self.enable_js,
                'error': str(e),
                'error_details': 'Crawling encountered an error but returned partial results'
            }

# Initialize analyzer
analyzer = PDFFormAnalyzer()

@app.route('/analyze', methods=['POST'])
def analyze_form():
    try:
        # Get URL from request
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        pdf_url = data['url'].strip()
        if not pdf_url:
            return jsonify({'error': 'URL cannot be empty'}), 400
        
        # Validate URL
        try:
            parsed = urlparse(pdf_url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError("Invalid URL format")
        except Exception:
            return jsonify({'error': 'Invalid URL format'}), 400
        
        logger.info(f"Starting analysis request for: {pdf_url}")
        
        # Analyze the form
        results = analyzer.analyze_form(pdf_url)
        
        # Save the results (if not an error)
        if results.get('status') != 'error':
            global analyzed_forms
            # Add to the beginning to show most recent first
            analyzed_forms.insert(0, results)
            # Keep only the most recent forms (to prevent memory issues)
            analyzed_forms = analyzed_forms[:500]
        
        # Return the results, maintaining status code 200 even for analysis errors
        # This allows the client to handle errors gracefully
        return jsonify(results), 200
        
    except Exception as e:
        logger.error(f"Request failed: {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'error_message': str(e)
        }), 500

# -----------------------------------------------------------------------------
# Batch analysis endpoint
#
# This endpoint accepts a JSON payload containing a list of PDF URLs and runs
# the form analysis on each URL in sequence.  This separation enables a
# two‑stage workflow: crawl to collect PDF links, then run a batch analysis.
# The endpoint returns an array of analysis results for each URL.  Errors on
# individual PDFs are included in the result array; the request itself returns
# HTTP 200 unless an unexpected exception occurs.
@app.route('/batch_analyze', methods=['POST'])
def batch_analyze():
    try:
        global analyzed_forms
        data = request.get_json()
        if not data or 'urls' not in data:
            return jsonify({'error': 'A list of URLs is required in the "urls" field'}), 400

        urls = data['urls']
        if not isinstance(urls, list) or not urls:
            return jsonify({'error': 'The "urls" field must be a non-empty list'}), 400

        batch_results = []
        for pdf_url in urls:
            try:
                url_str = str(pdf_url).strip()
                parsed = urlparse(url_str)
                if not parsed.scheme or not parsed.netloc:
                    raise ValueError("Invalid URL format")
                logger.info(f"Batch analysis: analyzing {url_str}")
                result = analyzer.analyze_form(url_str)
                # Store successful results in the global list for the dashboard
                if result.get('status') != 'error':
                    global analyzed_forms
                    analyzed_forms.insert(0, result)
                    analyzed_forms = analyzed_forms[:500]
                batch_results.append(result)
            except Exception as e:
                logger.error(f"Batch analysis failed for {pdf_url}: {str(e)}")
                batch_results.append({
                    'status': 'error',
                    'url': pdf_url,
                    'error_message': str(e)
                })
        # Use json.dumps with default=str to handle any non-serialisable objects gracefully
        json_body = json.dumps({'results': batch_results}, default=str)
        return Response(json_body, mimetype='application/json'), 200
    except Exception as e:
        logger.error(f"Batch analysis request failed: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/crawl', methods=['POST'])
def crawl_website():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        base_url = data['url'].strip()
        include_subpages = data.get('include_subpages', True)
        max_pdfs = min(int(data.get('max_pdfs', 20)), 50)
        max_depth = min(int(data.get('max_depth', 2)), 3)
        enable_js = data.get('enable_js', False)
        
        # Validate URL
        try:
            parsed = urlparse(base_url)
            if not parsed.scheme or not parsed.netloc:
                return jsonify({'error': 'Invalid URL format'}), 400
        except Exception:
            return jsonify({'error': 'Invalid URL format'}), 400
        
        logger.info(f"Starting enhanced crawl of {base_url} with JS enabled: {enable_js}")

        # ---------------------------------------------------------------------
        # Attempt a specialized credit-union crawl first.  If the credit-union
        # crawler finds any forms, we'll immediately analyze them and return
        # results rather than falling through to the generic crawler.  This
        # crawler looks for PDF links and form pages on the same domain using
        # patterns tailored for credit union websites.  The integration below
        # automatically runs the PDF analysis pipeline for each discovered PDF
        # and stores the results in the global `analyzed_forms` list so that
        # they appear on the dashboard and in the `/forms` API.
        cu_forms = []
        try:
            # Only attempt the credit union crawler if it is available
            if 'CreditUnionFormCrawler' in globals():
                cu_crawler = CreditUnionFormCrawler(base_url)
                cu_forms = cu_crawler.crawl(max_depth=max_depth, max_pages=max_pdfs)
        except Exception as cu_e:
            logger.warning(f"CreditUnionFormCrawler failed: {str(cu_e)}")
            cu_forms = []

        # If the credit-union crawler returned forms, return only the PDF URLs.
        # We no longer perform analysis during crawling; analysis is handled
        # separately via the batch analyzer.  This supports a two‑stage
        # workflow where crawling and analysis can be decoupled for large
        # websites.  The credit union crawler returns a list of dictionaries
        # with at least a 'url' key; extract those URLs for the caller.
        if cu_forms:
            pdf_urls = [form.get('url') for form in cu_forms if form.get('url')]
            crawl_stats = {
                'pages_crawled': len(cu_forms),
                'pdfs_found': len(pdf_urls),
                'visited_urls': len(cu_forms),
                'status': 'success',
                'source': 'credit_union_crawler'
            }
            return jsonify({
                'pdf_urls': pdf_urls,
                'crawl_stats': crawl_stats
            })
        
        # Use WebCrawler class if JavaScript is enabled
        if enable_js:
            crawler = WebCrawler(base_url, include_subpages, max_depth, max_pdfs, True)
            pdf_urls, stats = crawler.crawl()
            
            # If we found PDFs, return them
            if pdf_urls and len(pdf_urls) > 0:
                return jsonify({
                    'pdf_urls': pdf_urls,
                    'crawl_stats': stats
                })
            # If JS crawler found nothing, fall back to enhanced crawler
            logger.info("JavaScript crawler found no PDFs, trying enhanced crawler")
        
        # Enhanced crawler implementation
        pdfs = []
        pages_crawled = 0
        
        # Create a session to maintain cookies
        session = requests.Session()
        
        # Use more sophisticated browser headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
            'Referer': base_url
        }
        
        # Track visited URLs
        visited = set()
        to_visit = [(base_url, 0)]  # (url, depth)
        
        # Enhanced PDF detection patterns for financial sites
        pdf_indicators = [
            '.pdf', 
            '/pdf/', 
            'document', 
            'download', 
            'form', 
            'application', 
            'getfile', 
            'viewdoc', 
            'file.php',
            'formularios',
            'documentos',
            'getDocument',
            'download.aspx',
            'download.php',
            'viewform',
            'file=',
            'type=pdf',
            'format=pdf',
            'document_id=',
            'doc_id=',
            'filedownload',
            'displayfile',
            'attachment',
            'terms',
            'agreement',
            'statement',
            'report',
            'disclosure',
            'account_opening',
            'request',
            'checklist',
            'authorization'
        ]
        
        while to_visit and len(pdfs) < max_pdfs and pages_crawled < 30:
            current_url, depth = to_visit.pop(0)
            
            # Skip if already visited or exceeds max depth
            if current_url in visited or depth > max_depth:
                continue
                
            visited.add(current_url)
            pages_crawled += 1
            logger.info(f"Crawling page {pages_crawled}: {current_url}")
            
            try:
                # Make the request with increased timeout
                response = session.get(current_url, headers=headers, timeout=30)
                
                if response.status_code != 200:
                    logger.warning(f"Got status code {response.status_code} for {current_url}")
                    continue
                
                # Check content type - if it's already a PDF, add it
                content_type = response.headers.get('Content-Type', '').lower()
                if 'application/pdf' in content_type:
                    if current_url not in pdfs:
                        logger.info(f"Found PDF by content type: {current_url}")
                        pdfs.append(current_url)
                    continue
                
                # Parse the page
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Method 1: Look for direct PDF links
                for a in soup.find_all('a', href=True):
                    href = a.get('href', '').strip()
                    if not href or href.startswith('#') or href.startswith('javascript:'):
                        continue
                    
                    full_url = urljoin(current_url, href)
                    
                    # Check if it's a direct PDF link
                    if full_url.lower().endswith('.pdf'):
                        if full_url not in pdfs and len(pdfs) < max_pdfs:
                            logger.info(f"Found PDF by extension: {full_url}")
                            pdfs.append(full_url)
                            continue
                    
                    # Check for PDF indicators in the URL
                    full_url_lower = full_url.lower()
                    for indicator in pdf_indicators:
                        if indicator in full_url_lower:
                            # Try to validate if it's a PDF with a HEAD request
                            try:
                                head_response = session.head(full_url, headers=headers, timeout=10, allow_redirects=True)
                                final_url = head_response.url
                                
                                # Check if it redirects to a PDF
                                if final_url.lower().endswith('.pdf'):
                                    if final_url not in pdfs and len(pdfs) < max_pdfs:
                                        logger.info(f"Found PDF through redirect: {final_url}")
                                        pdfs.append(final_url)
                                        break
                                
                                # Check content type header
                                head_content_type = head_response.headers.get('Content-Type', '').lower()
                                if 'application/pdf' in head_content_type:
                                    if final_url not in pdfs and len(pdfs) < max_pdfs:
                                        logger.info(f"Found PDF by content type: {final_url}")
                                        pdfs.append(final_url)
                                        break
                            except Exception as head_e:
                                logger.warning(f"Error in HEAD request for {full_url}: {str(head_e)}")
                                # If HEAD fails but URL looks promising, add it anyway
                                if any(ext in full_url_lower for ext in ['.pdf', 'getdocument', 'download']):
                                    if full_url not in pdfs and len(pdfs) < max_pdfs:
                                        logger.info(f"Adding potential PDF without verification: {full_url}")
                                        pdfs.append(full_url)
                                        break
                            break
                    
                    # For non-PDFs, add to visit queue if within depth limit
                    if depth < max_depth and full_url not in visited and full_url not in [u for u, _ in to_visit]:
                        to_visit.append((full_url, depth + 1))
                
                # Method 2: Look for buttons, divs, spans with onclick handlers
                for elem in soup.find_all(['button', 'div', 'span', 'a']):
                    onclick = elem.get('onclick', '')
                    if onclick and any(keyword in onclick.lower() for keyword in ['pdf', 'download', 'form', 'document']):
                        # Try to extract URL from onclick
                        url_match = re.search(r'["\'](https?://[^"\')]+)["\']', onclick)
                        if url_match:
                            extracted_url = url_match.group(1)
                            full_url = urljoin(current_url, extracted_url)
                            
                            # Check if it's likely a PDF
                            if any(indicator in full_url.lower() for indicator in pdf_indicators):
                                if full_url not in pdfs and len(pdfs) < max_pdfs:
                                    logger.info(f"Found potential PDF in onclick: {full_url}")
                                    pdfs.append(full_url)
                
                # Method 3: Look for form-related text in links
                for a in soup.find_all('a'):
                    link_text = a.get_text().lower() if a.get_text() else ""
                    
                    # Check for form-related text
                    if any(keyword in link_text for keyword in ['form', 'pdf', 'download', 'application', 'checklist']):
                        href = a.get('href')
                        if href:
                            full_url = urljoin(current_url, href)
                            if full_url not in pdfs and len(pdfs) < max_pdfs:
                                # Verify it's a PDF
                                try:
                                    head_response = session.head(full_url, headers=headers, timeout=10, allow_redirects=True)
                                    final_url = head_response.url
                                    
                                    head_content_type = head_response.headers.get('Content-Type', '').lower()
                                    if 'application/pdf' in head_content_type or final_url.lower().endswith('.pdf'):
                                        logger.info(f"Found PDF from link text: {final_url}")
                                        pdfs.append(final_url)
                                except Exception:
                                    # If verification fails but URL has pdf extension, add it anyway
                                    if full_url.lower().endswith('.pdf'):
                                        logger.info(f"Adding unverified PDF from link text: {full_url}")
                                        pdfs.append(full_url)
                
                # Method 4: Check for data attributes that might contain PDF URLs
                for elem in soup.find_all(attrs=True):
                    for attr_name, attr_value in elem.attrs.items():
                        if isinstance(attr_value, str) and attr_name.startswith('data-'):
                            if any(keyword in attr_value.lower() for keyword in ['pdf', 'form', 'download']):
                                url_match = re.search(r'(https?://[^\s"\']+)', attr_value)
                                if url_match:
                                    extracted_url = url_match.group(1)
                                    full_url = urljoin(current_url, extracted_url)
                                    
                                    # Check if likely a PDF
                                    if any(indicator in full_url.lower() for indicator in pdf_indicators):
                                        if full_url not in pdfs and len(pdfs) < max_pdfs:
                                            logger.info(f"Found potential PDF in data attribute: {full_url}")
                                            pdfs.append(full_url)
                
            except Exception as e:
                logger.warning(f"Error processing page {current_url}: {str(e)}")
        
        # Return results - even if partial
        return jsonify({
            'pdf_urls': pdfs[:max_pdfs],
            'crawl_stats': {
                'pages_crawled': pages_crawled,
                'pdfs_found': len(pdfs),
                'visited_urls': len(visited),
                'status': 'success'
            }
        })
        
    except Exception as e:
        logger.error(f"Crawling failed: {str(e)}", exc_info=True)
        return jsonify({
            'error': str(e),
            'pdf_urls': [],
            'crawl_stats': {'status': 'error', 'message': str(e)}
        })
@app.route('/dashboard', methods=['GET'])
def show_dashboard():
    forms = get_analyzed_forms()
    dashboard_html = analyzer.generate_dashboard_html(forms)
    return dashboard_html

@app.route('/health', methods=['GET'])
def health_check():
    # Add version info and basic diagnostic info
    version = "1.3.2"  # Updated version number
    try:
        import platform
        import sys
        system_info = {
            'python': sys.version,
            'platform': platform.platform(),
            'system': platform.system(),
            'release': platform.release()
        }
    except:
        system_info = {'note': 'System info unavailable'}
        
    # Check if we can import and use PyPDF2
    pdf_lib_ok = False
    try:
        import PyPDF2
        pdf_lib_ok = True
    except:
        pass
    
    # Get rate limiting status
    rate_limit_status = {
        'domains_tracked': len(domain_rate_limits),
        'rate_limit_settings': {
            'max_requests': DEFAULT_RATE_LIMIT['max_requests'],
            'window_seconds': DEFAULT_RATE_LIMIT['window']
        }
    }
    
    # Return OK status with diagnostics
    return jsonify({
        'status': 'healthy',
        'version': version,
        'timestamp': datetime.now().isoformat(),
        'system': system_info,
        'libraries': {
            'pdf': pdf_lib_ok
        },
        'features': {
            'dashboard': DASHBOARD_FEATURE_ENABLED
        },
        'rate_limiting': rate_limit_status
    }), 200

# Serve index.html at root path
@app.route('/')
def root():
    return send_from_directory('static', 'index.html')

# Add explicit route for serving static files
@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

# API info endpoint
@app.route('/api', methods=['GET'])
def api_info():
    return jsonify({
        'service': 'PDF Form Analyzer',
        'version': '1.3.2',  # Updated version number
        'endpoints': {
            'analyze': '/analyze (POST)',
            'crawl': '/crawl (POST)',
            'dashboard': '/dashboard (GET)',
            'health': '/health (GET)'
        },
        'features': {
            'entity_detection': 'Enhanced for financial institutions',
            'rate_limiting': 'Advanced domain-based rate limiting'
        }
    })

# List analyzed forms endpoint
@app.route('/forms', methods=['GET'])
def list_forms():
    forms = get_analyzed_forms()
    
    # Only return essential info, not full analysis
    summary = []
    for form in forms:
        # Skip error results
        if form.get('status') == 'error':
            continue
            
        summary.append({
            'analysis_id': form.get('analysis_id'),
            'entity_name': form.get('entity_name'),
            'form_title': form.get('form_title'),
            'url': form.get('url'),
            'complexity_score': form.get('complexity_score'),
            'timestamp': form.get('timestamp')
        })
    
    return jsonify({
        'total': len(summary),
        'forms': summary
    })

# Clear rate limits endpoint (admin only)
@app.route('/admin/clear_rate_limits', methods=['POST'])
def clear_rate_limits():
    # In a production app, this would have authentication
    global domain_rate_limits
    domain_rate_limits = {}
    
    return jsonify({
        'status': 'success',
        'message': 'Rate limits cleared'
    })


# -----------------------------------------------------------------------------
# CX-facing report generation route.  This endpoint generates an HTML report
# summarizing the analyzed forms in a customer-facing format similar to
# executive dashboards.  The report includes metrics such as the number of
# forms with conditional logic, deadlines, third-party involvement, ID
# verification, notarization and witness requirements, as well as a breakdown
# of complexity levels and a list of the top 10 most complex forms.  It uses
# the existing `analyzed_forms` data in memory.  The resulting HTML uses a
# dark-themed aesthetic with animated accents, matching the sample provided by
# the user.

@app.route('/cx_report', methods=['GET'])
def cx_report():
    # Load forms analyzed in this session
    forms = get_analyzed_forms()
    # If no forms have been analyzed yet, return a simple message
    if not forms:
        return "<p>No forms have been analyzed yet. Please analyze or crawl forms first.</p>"

    # Filter out error results
    valid_forms = [f for f in forms if f.get('status') != 'error']
    total_forms = len(valid_forms)
    if total_forms == 0:
        return "<p>All analyzed forms resulted in errors. Cannot generate report.</p>"

    # Helper to safely convert complexity to integer
    def complexity(form):
        try:
            return int(float(form.get('complexity_score', 0)))
        except Exception:
            return 0

    # Count forms with conditional logic (string 'Yes' or boolean True)
    cond_count = sum(1 for f in valid_forms if str(f.get('conditional_logic', '')).lower() == 'yes')
    cond_percent = round((cond_count / total_forms) * 100, 1) if total_forms > 0 else 0

    # Count forms with deadlines
    deadline_count = sum(1 for f in valid_forms if f.get('deadlines') and len(f.get('deadlines')) > 0)
    deadline_percent = round((deadline_count / total_forms) * 100, 1) if total_forms > 0 else 0

    # Count forms requiring third-party involvement (third_party_roles list)
    third_count = sum(1 for f in valid_forms if f.get('third_party_roles') and len(f.get('third_party_roles')) > 0)
    third_percent = round((third_count / total_forms) * 100, 1) if total_forms > 0 else 0

    # Count forms requiring notarization
    notary_count = sum(1 for f in valid_forms if f.get('signature_analysis', {}).get('notarized') == 'Yes')
    notary_percent = round((notary_count / total_forms) * 100, 1) if total_forms > 0 else 0

    # Count forms requiring witnesses
    witness_count = sum(1 for f in valid_forms if f.get('signature_analysis', {}).get('witness_signature_count', 0) > 0)
    witness_percent = round((witness_count / total_forms) * 100, 1) if total_forms > 0 else 0

    # Approximate forms requiring ID verification: count forms with any PII fields
    id_count = sum(1 for f in valid_forms if f.get('pii_fields') and len(f.get('pii_fields')) > 0)
    id_percent = round((id_count / total_forms) * 100, 1) if total_forms > 0 else 0

    # Average complexity score
    avg_complexity = round(sum(complexity(f) for f in valid_forms) / total_forms, 1) if total_forms > 0 else 0

    # Complexity level distribution
    low = medium = high = very_high = extreme = 0
    for f in valid_forms:
        c = complexity(f)
        if c <= 33:
            low += 1
        elif c <= 66:
            medium += 1
        elif c <= 80:
            high += 1
        elif c <= 90:
            very_high += 1
        else:
            extreme += 1

    # Convert to percentages
    low_pct = round((low / total_forms) * 100, 1)
    med_pct = round((medium / total_forms) * 100, 1)
    high_pct = round((high / total_forms) * 100, 1)
    vhigh_pct = round((very_high / total_forms) * 100, 1)
    extreme_pct = round((extreme / total_forms) * 100, 1)

    # Top 10 most complex forms
    sorted_forms = sorted(valid_forms, key=lambda f: complexity(f), reverse=True)[:10]

    # Build table rows
    table_rows = ""
    for f in sorted_forms:
        title = f.get('form_title') or f.get('url') or 'Unknown'
        form_id = f.get('analysis_id', '')
        score = complexity(f)
        table_rows += f"<tr><td>{form_id}</td><td>{title}</td><td>{score}</td></tr>\n"

    # Gauge needle rotation: ((value/100)*180)-90 degrees
    gauge_rotate = ((avg_complexity / 100) * 180) - 90

    # Generate HTML report using template with inserted values
    report_html = f"""<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Forms Analysis Report</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');
        :root {{
            --primary: #76A922; --secondary: #6366F1; --accent: #F59E0B; --error: #EF4444;
            --success: #10B981; --dark: #0F172A; --darker: #020617; --light: #F8FAFC;
            --text: #CBD5E1; --muted: #64748B; --border: #1E293B; --card: #0F172A; --glow: #76A922;
        }}
        * {{ box-sizing: border-box; margin:0; padding:0; }}
        body {{ font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
            background: linear-gradient(135deg,#020617 0%,#0F172A 50%,#020617 100%);
            color:var(--text); line-height:1.6; overflow-x:hidden; }}
        body::before {{ content:''; position:fixed; top:0; left:0; right:0; bottom:0;
            background:
              radial-gradient(circle at 20% 50%, rgba(118,169,34,0.15) 0%, transparent 50%),
              radial-gradient(circle at 80% 80%, rgba(99,102,241,0.1) 0%, transparent 50%),
              radial-gradient(circle at 40% 20%, rgba(245,158,11,0.08) 0%, transparent 50%);
            pointer-events:none; animation:float 20s ease-in-out infinite; }}
        @keyframes float {{
            0%,100% {{ transform: translate(0, 0) scale(1); }}
            33% {{ transform: translate(-20px, -20px) scale(1.02); }}
            66% {{ transform: translate(20px, -10px) scale(0.98); }}
        }}
        .container {{ max-width:1400px; margin:0 auto; padding:3rem 2rem; position:relative; z-index:1; }}
        header {{ background:linear-gradient(135deg, rgba(118,169,34,0.1) 0%, rgba(99,102,241,0.05) 100%);
            border:1px solid var(--border); border-radius:24px; padding:3rem; text-align:center;
            margin-bottom:3rem; position:relative; overflow:hidden; }}
        header::before {{ content:''; position:absolute; top:-50%; right:-10%; width:500px; height:500px;
            background: radial-gradient(circle, var(--glow) 0%, transparent 70%);
            opacity:0.1; animation:pulse 4s ease-in-out infinite; }}
        @keyframes pulse {{ 0%,100%{{transform:scale(1); opacity:0.1;}} 50%{{transform:scale(1.1); opacity:0.2;}} }}
        h1 {{ font-size:3rem; font-weight:800; margin-bottom:1rem;
            background: linear-gradient(135deg, var(--light) 0%, var(--text) 100%);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .subtitle {{ font-size:1.25rem; color:var(--muted); }}
        section {{ background: linear-gradient(135deg, rgba(15,23,42,0.6) 0%, rgba(30,41,59,0.3) 100%);
            border:1px solid var(--border); border-radius:24px; padding:2.5rem; margin-bottom:2rem; position:relative; }}
        h2 {{ font-size:2rem; font-weight:700; margin-bottom:1.5rem; color:var(--light);
            padding-bottom:1rem; border-bottom:2px solid var(--border); display:flex; align-items:center; }}
        h3 {{ font-size:1.25rem; font-weight:600; color:var(--primary); margin:1.5rem 0 1rem; display:flex; align-items:center; }}
        .exec-priority {{ display:grid; grid-template-columns: repeat(3, 1fr); gap:1.5rem; margin-bottom:2rem; }}
        .priority-card {{ background:linear-gradient(135deg, rgba(239,68,68,0.15) 0%, rgba(15,23,42,0.95) 100%);
            border:2px solid var(--error); border-radius:16px; padding:1.5rem; text-align:center; position:relative; overflow:hidden; }}
        .priority-card::before {{ content:''; position:absolute; top:0; left:0; right:0; bottom:0;
            background:linear-gradient(135deg, transparent 0%, rgba(239,68,68,0.1) 100%); pointer-events:none; }}
        .priority-metric {{ font-size:3rem; font-weight:800;
            background:linear-gradient(135deg, var(--error) 0%, var(--accent) 100%);
            -webkit-background-clip:text; -webkit-text-fill-color:transparent; position:relative; z-index:1; }}
        .priority-label {{ color:var(--light); font-weight:600; margin-top:0.5rem; font-size:1.1rem; }}
        .priority-detail {{ color:var(--muted); font-size:0.85rem; }}
        .blockers-grid {{ display:grid; grid-template-columns: repeat(3, 1fr); gap:1.5rem; margin-bottom:1rem; }}
        .blocker-card {{ background:linear-gradient(135deg, rgba(30,41,59,0.8) 0%, rgba(15,23,42,0.6) 100%);
            border:1px solid var(--border); border-radius:12px; padding:1rem; text-align:center; }}
        .blocker-value {{ font-size:2rem; font-weight:700; color:var(--accent); }}
        .blocker-percent {{ font-size:0.9rem; color:var(--muted); margin-bottom:0.3rem; }}
        .blocker-label {{ font-size:1rem; color:var(--light); margin-bottom:0.5rem; }}
        .blocker-bar {{ width:100%; height:8px; background:var(--border); border-radius:4px; position:relative; }}
        .blocker-fill {{ height:100%; background:var(--secondary); border-radius:4px; position:absolute; top:0; left:0; }}
        .complexity-gauge {{ display:flex; align-items:center; justify-content:space-around; flex-wrap:wrap; margin-top:2rem; }}
        .gauge-container {{ position:relative; width:200px; height:100px; margin-bottom:1rem; }}
        .gauge-bg {{ width:100%; height:100%; border-radius:100px 100px 0 0;
            background:linear-gradient(135deg, rgba(30,41,59,0.8) 0%, rgba(15,23,42,0.6) 100%);
            border:1px solid var(--border); position:relative; overflow:hidden; }}
        .gauge-needle {{ position:absolute; width:3px; height:85px; background:white; left:50%; bottom:0;
            transform-origin:bottom center;
            transform:translateX(-50%) rotate({gauge_rotate}deg);
            border-radius:2px; box-shadow:0 0 10px rgba(255,255,255,0.5); }}
        .gauge-value {{ position:absolute; bottom:25px; left:50%; transform:translateX(-50%);
            font-size:1.8rem; font-weight:800; color:var(--accent); }}
        .gauge-labels {{ display:flex; justify-content:space-between; margin-top:0.5rem; }}
        .gauge-labels span {{ font-size:0.75rem; color:var(--muted); }}
        .gauge-scale {{ display:flex; justify-content:center; gap:1rem; margin-top:1rem; }}
        .scale-item {{ display:flex; flex-direction:column; align-items:center; font-size:0.75rem; color:var(--muted); }}
        .scale-dot {{ width:10px; height:10px; border-radius:50%; margin-bottom:0.3rem; }}
        .scale-dot.low {{ background:var(--primary); }}
        .scale-dot.medium {{ background:var(--accent); }}
        .scale-dot.high {{ background:var(--error); }}
        .scale-dot.vhigh {{ background:var(--secondary); }}
        .scale-dot.extreme {{ background:var(--glow); }}
        .forms-table {{ width:100%; border-collapse:collapse; margin-top:1rem; }}
        .forms-table th, .forms-table td {{ padding:0.5rem 0.75rem; border-bottom:1px solid var(--border);
            color:var(--text); text-align:left; font-size:0.85rem; }}
        .forms-table th {{ font-weight:600; color:var(--light); }}
        .forms-table tr:nth-child(even) {{ background:rgba(15,23,42,0.4); }}
        .categories-grid {{ display:grid; grid-template-columns: repeat(5, 1fr); gap:1.5rem; margin-top:1rem; }}
        .category-card {{ padding:1rem; background:linear-gradient(135deg, rgba(30,41,59,0.8) 0%, rgba(15,23,42,0.6) 100%);
            border:1px solid var(--border); border-radius:12px; text-align:center; }}
        .category-value {{ font-size:1.6rem; font-weight:700; color:var(--accent); }}
        .category-label {{ margin-top:0.5rem; font-size:1rem; color:var(--light); }}
        .category-bar {{ width:100%; height:8px; background:var(--border); border-radius:4px; margin-top:0.5rem; position:relative; }}
        .category-fill {{ height:100%; background:var(--primary); border-radius:4px; position:absolute; top:0; left:0; }}
        .insights {{ margin-top:1.5rem; color:var(--muted); font-size:0.95rem; line-height:1.6; }}
        .insights h3 {{ color:var(--primary); font-size:1.25rem; margin-bottom:0.5rem; font-weight:600; }}
        .insights ul {{ margin-left:1.5rem; list-style-type:disc; }}
        .insights li {{ margin-bottom:0.5rem; }}
        @media (max-width:768px) {{
            h1 {{ font-size: 2rem; }}
            .exec-priority {{ grid-template-columns: 1fr; }}
            .blockers-grid {{ grid-template-columns: repeat(2, 1fr); }}
            .categories-grid {{ grid-template-columns: repeat(2, 1fr); }}
            .forms-table th, .forms-table td {{ font-size: 0.75rem; }}
        }}
    </style>
</head>
<body>
    <div class='container'>
        <header>
            <h1>📑 Forms Analysis Report</h1>
            <p class='subtitle'>Customer‑facing summary of form complexity, blockers and automation opportunities</p>
        </header>
        <section>
            <h2>Critical Form Requirements</h2>
            <div class='exec-priority'>
                <div class='priority-card'><div class='priority-metric'>{cond_count}</div><div class='priority-label'>Forms with Conditional Logic</div><div class='priority-detail'>{cond_percent}% of all forms</div></div>
                <div class='priority-card'><div class='priority-metric'>{deadline_count}</div><div class='priority-label'>Forms with Deadlines</div><div class='priority-detail'>{deadline_percent}% of all forms</div></div>
                <div class='priority-card'><div class='priority-metric'>{third_count}</div><div class='priority-label'>Forms Requiring Third‑Party</div><div class='priority-detail'>{third_percent}% of all forms</div></div>
            </div>
        </section>
        <section>
            <h2>Workflow Blockers</h2>
            <div class='blockers-grid'>
                <div class='blocker-card'><div class='blocker-value'>{notary_count}</div><div class='blocker-percent'>{notary_percent}%</div><div class='blocker-label'>Notarization Required</div><div class='blocker-bar'><div class='blocker-fill' style='width: {notary_percent}%'></div></div></div>
                <div class='blocker-card'><div class='blocker-value'>{witness_count}</div><div class='blocker-percent'>{witness_percent}%</div><div class='blocker-label'>Witnesses Required</div><div class='blocker-bar'><div class='blocker-fill' style='width: {witness_percent}%'></div></div></div>
                <div class='blocker-card'><div class='blocker-value'>{third_count}</div><div class='blocker-percent'>{third_percent}%</div><div class='blocker-label'>Third‑party Involved</div><div class='blocker-bar'><div class='blocker-fill' style='width: {third_percent}%'></div></div></div>
                <div class='blocker-card'><div class='blocker-value'>{deadline_count}</div><div class='blocker-percent'>{deadline_percent}%</div><div class='blocker-label'>Deadline Present</div><div class='blocker-bar'><div class='blocker-fill' style='width: {deadline_percent}%'></div></div></div>
                <div class='blocker-card'><div class='blocker-value'>{cond_count}</div><div class='blocker-percent'>{cond_percent}%</div><div class='blocker-label'>Conditional Logic</div><div class='blocker-bar'><div class='blocker-fill' style='width: {cond_percent}%'></div></div></div>
                <div class='blocker-card'><div class='blocker-value'>{id_count}</div><div class='blocker-percent'>{id_percent}%</div><div class='blocker-label'>ID Verification</div><div class='blocker-bar'><div class='blocker-fill' style='width: {id_percent}%'></div></div></div>
            </div>
            <h3>Form Complexity Distribution</h3>
            <div class='complexity-gauge'>
                <div class='gauge-container'>
                    <div class='gauge-bg'>
                        <div class='gauge-needle'></div>
                        <div class='gauge-value'>{avg_complexity}</div>
                    </div>
                    <div class='gauge-labels'><span>0</span><span>25</span><span>50</span><span>75</span><span>100</span></div>
                </div>
                <div class='gauge-scale'>
                    <div class='scale-item'><div class='scale-dot low'></div><span>Low (0–33)</span></div>
                    <div class='scale-item'><div class='scale-dot medium'></div><span>Medium (34–66)</span></div>
                    <div class='scale-item'><div class='scale-dot high'></div><span>High (67–80)</span></div>
                    <div class='scale-item'><div class='scale-dot vhigh'></div><span>Very High (81–90)</span></div>
                    <div class='scale-item'><div class='scale-dot extreme'></div><span>Extreme (91–100)</span></div>
                </div>
            </div>
            <p style='color: var(--text); text-align:center; margin-top:1rem;'>
                With an average complexity score of <strong>{avg_complexity}</strong>, most forms cluster in the medium to high range, signalling opportunities for simplification and automation.
            </p>
        </section>
        <section>
            <h2>Top 10 Most Complex Forms</h2>
            <table class='forms-table'>
                <thead><tr><th>Form ID</th><th>Form Title</th><th>Complexity Score</th></tr></thead>
                <tbody>{table_rows}</tbody>
            </table>
            <p style='color: var(--text); margin-top: 1rem;'>
                These forms exhibit the highest complexity scores in the current dataset. They often combine many pages, numerous fields and layered conditional logic. Simplifying these will yield significant UX improvements.
            </p>
        </section>
        <section>
            <h2>Complexity Level Breakdown</h2>
            <div class='categories-grid'>
                <div class='category-card'><div class='category-value'>{low_pct}%</div><div class='category-label'>Low</div><div class='category-bar'><div class='category-fill' style='width: {low_pct}%'></div></div></div>
                <div class='category-card'><div class='category-value'>{med_pct}%</div><div class='category-label'>Medium</div><div class='category-bar'><div class='category-fill' style='width: {med_pct}%'></div></div></div>
                <div class='category-card'><div class='category-value'>{high_pct}%</div><div class='category-label'>High</div><div class='category-bar'><div class='category-fill' style='width: {high_pct}%'></div></div></div>
                <div class='category-card'><div class='category-value'>{vhigh_pct}%</div><div class='category-label'>Very High</div><div class='category-bar'><div class='category-fill' style='width: {vhigh_pct}%'></div></div></div>
                <div class='category-card'><div class='category-value'>{extreme_pct}%</div><div class='category-label'>Extreme</div><div class='category-bar'><div class='category-fill' style='width: {extreme_pct}%'></div></div></div>
            </div>
            <p style='color: var(--text); margin-top:1rem;'>
                Complexity levels span the full spectrum: {low_pct}% of forms are low complexity, {med_pct}% medium, {high_pct}% high, {vhigh_pct}% very high and {extreme_pct}% extreme. Targeting very high and extreme forms for digitisation can provide the greatest gains.
            </p>
        </section>
        <section>
            <h2>Key Insights & Opportunities</h2>
            <div class='insights'>
                <h3>Observations</h3>
                <ul>
                    <li>The dataset contains <strong>{total_forms} forms</strong>.</li>
                    <li>The <strong>average complexity score</strong> is <strong>{avg_complexity}</strong>.</li>
                    <li><strong>{cond_percent}%</strong> of forms include conditional logic.</li>
                    <li><strong>{deadline_percent}%</strong> of forms have deadlines.</li>
                    <li><strong>{notary_percent}%</strong> require notarization and <strong>{witness_percent}%</strong> require witnesses.</li>
                    <li><strong>{third_percent}%</strong> involve third parties, while <strong>{id_percent}%</strong> require ID verification.</li>
                </ul>
                <h3>Opportunities for Automation</h3>
                <ul>
                    <li>Prioritise digitisation of <strong>very high</strong> and <strong>extreme</strong> complexity forms to achieve the greatest impact.</li>
                    <li>Develop a reusable library of <strong>conditional logic patterns</strong> to simplify form construction and reduce errors.</li>
                    <li>Implement <strong>deadline reminders</strong> and escalation workflows for time‑sensitive forms.</li>
                    <li>Streamline <strong>ID verification</strong> processes and integrate with external identity providers.</li>
                    <li>Because notarization and witness requirements are relatively rare, focus resources on more common blockers first.</li>
                </ul>
            </div>
        </section>
    </div>
</body>
</html>"""
    return report_html

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
                
                