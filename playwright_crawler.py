"""
playwright_crawler
-------------------

This module provides a helper function to crawl websites using a headless
Chromium browser via the Playwright library. It is intended for use in
projects where HTML pages may block simple HTTP clients or load PDF links
dynamically via JavaScript.  When called, the crawler visits the provided
URL, optionally follows links within the same domain up to a given depth,
and extracts all hyperlinks ending in ``.pdf``.  The result is returned
as a list of absolute URLs.

Example usage from synchronous code::

    from playwright_crawler import crawl_with_playwright_sync
    pdfs = crawl_with_playwright_sync(
        start_url="https://example.com/forms",
        include_subpages=True,
        max_depth=2
    )

For asynchronous usage, you can call the ``crawl_playwright`` coroutine
directly with ``await``.

Before using this module in your project, ensure that the ``playwright``
package is installed and that Chromium has been installed via
``playwright install chromium``.  See the project README for details.
"""

from __future__ import annotations

import asyncio
from typing import Iterable, List, Set, Tuple
from urllib.parse import urljoin, urlparse

try:
    from playwright.async_api import async_playwright
except ImportError as exc:  # pragma: no cover - handled at runtime
    raise ImportError(
        "playwright is required for playwright_crawler. Install it via "
        "'pip install playwright' and run 'playwright install chromium' to "
        "download the browser binaries."
    ) from exc


async def _extract_pdf_links(page, base_url: str) -> List[str]:
    """Return a list of absolute PDF links from the current Playwright page.

    This function evaluates JavaScript on the page to collect all anchor
    elements whose ``href`` attribute ends with ``.pdf`` (case‑insensitive).
    Relative links are converted to absolute URLs using the provided
    ``base_url``.

    :param page: The Playwright page object.
    :param base_url: The base URL used to resolve relative links.
    :return: A list of absolute PDF URLs found on the page.
    """
    # JavaScript to collect hrefs ending in .pdf (case‑insensitive)
    script = (
        "els => els.map(el => el.getAttribute('href'))"
    )
    hrefs: Iterable[str] = await page.eval_on_selector_all('a[href$=".pdf" i]', script)
    pdf_links: List[str] = []
    for href in hrefs:
        if not href:
            continue
        # Normalize relative URLs to absolute
        if href.startswith(('http://', 'https://')):
            pdf_links.append(href)
        else:
            pdf_links.append(urljoin(base_url, href))
    return pdf_links


async def crawl_playwright(
    start_url: str,
    *,
    include_subpages: bool = False,
    max_depth: int = 1,
    timeout: int = 60000,
) -> List[str]:
    """Crawl a website using Playwright and collect all PDF links.

    This coroutine launches a headless Chromium browser, navigates to
    ``start_url`` and extracts PDF links. If ``include_subpages`` is
    ``True``, it will follow internal links (limited to the same domain)
    recursively up to ``max_depth`` levels deep.  All pages are fetched
    sequentially to avoid overloading the server.

    :param start_url: The starting URL to crawl.
    :param include_subpages: Whether to recursively crawl internal links.
    :param max_depth: Maximum depth for recursion (0 means only the start URL).
    :param timeout: Page load timeout in milliseconds.
    :returns: A list of unique PDF URLs discovered on the site.
    """
    visited_pages: Set[str] = set()
    pdf_urls: Set[str] = set()
    queue: List[Tuple[str, int]] = [(start_url, 0)]

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        while queue:
            url, depth = queue.pop(0)
            if url in visited_pages or depth > max_depth:
                continue
            visited_pages.add(url)

            try:
                await page.goto(url, timeout=timeout)
                # Wait until network is idle to give JS a chance to load
                await page.wait_for_load_state('networkidle')
            except Exception:
                # Skip pages that fail to load
                continue

            try:
                # Collect PDF links
                for pdf_link in await _extract_pdf_links(page, url):
                    pdf_urls.add(pdf_link)

                # Collect subpage links if needed
                if include_subpages and depth < max_depth:
                    # Get all hrefs on the page
                    all_hrefs: Iterable[str] = await page.eval_on_selector_all(
                        'a[href]', "els => els.map(el => el.getAttribute('href'))"
                    )
                    for href in all_hrefs:
                        if not href:
                            continue
                        # Resolve relative URLs
                        if href.startswith(('http://', 'https://')):
                            link = href
                        else:
                            link = urljoin(url, href)
                        # Ignore fragments
                        link = link.split('#')[0]
                        # Only crawl pages on the same domain
                        if urlparse(link).netloc == urlparse(start_url).netloc:
                            queue.append((link, depth + 1))
            except Exception:
                continue

        await browser.close()

    return list(pdf_urls)


def crawl_with_playwright_sync(**kwargs) -> List[str]:
    """Blocking wrapper around ``crawl_playwright``.

    This helper allows synchronous code (such as Flask request handlers) to
    invoke the asynchronous crawler using ``asyncio.run``.  Any keyword
    arguments are forwarded directly to ``crawl_playwright``.

    :returns: A list of discovered PDF URLs.
    """
    return asyncio.run(crawl_playwright(**kwargs))