#!/usr/bin/env python
# vim:fileencoding=UTF-8:ts=4:sw=4:sta:et:sts=4:ai
__license__ = 'GPL v3'
"""
browser_fetch.py -- Playwright/Firefox browser layer -- MetadataPlusPlus

Provides browser_get(), a drop-in complement to providers._get() that drives
a real Firefox browser instead of urllib, bypassing bot-detection systems that
fingerprint server-side HTTP requests (missing browser headers, wrong TLS
fingerprint, no JS execution, etc.).

REQUIRES (one-time system-wide setup -- install into the SYSTEM Python):
    pip install playwright
    playwright install firefox

Architecture
------------
Playwright runs in a SYSTEM PYTHON SUBPROCESS, not inside Calibre's bundled
Python.  This is the only reliable approach because:

  - Calibre embeds its own Python interpreter.
  - Installing playwright into Calibre's Python causes dependency conflicts.
  - Even with sys.path injection, compiled C extensions (greenlet, the
    playwright browser binaries) built for one Python version cannot load
    inside a different Python's interpreter (ABI mismatch).

Single-window worker (merged fix)
----------------------------------
Earlier releases launched a brand-new Firefox subprocess (and therefore a
brand-new visible window) for EVERY browser_get() call -- one window per
URL, with a ~3-5s Firefox-launch cost paid every single time. The plugin
now starts ONE long-lived worker subprocess that keeps a single Firefox
browser/context/page alive and reuses it across every browser_get() call
for the life of the calibre/plugin process, talking to it over a simple
line-based JSON stdin/stdout protocol. This keeps visible Firefox usage to
one window total instead of one window per URL, and removes the repeated
launch cost for every fetch after the first. If the worker's page/context
ever becomes unusable (e.g. a hard navigation failure), the worker
recreates just the context/page internally rather than spawning a new
browser process or window.

Each browser_get() call:
  1. Finds the system Python that has playwright (cached after first probe).
  2. Ensures the persistent worker subprocess is running (starts it once).
  3. Sends the URL as a JSON request line and reads back the rendered HTML.

Integration pattern in providers.py
-------------------------------------
    raw = _get(url, timeout, retries, headers=hdrs, log=log)
    if (not raw or <blocked_check>(raw)) and _browser_fallback_enabled():
        log.info('Source: urllib blocked -- retrying via browser')
        raw = _browser_get(url, headers=hdrs, timeout=timeout, log=log)
"""

import atexit
import json
import os
import subprocess
import sys
import tempfile
import threading

# Suppress console windows created by subprocess calls on Windows.
# Without this every Popen/run call spawns a visible black CMD window.
_CREATE_NO_WINDOW = 0x08000000 if sys.platform == 'win32' else 0


# ── System Python discovery ────────────────────────────────────────────────────
_find_lock             = threading.Lock()
_system_python_cmd     = None   # e.g. ['py', '-3.11'] or ['python']
_system_python_checked = False  # True after first probe (even if none found)

# ── Persistent browser worker state ────────────────────────────────────────────
# Only one Firefox worker (and therefore one Firefox window) at a time. Browser
# calls are serialised through this same semaphore so requests queue rather
# than racing to talk to the worker's stdin/stdout concurrently.
_browser_semaphore = threading.Semaphore(1)
_worker_lock       = threading.Lock()
_worker_proc       = None
_worker_key        = None
_worker_script     = None


def _find_system_python_with_playwright():
    """
    Find and cache the system Python command that has playwright installed.

    Probes Python Launcher versioned variants first (py -3.12, py -3.11, ...)
    then falls back to simple executable names.  Skips Calibre's own Python.

    Returns a list like ['py', '-3.11'] or ['python'], or None if not found.
    Thread-safe -- the expensive probe runs at most once per Calibre session.
    """
    global _system_python_cmd, _system_python_checked

    if _system_python_checked:
        return _system_python_cmd

    with _find_lock:
        if _system_python_checked:
            return _system_python_cmd
        _system_python_checked = True

        calibre_exe  = os.path.normcase(os.path.realpath(sys.executable))
        check_script = 'from playwright.sync_api import sync_playwright; print("ok")'

        # Python Launcher versioned variants -- try older/more-stable versions
        # first since playwright is often installed for an LTS Python rather
        # than the newest available (3.14 is very recent and may lack packages).
        py_launcher_variants = [
            ['py', '-3.12'], ['py', '-3.11'], ['py', '-3.10'],
            ['py', '-3.13'], ['py', '-3.9'],  ['py', '-3'],
        ]
        simple_candidates = ['python3', 'python', 'py', 'python3.exe', 'python.exe']

        def _test(cmd_parts):
            """Return True if cmd_parts runs a non-Calibre Python that has playwright."""
            try:
                id_r = subprocess.run(
                    cmd_parts + ['-c', 'import sys; print(sys.executable)'],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
                    creationflags=_CREATE_NO_WINDOW,
                )
                if id_r.returncode == 0:
                    real = os.path.normcase(os.path.realpath(
                        id_r.stdout.decode('utf-8', errors='replace').strip()
                    ))
                    if real == calibre_exe:
                        return False  # this IS Calibre's Python -- skip it
                r = subprocess.run(
                    cmd_parts + ['-c', check_script],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
                    creationflags=_CREATE_NO_WINDOW,
                )
                return r.returncode == 0
            except (OSError, subprocess.TimeoutExpired, Exception):
                return False

        for parts in py_launcher_variants:
            if _test(parts):
                _system_python_cmd = parts
                return parts

        for exe in simple_candidates:
            if _test([exe]):
                _system_python_cmd = [exe]
                return [exe]

        return None


# ── Firefox UA ─────────────────────────────────────────────────────────────────
# Use the same UA a real Firefox 125 on Windows 10 x64 sends.
# A Chrome UA paired with a Firefox TLS fingerprint is a high-confidence bot
# signal on Cloudflare/Akamai/PerimeterX -- never mix them.
_FIREFOX_UA = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) '
    'Gecko/20100101 Firefox/125.0'
)

# ── Stealth JS (single-line so repr() embeds cleanly in the subprocess script) ─
_STEALTH_JS = (
    "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});"
    "if(navigator.plugins.length===0){"
    "Object.defineProperty(navigator,'plugins',{get:()=>{"
    "const a=[1,2,3];a.item=i=>a[i];a.namedItem=()=>null;a.refresh=()=>{};return a;"
    "}});"
    "}"
    "try{Object.defineProperty(navigator,'languages',{"
    "get:()=>(navigator.language?[navigator.language,'en']:['en-US','en'])"
    "});}catch(e){}"
    "try{delete window.__playwright;}catch(e){}"
    "try{delete window.__pw_manual;}catch(e){}"
    "try{delete window.__PW_inspect;}catch(e){}"
)

# ── Firefox user prefs (same for every call) ───────────────────────────────────
_FF_PREFS = {
    # Disable WebRTC -- local IP leaks are a common bot-detection signal.
    'media.peerconnection.enabled':              False,
    # Leave resistFingerprinting OFF -- its spoofed canvas/screen values are
    # themselves a detection signal on sophisticated WAFs.
    'privacy.resistFingerprinting':              False,
    # Suppress background update/telemetry requests.
    'app.update.auto':                           False,
    'app.update.enabled':                        False,
    'toolkit.telemetry.enabled':                 False,
    'datareporting.healthreport.uploadEnabled':  False,
}


# ── Public API ─────────────────────────────────────────────────────────────────

def is_browser_available():
    """
    Return True if a system Python with playwright is reachable.

    The underlying probe runs at most once per Calibre session (cached).
    Subsequent calls are a fast dict/bool lookup.
    """
    return _find_system_python_with_playwright() is not None


def browser_get(url, headers=None, timeout=30, log=None):
    """
    Fetch `url` using a persistent Playwright Firefox worker that reuses a
    single browser window across calls. Returns the fully-rendered page
    HTML as a str, or None on failure.

    Parameters
    ----------
    url     : str  -- page to fetch
    headers : dict -- optional extra HTTP request headers (Accept-Language
                      is used to set the browser locale)
    timeout : int  -- page-load timeout in seconds (default 30)
    log           -- calibre/standard logger, or None
    """
    sys_python = _find_system_python_with_playwright()
    if sys_python is None:
        if log:
            log.warning(
                'browser_fetch: no system Python with playwright found. '
                'Install commands:\n'
                '  1.  pip install playwright\n'
                '  2.  playwright install firefox'
            )
        return None

    # Read headless and timeout from plugin prefs (fall back to defaults).
    # DEBUG: default is False so Firefox window is visible for diagnosis.
    headless = False
    try:
        from calibre_plugins.metadata_plus.ui.config import prefs  # type: ignore
        headless = bool(prefs.get('browser_headless', True))
        timeout  = int(prefs.get('browser_timeout', timeout))
    except Exception:
        pass

    hdrs        = headers or {}
    accept_lang = hdrs.get('Accept-Language', 'en-US,en;q=0.9')
    locale      = accept_lang.split(',')[0].strip()
    timeout_ms  = int(timeout * 1000)

    extra_headers = {
        'Accept': (
            'text/html,application/xhtml+xml,application/xml;'
            'q=0.9,image/avif,image/webp,*/*;q=0.8'
        ),
        'Accept-Language':           accept_lang,
        'Accept-Encoding':           'gzip, deflate, br',
        'Cache-Control':             'no-cache',
        'Pragma':                    'no-cache',
        'Upgrade-Insecure-Requests': '1',
        'DNT':                       '1',
        'Sec-Fetch-Dest':            'document',
        'Sec-Fetch-Mode':            'navigate',
        'Sec-Fetch-Site':            'none',
        'Sec-Fetch-User':            '?1',
    }

    # Serialise: only one caller talks to the worker's stdin/stdout at a time.
    with _browser_semaphore:
        html = _worker_fetch(sys_python, url, extra_headers, locale,
                              headless, timeout_ms, log)
    return html


def _worker_fetch(sys_python, url, extra_headers, locale, headless, timeout_ms, log=None):
    proc = _ensure_worker(sys_python, headless, locale, extra_headers, log)
    if proc is None:
        return None

    try:
        req = json.dumps({'url': url, 'timeout_ms': int(timeout_ms)})
        proc.stdin.write((req + '\n').encode('utf-8'))
        proc.stdin.flush()

        status = proc.stdout.readline().decode('utf-8', errors='replace').strip()
        size_s = proc.stdout.readline().decode('utf-8', errors='replace').strip()
        if not status or not size_s:
            if log:
                log.warning('browser_fetch: reusable Firefox worker exited unexpectedly')
            _stop_worker()
            return None

        size = int(size_s)
        body = proc.stdout.read(size).decode('utf-8', errors='replace')
        proc.stdout.readline()  # trailing separator newline

        if status != 'OK':
            if log:
                log.warning('browser_fetch: worker failed for %s: %s',
                            url[:80], body[-300:] if body else '(no error)')
            # Keep the worker (and its single Firefox window) alive: its
            # script recreates the context/page internally after a
            # navigation failure. Do not launch a whole new Firefox window
            # here just because one fetch failed.
            return None

        if log:
            log.debug('browser_fetch: worker fetched %d bytes for %s',
                      len(body), url[:100])
        return body if body.strip() else None
    except Exception as e:
        if log:
            log.warning('browser_fetch: worker transport error for %s: %s',
                        url[:80], e)
        _stop_worker()
        return None


def _ensure_worker(sys_python, headless, locale, extra_headers, log=None):
    """
    Start the persistent Firefox worker if it isn't already running with a
    matching configuration, otherwise return the existing worker process.
    This is what keeps browser usage down to a single, reused window.
    """
    global _worker_proc, _worker_key, _worker_script

    key = (' '.join(sys_python), bool(headless), locale,
           repr(sorted(extra_headers.items())))
    with _worker_lock:
        if (_worker_proc is not None and _worker_proc.poll() is None
                and _worker_key == key):
            return _worker_proc

        _stop_worker_locked()
        script_path = _write_worker_script(headless, locale, extra_headers)
        try:
            proc = subprocess.Popen(
                sys_python + [script_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                creationflags=_CREATE_NO_WINDOW,
            )
            _worker_proc = proc
            _worker_key = key
            _worker_script = script_path
            if log:
                log.info('browser_fetch: started reusable Firefox worker (%s headless=%s)',
                         ' '.join(sys_python), headless)
            return proc
        except Exception as e:
            if log:
                log.warning('browser_fetch: could not start reusable Firefox worker: %s', e)
            try:
                os.unlink(script_path)
            except Exception:
                pass
            _worker_proc = None
            _worker_key = None
            _worker_script = None
            return None


def _write_worker_script(headless, locale, extra_headers):
    """
    Build the long-lived worker script: launches ONE Firefox browser and
    keeps a single context/page alive across requests read from stdin (one
    JSON line per fetch), writing back an OK/ERR status line, a byte-length
    line, and the raw response body -- so callers never spawn a second
    Firefox window for subsequent fetches.
    """
    script = '\n'.join([
        'import json, random, sys, time',
        'from playwright.sync_api import sync_playwright',
        f'_headless = {repr(headless)}',
        f'_locale = {repr(locale)}',
        f'_ua = {repr(_FIREFOX_UA)}',
        f'_extra_hdrs = {repr(extra_headers)}',
        f'_stealth_js = {repr(_STEALTH_JS)}',
        f'_ff_prefs = {repr(_FF_PREFS)}',
        '',
        # ── Resource blocker (matches reference playwright_utils.py) ──────────
        # Blocks heavy resources that don't contribute to metadata content:
        # stylesheets, fonts, media, and known ad/analytics domains. Cover
        # images from Amazon CDN and Goodreads are explicitly allowed.
        'def _block_resources(route, request):',
        '    u = request.url.lower()',
        '    if "m.media-amazon.com" in u or "images-na.ssl-images-amazon.com" in u:',
        '        return route.continue_()',
        '    if "goodreads.com" in u and ("/books/" in u or "/images/" in u):',
        '        return route.continue_()',
        '    if request.resource_type in ("stylesheet", "font", "media"):',
        '        return route.abort()',
        '    blocked = ("google-analytics.com", "doubleclick.net", "amazon-adsystem.com",',
        '               "fls-na.amazon.com", "amazonvideo.com", "googletagmanager.com",',
        '               "facebook.com", "twitter.com", "scorecardresearch.com",',
        '               "quantserve.com", "omtrdc.net")',
        '    if any(d in u for d in blocked):',
        '        return route.abort()',
        '    return route.continue_()',
        '',
        # ── Amazon "Click to continue" challenge handler ───────────────────────
        'def _handle_continue_challenge(page):',
        '    selectors = ["input#continue",',
        '                 "xpath=/html/body/div/div[1]/div[3]/div/div/form/div/div/span"]',
        '    for sel in selectors:',
        '        try:',
        '            btn = page.locator(sel)',
        '            if btn.count() > 0 and btn.first.is_visible(timeout=1000):',
        '                btn.first.click(timeout=3000)',
        '                page.wait_for_load_state("domcontentloaded", timeout=5000)',
        '                page.wait_for_timeout(1500)',
        '                return True',
        '        except Exception:',
        '            continue',
        '    return False',
        '',
        'def _new_context(browser):',
        '    ctx = browser.new_context(',
        '        viewport={"width": 1366, "height": 768},',
        '        user_agent=_ua,',
        '        locale=_locale,',
        '        timezone_id="America/New_York",',
        '        extra_http_headers=_extra_hdrs,',
        '    )',
        '    page = ctx.new_page()',
        '    page.add_init_script(_stealth_js)',
        # Block heavy resources before navigating so they never hit the network.
        # This is the single biggest speed-up for slow sites like Goodreads.
        '    page.route("**/*", _block_resources)',
        '    return ctx, page',
        '',
        # ONE Firefox browser for the life of this worker process -- this is
        # what keeps every fetch inside a single visible window instead of
        # opening a fresh one per URL.
        'with sync_playwright() as pw:',
        '    browser = pw.firefox.launch(',
        '        headless=_headless,',
        '        args=["--no-sandbox"],',
        '        firefox_user_prefs=_ff_prefs,',
        '    )',
        '    ctx, page = _new_context(browser)',
        '    for line in sys.stdin:',
        '        try:',
        '            req = json.loads(line)',
        '            time.sleep(0.3 + random.random() * 0.5)',
        # v6.2.33 ROOT-CAUSE FIX, carried into the persistent worker:
        # wait_until="networkidle" used to raise TimeoutError, discarding
        # the ENTIRE already-loaded page (zero content captured) whenever a
        # site never goes fully network-silent. Amazon product pages
        # routinely never satisfy networkidle even with the third-party
        # ad/analytics blocklist above, because they keep making
        # same-origin telemetry/personalization/live-pricing XHRs
        # indefinitely. Two-stage approach instead: navigate waiting only
        # for domcontentloaded (fast, reliable -- real page content is
        # present by then), then give networkidle a SHORT best-effort
        # window afterward for Cloudflare/bot-challenge JS redirects to
        # settle, without throwing the whole fetch away if that window
        # is not enough.
        '            try:',
        '                page.goto(req["url"], wait_until="domcontentloaded", timeout=int(req["timeout_ms"]))',
        '            except Exception:',
        # A hard navigation failure (not just a networkidle timeout, which
        # is handled separately below) may have left the page/context in a
        # bad state -- recreate just the context/page, NOT a new browser
        # process/window, and retry once.
        '                try:',
        '                    ctx.close()',
        '                except Exception:',
        '                    pass',
        '                ctx, page = _new_context(browser)',
        '                page.goto(req["url"], wait_until="domcontentloaded", timeout=int(req["timeout_ms"]))',
        '            try:',
        '                page.wait_for_load_state("networkidle", timeout=8000)',
        '            except Exception:',
        '                pass  # never went fully idle -- proceed with what loaded anyway',
        '            _handle_continue_challenge(page)',
        # Extra breathing room after networkidle -- some SPAs fire late XHRs.
        '            page.wait_for_timeout(1500 + random.randint(0, 500))',
        '            html = page.content()',
        # Safety net: if content is suspiciously small the challenge may
        # still be resolving (e.g. a slow Cloudflare turnstile). Wait and
        # re-sample.
        '            if len(html.encode("utf-8")) < 5000:',
        '                page.wait_for_timeout(4000 + random.randint(0, 1000))',
        '                html = page.content()',
        '            out = html.encode("utf-8", errors="replace")',
        '            sys.stdout.buffer.write(b"OK\\n")',
        '            sys.stdout.buffer.write((str(len(out)) + "\\n").encode("ascii"))',
        '            sys.stdout.buffer.write(out + b"\\n")',
        '            sys.stdout.buffer.flush()',
        '        except Exception as e:',
        '            out = str(e).encode("utf-8", errors="replace")',
        '            sys.stdout.buffer.write(b"ERR\\n")',
        '            sys.stdout.buffer.write((str(len(out)) + "\\n").encode("ascii"))',
        '            sys.stdout.buffer.write(out + b"\\n")',
        '            sys.stdout.buffer.flush()',
        '    try:',
        '        ctx.close()',
        '    except Exception:',
        '        pass',
        '    browser.close()',
    ])
    with tempfile.NamedTemporaryFile(
        mode='w', suffix='_mpp_browser_worker.py',
        delete=False, encoding='utf-8'
    ) as f:
        f.write(script)
        return f.name


def _stop_worker_locked():
    global _worker_proc, _worker_key, _worker_script
    proc = _worker_proc
    script_path = _worker_script
    _worker_proc = None
    _worker_key = None
    _worker_script = None

    if proc is not None:
        try:
            if proc.stdin:
                proc.stdin.close()
        except Exception:
            pass
        try:
            proc.terminate()
        except Exception:
            pass
    if script_path:
        try:
            os.unlink(script_path)
        except Exception:
            pass


def _stop_worker():
    with _worker_lock:
        _stop_worker_locked()


def browser_close():
    """Shut down the reusable browser worker (and its Firefox window), if
    one is running. Registered via atexit so it also runs on normal
    interpreter shutdown."""
    _stop_worker()


atexit.register(browser_close)
