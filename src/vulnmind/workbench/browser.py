"""Bounded browser verification for XSS behavior. No downloads, no cross-origin traffic."""
import hashlib
import time


class BrowserUnavailable(RuntimeError):
    pass


class BrowserRunner:
    """Headless Edge/Chromium navigation with an explicit request budget.

    Every network attempt is counted, and requests outside the authorized origin
    are aborted before they leave the host. Dialogs are recorded as evidence of
    script execution; DOM snapshots are hashed and bounded.
    """

    def __init__(self, scope, origin, *, channel='msedge', max_requests=120, timeout_ms=12000,
                 dom_bytes=200_000, executable=None, transport=None):
        self.scope = scope
        self.origin = origin.rstrip('/')
        self.channel = channel
        self.max_requests = max_requests
        self.timeout_ms = timeout_ms
        self.dom_bytes = dom_bytes
        self.executable = executable
        self.transport = transport

    def _launch(self, playwright):
        options = dict(headless=True,args=['--disable-background-networking','--disable-component-update',
            '--disable-sync','--no-pings','--force-webrtc-ip-handling-policy=disable_non_proxied_udp'])
        if self.executable:
            return playwright.chromium.launch(executable_path=self.executable, **options)
        return playwright.chromium.launch(channel=self.channel, **options)

    def run(self, url, *, wait_ms=2500):
        from urllib.parse import urlsplit
        if not url.startswith(self.origin + '/'):
            raise ValueError('browser target is outside the authorized origin')
        parsed = urlsplit(url)
        if parsed.hostname != urlsplit(self.origin).hostname:
            raise ValueError('browser target host mismatch')
        if self.scope is None or self.transport is None:
            raise BrowserUnavailable('browser requires an authorized isolated HTTP transport')
        try:
            from playwright.sync_api import sync_playwright, Error as PlaywrightError
        except ImportError as exc:  # pragma: no cover - dependency boundary
            raise BrowserUnavailable('playwright is not installed') from exc
        requests = []
        blocked = []
        dialogs = []
        console = []
        try:
            with sync_playwright() as playwright:
                try:
                    browser = self._launch(playwright)
                except Exception as exc:  # noqa: BLE001 - engine/browser availability
                    raise BrowserUnavailable('browser launch failed: ' + type(exc).__name__) from exc
                context = browser.new_context(java_script_enabled=True, service_workers='block', accept_downloads=False)
                if not hasattr(context,'route_web_socket'):
                    browser.close()
                    raise BrowserUnavailable('browser version must support WebSocket blocking')
                context.route_web_socket('**/*',lambda ws:ws.close())
                page = context.new_page()
                page.set_default_timeout(self.timeout_ms)

                def guard(route):
                    target = route.request.url
                    if target.startswith(self.origin + '/') and route.request.method in {'GET','HEAD'}:
                        if len(requests) >= self.max_requests:
                            blocked.append(target[:200])
                            route.abort()
                            return
                        requests.append(target.split('?')[0])
                        # Chromium never opens the target connection. The broker checks
                        # scope, resolved IPs and performs one pinned, non-redirecting hop.
                        response=self.transport(route.request.method,target)
                        if response.truncated:
                            blocked.append(target[:200]);route.abort();return
                        headers={k:v for k,v in response.headers.items() if k.lower() not in
                            {'content-length','transfer-encoding','content-encoding','set-cookie'}}
                        route.fulfill(status=response.status_code,headers=headers,body=response.body)
                    else:
                        blocked.append(target[:200])
                        route.abort()

                def dismiss(dialog):
                    dialogs.append(dict(type=dialog.type, message=dialog.message[:300]))
                    dialog.dismiss()

                context.route('**/*', guard)
                page.on('dialog', dismiss)
                page.on('console', lambda message: console.append(dict(type=message.type, text=message.text[:200]))
                        if len(console) < 20 else None)
                started = time.monotonic()
                status = None
                try:
                    response = page.goto(url, wait_until='domcontentloaded', timeout=self.timeout_ms)
                    status = response.status if response else None
                except PlaywrightError as exc:
                    if 'Timeout' not in type(exc).__name__ and 'Timeout' not in str(exc):
                        raise
                page.wait_for_timeout(wait_ms)
                raw_html=page.content().encode('utf-8')
                html = raw_html[:self.dom_bytes].decode('utf-8',errors='ignore')
                html_truncated=len(raw_html)>self.dom_bytes
                title = page.title()[:300]
                elapsed = int((time.monotonic() - started) * 1000)
                context.close()
                browser.close()
        except BrowserUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 - treat unknown browser failure as not tested
            raise BrowserUnavailable('browser run failed: ' + type(exc).__name__) from exc
        return dict(status_code=status, requests=len(requests), request_paths=requests[:40],
                    blocked=blocked[:10], dialogs=dialogs, console=console, title=title,
                    elapsed_ms=elapsed, html=html, sha256=hashlib.sha256(html.encode()).hexdigest(),
                    dom_bytes=len(html.encode('utf-8')),html_truncated=html_truncated)


def evaluate_browser(action, outcome, marker='vm-probe'):
    """Only a real dialog counts as script execution; DOM text alone is not confirmation."""
    dialogs = outcome.get('dialogs') or []
    html = outcome.get('html', '')
    executable = any(dialog.get('type') == 'alert' for dialog in dialogs)
    if action.get('detector_version')=='7.0.0':
        marker=action['marker']
        proof=outcome.get('causal_runs',[])
        matches=lambda run:any(d.get('type')=='alert' and d.get('message')==marker for d in run.get('dialogs',[]))
        executable=(len(proof)==3 and not matches(proof[0]) and matches(proof[1]) and matches(proof[2])
            and all(not r.get('blocked') and not r.get('html_truncated') and r.get('status_code')==200 for r in proof))
    reflected = marker in html
    if executable:
        verdict, behavior = 'candidate', 'script_execution'
        detail = '浏览器执行了页面注入的脚本（dialog 类型 ' + ','.join(dict.fromkeys(d.get('type', '') for d in dialogs)) + '）；仅确认脚本执行，不扩大为持久化利用'
    elif reflected:
        verdict, behavior = 'inconclusive', None
        detail = '标记出现在 DOM 但未触发脚本执行；可能是编码或上下文不匹配'
    else:
        verdict, behavior = 'inconclusive', None
        detail = '未观察到脚本执行或标记反射；不足以判断不存在'
    return dict(action_id=action['id'], kind=action['kind'], url=action['url'], method='GET',
                parameter=action.get('parameter', ''), category=action['category'],
                verdict=verdict, behavior=behavior, detail=detail, source=action.get('source') or {},
                statuses=[outcome.get('status_code')] if outcome.get('status_code') else [],
                response_hashes=[outcome['sha256']],
                browser=dict(requests=outcome.get('requests'), blocked=len(outcome.get('blocked') or []),
                             dialogs=dialogs, title=outcome.get('title'), elapsed_ms=outcome.get('elapsed_ms')),
                detector_version=action.get('detector_version', '2.2.0'))
