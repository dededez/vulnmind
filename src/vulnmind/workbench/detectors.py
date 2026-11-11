"""Versioned, bounded detectors. Findings describe evidence, never exploitability."""
import hashlib
import json
import re
from urllib.parse import quote,urlencode,urlsplit

from vulnmind.workbench import investigation as legacy

CATALOG = {
    'sql_boolean': ('sql_injection', 'SQL 布尔重复差分', 6),
    'sql_error': ('sql_injection', 'SQL 错误差分', 3),
    'xss_context': ('xss', 'HTML 注入上下文', 3),
    'template_expression': ('ssti', '模板表达式差分', 3),
    'reflection': ('xss', '输入反射', 3),
    'cors': ('cors', '跨域响应策略', 3),
    'security_headers': ('security_headers', '响应安全头', 3),
    'response_disclosure': ('information_disclosure', '匿名响应信息暴露', 2),
    'redirect_location': ('open_redirect', '跳转目标差分（不跟随）', 3),
    'nosql_error': ('nosql_injection', 'NoSQL 输入类型差分', 3),
    'sql_login': ('sql_injection', '登录表单 SQL 注入', 3),
    'weak_password': ('broken_authentication', '管理员弱口令', 2),
    'config_exposure': ('information_disclosure', '匿名应用配置暴露', 2),
    'well_known_exposure': ('information_disclosure', '常见暴露端点', 2),
    'browser_xss': ('xss', '浏览器 XSS 执行复核', 120),
    'auth_idor': ('broken_access_control', '跨账号购物篮读取', 4),
    'exposed_file': ('information_disclosure', '匿名文件下载', 2),
}
SYNTHETIC_KINDS = {'sql_login', 'weak_password', 'config_exposure', 'well_known_exposure', 'browser_xss', 'auth_idor', 'exposed_file'}
SIGNALS = {
    'dynamic_sql': 'sql_injection', 'dynamic_nosql': 'nosql_injection', 'dynamic_template': 'ssti',
    'outbound_request': 'ssrf', 'file_access': 'path_traversal',
    'process_execution': 'command_injection', 'deserialization': 'deserialization',
    'xml_parse': 'xxe', 'redirect': 'open_redirect',
    'static_directory': 'information_disclosure',
}


def classify(mapping):
    items = []
    for route in mapping['routes']:
        categories = {SIGNALS[s] for s in route.get('signals', []) if s in SIGNALS}
        if route.get('parameters'):
            categories.update(['sql_injection', 'xss', 'ssti'])
        if route['method'] == 'GET':
            categories.update(['cors', 'security_headers', 'information_disclosure'])
        for category in sorted(categories):
            kinds = [k for k, v in CATALOG.items() if v[0] == category]
            supported = [s for s in route.get('signals', []) if SIGNALS.get(s) == category]
            items.append(dict(route_id=route['id'], category=category, source_signals=supported,
                              basis='static_signal' if supported else 'generic_hypothesis',
                              tools=kinds, status='available' if kinds and route.get('executable') else 'needs_context',
                              note='静态信号不是污点传播证明；缺少专用验证器的类型仅列为调查线索'))
    return items


def actions_for(mapping, enabled, *, limit=60):
    actions = []
    for route in mapping['routes']:
        if not route.get('executable'): continue
        parameters = [p for p in route.get('parameters', [])[:2]
                      if not re.search('password|passwd|token|secret|cookie|authorization', p, re.I)]
        for kind in enabled:
            if kind not in CATALOG: raise ValueError('unknown detector')
            # Probe kinds target fixed endpoints; they must never be attached to
            # arbitrary routes discovered from source.
            if kind in SYNTHETIC_KINDS: continue
            if kind.startswith('sql_') and 'dynamic_nosql' in route.get('signals', []) and 'dynamic_sql' not in route.get('signals', []): continue
            if kind == 'nosql_error' and 'dynamic_nosql' not in route.get('signals', []): continue
            if kind == 'redirect_location' and 'redirect' not in route.get('signals', []): continue
            # Anonymous exposure checks only where the source shows a disclosure surface;
            # probing every GET route would waste the bounded request budget.
            if kind == 'response_disclosure' and not set(route.get('signals', [])) & {'static_directory', 'file_access'}: continue
            # Header probes use GET only; do not create unsolicited POST bodies.
            parameterless = {'cors', 'security_headers', 'response_disclosure'}
            targets = [''] if kind in parameterless and route['method'] == 'GET' else parameters if kind not in parameterless else []
            for parameter in targets:
                action = dict(route_id=route['id'], method=route['method'], url=route['url'], parameter=parameter,
                              parameters=route['parameters'], encoding=route.get('encoding', 'json'), kind=kind,
                              category=CATALOG[kind][0], cost=CATALOG[kind][2], detector_version='2.0.0',
                              source=dict(file=route.get('file'), line=route.get('line'), handler=route.get('handler'),
                                          signals=route.get('signals', []), linked=route['source_link_verified']))
                action['id'] = hashlib.sha256(json.dumps(action, sort_keys=True).encode()).hexdigest()[:20]
                actions.append(action)
    ordinals = {}; counts = {}
    for action in actions:
        kind = action['kind']; ordinals[action['id']] = counts.get(kind, 0); counts[kind] = counts.get(kind, 0) + 1
    def priority(a):
        supported = any(SIGNALS.get(s) == a['category'] for s in a['source']['signals'])
        return (not supported, ordinals[a['id']], list(enabled).index(a['kind']), a['url'], a['parameter'])
    return sorted(actions, key=priority)[:limit]


def synthetic_actions(origin, enabled, *, auth_probe=False, existing=None, account=False):
    """Bounded actions for endpoints the source index cannot prove.

    Login probes are gated by their own flag because they submit credentials to
    an authentication endpoint; exposure probes only issue anonymous GETs.
    Cross-account checks require the one authorized test account.
    """
    origin = origin.rstrip('/')
    taken = {(a.get('kind'), a['method'], a['url']) for a in (existing or [])}
    specs = []
    if account and 'auth_idor' in enabled:
        specs.append(('auth_idor', 'GET', origin + '/rest/basket/0'))
    if auth_probe:
        if 'sql_login' in enabled:
            specs.append(('sql_login', 'POST', origin + '/rest/user/login'))
        if 'weak_password' in enabled:
            specs.append(('weak_password', 'POST', origin + '/rest/user/login'))
    if 'config_exposure' in enabled:
        specs.append(('config_exposure', 'GET', origin + '/rest/admin/application-configuration'))
    if 'well_known_exposure' in enabled:
        for path in ('/metrics', '/support/logs', '/ftp/'):
            specs.append(('well_known_exposure', 'GET', origin + path))
    if 'browser_xss' in enabled:
        marker = '<iframe src="javascript:alert(1)">'
        specs.append(('browser_xss', 'GET', origin + '/#/search?q=' + quote(marker, safe='')))
    actions = []
    for kind, method, url in specs:
        if (kind, method, url) in taken:
            continue
        action = dict(route_id='synthetic:' + kind + ':' + url, method=method, url=url,
                      parameter='q' if kind == 'browser_xss' else '', parameters=[], encoding='json', kind=kind,
                      category=CATALOG[kind][0], cost=CATALOG[kind][2], detector_version='2.2.0',
                      source=dict(file=None, line=None, handler=None, signals=[], linked=False))
        action['id'] = hashlib.sha256(json.dumps(action, sort_keys=True).encode()).hexdigest()[:20]
        actions.append(action)
        taken.add((kind, method, url))
    return actions


def file_followups(origin, listing, *, limit=3):
    """Turn one exposed-directory listing into a few bounded file reads.

    Handles the JSON array form used by the lab's index view and plain HTML links.
    Only names with a risky extension are followed; directories are skipped.
    """
    origin = origin.rstrip('/')
    names = []
    try:
        parsed = json.loads(listing)
        if isinstance(parsed, list):
            names = [value for value in parsed if isinstance(value, str)]
    except (TypeError, ValueError):
        names = re.findall(r'href="([^"?]+)"', listing or '')
    risky = ('.bak', '.md', '.kdbx', '.zip', '.yml', '.yaml', '.json', '.log', '.pdf', '.ini', '.conf')
    actions = []
    seen = set()
    for name in names:
        clean = name.strip().lstrip('/')
        if not clean or clean in seen or '/' in clean or clean in {'..', '.', 'quarantine'}:
            continue
        if not clean.lower().endswith(risky):
            continue
        seen.add(clean)
        action = dict(route_id='followup:ftp:' + clean, method='GET', url=origin + '/ftp/' + quote(clean, safe=''),
                      parameter='', parameters=[], encoding='json', kind='exposed_file',
                      category=CATALOG['exposed_file'][0], cost=CATALOG['exposed_file'][2], detector_version='2.4.0',
                      filename=clean,
                      source=dict(file=None, line=None, handler=None, signals=['static_directory'], linked=False))
        action['id'] = hashlib.sha256(json.dumps(action, sort_keys=True).encode()).hexdigest()[:20]
        actions.append(action)
        if len(actions) >= limit:
            break
    return actions


def requests_for(action):
    kind = action['kind']
    if kind in {'browser_xss', 'auth_idor'}:
        raise ValueError('this action is executed by its own bounded runner')
    if kind == 'exposed_file':
        return [dict(method='GET', url=action['url'], body='', headers={'Accept': '*/*'}, variant=i) for i in range(2)]
    if kind in {'sql_login', 'weak_password'}:
        pairs = {'sql_login': [('vm_probe_control@example.invalid', 'vm_control_a82'),
                               ("' OR 1=1--", 'vm_control_a82'),
                               ("admin@juice-sh.op'--", 'vm_control_a82')],
                 'weak_password': [('admin@juice-sh.op', 'vm_control_a82'),
                                   ('admin@juice-sh.op', 'admin123')]}[kind]
        return [dict(method='POST', url=action['url'], body=json.dumps(dict(email=email, password=password)),
                     headers={'Content-Type': 'application/json', 'Accept': 'application/json'}, variant=i)
                for i, (email, password) in enumerate(pairs)]
    if kind in {'config_exposure', 'well_known_exposure'}:
        accept = 'application/json' if kind == 'config_exposure' else 'text/html,application/json'
        return [dict(method='GET', url=action['url'], body='', headers={'Accept': accept}, variant=i) for i in range(2)]
    if kind in {'response_disclosure', 'redirect_location', 'nosql_error'}:
        values = {'response_disclosure': ['', ''],
                  'redirect_location': ['/', 'https://vm-redirect-a.invalid/', 'https://vm-redirect-b.invalid/'],
                  'nosql_error': ['vm_control_a82', {'vm_probe': 'value'}, 'vm_control_b93']}[kind]
        result = []
        for i, value in enumerate(values):
            fields = {p: 'vm_control_a82' for p in action['parameters']} if kind != 'response_disclosure' else {}
            if action['parameter']:
                fields[action['parameter']] = value
            headers = {'Accept': 'application/json, text/html'}; body = ''; url = action['url']
            if action['method'] == 'GET':
                pairs = []
                for k, v in fields.items():
                    if isinstance(v, dict):
                        pairs.extend((k + '[' + sub + ']', val) for sub, val in v.items())
                    else:
                        pairs.append((k, v))
                if pairs: url += '?' + urlencode(pairs)
            elif action['encoding'] == 'form':
                body = urlencode(fields); headers['Content-Type'] = 'application/x-www-form-urlencoded'
            else:
                body = json.dumps(fields); headers['Content-Type'] = 'application/json'
            result.append(dict(method=action['method'], url=url, body=body, headers=headers, variant=i))
        return result
    if action.get('boolean_closures') and kind == 'sql_boolean':
        result = []
        for closure in ("'", "')", "'))"):
            yes = closure + ' AND 1=1 -- '
            no = closure + ' AND 1=2 -- '
            for value in ('', yes, no, '', no, yes):
                fields = {p: '1' for p in action['parameters']}
                fields[action['parameter']] = value
                headers = {'Accept': 'application/json, text/html'}; body = ''; url = action['url']
                if action['method'] == 'GET':
                    url += '?' + urlencode(fields)
                elif action['encoding'] == 'form':
                    body = urlencode(fields); headers['Content-Type'] = 'application/x-www-form-urlencoded'
                else:
                    body = json.dumps(fields); headers['Content-Type'] = 'application/json'
                result.append(dict(method=action['method'], url=url, body=body, headers=headers, variant=len(result)))
        return result
    if kind in {'reflection', 'template_expression', 'sql_error'}:
        return legacy.requests_for(action)
    values = {
        'sql_boolean': ['1', "1' AND '1'='1' -- ", "1' AND '1'='2' -- ",
                        '1', "1' AND '1'='2' -- ", "1' AND '1'='1' -- "],
        # Inert custom tags test HTML parsing context; no script execution claimed.
        'xss_context': ['vm_control_a82', '<vm-probe data-id="b19">b19</vm-probe>',
                        '<vm-probe data-id="c31">c31</vm-probe>'],
        'cors': ['', '', ''],
        'security_headers': ['', '', ''],
    }[kind]
    result = []
    for i, value in enumerate(values):
        fields = {p: 'vm_control_a82' for p in action['parameters']}
        if action['parameter']:
            fields[action['parameter']] = value
        headers = {'Accept': 'application/json, text/html'}; body = ''; url = action['url']
        if kind == 'cors' and i:
            headers['Origin'] = f'https://vm-origin-{i}.invalid'
        if action['method'] == 'GET':
            if fields: url += '?' + urlencode(fields)
        elif action['encoding'] == 'form':
            body = urlencode(fields); headers['Content-Type'] = 'application/x-www-form-urlencoded'
        else:
            body = json.dumps(fields); headers['Content-Type'] = 'application/json'
        result.append(dict(method=action['method'], url=url, body=body, headers=headers, variant=i))
    return result


def evaluate(action, responses):
    if action['kind'] in {'response_disclosure', 'redirect_location', 'nosql_error'}:
        return evaluate_extended(action, responses)
    if action.get('boolean_closures') and action['kind'] == 'sql_boolean':
        if len(responses) != 18: raise ValueError('incomplete closure response set')
        original = {k: v for k, v in action.items() if k != 'boolean_closures'}
        results = [evaluate(original, responses[i:i + 6]) for i in range(0, 18, 6)]
        for index, result in enumerate(results):
            group = responses[index * 6:index * 6 + 6]
            bodies = [r['body'] for r in group]
            complete = all(200 <= r['status_code'] < 300 and not r['truncated'] for r in group)
            reflected = any('AND 1=1' in body or 'AND 1=2' in body for body in bodies)
            stable = bodies[0] == bodies[3] and bodies[1] == bodies[5] and bodies[2] == bodies[4] and bodies[1] != bodies[2]
            if complete and stable and not reflected and bodies[0].strip():
                result.update(verdict='candidate', behavior='repeatable_boolean_difference',
                              detail='重复基线稳定；两种顺序的真条件与假条件各自一致且相互不同，未反射条件文本；SQL 注入候选，需复核因果')
        result = next((r for r in results if r['verdict'] == 'candidate'), results[0])
        result['response_hashes'] = [r['sha256'] for r in responses]
        result['statuses'] = [r['status_code'] for r in responses]
        return result

    if len(responses) != CATALOG[action['kind']][2]: raise ValueError('incomplete detector response set')
    kind = action['kind']
    if kind in {'sql_login', 'weak_password', 'config_exposure', 'well_known_exposure', 'exposed_file'}:
        return evaluate_probe(action, responses)
    if kind in {'reflection', 'template_expression', 'sql_error'}:
        result = legacy.evaluate(action, responses)
    else:
        bodies = [r['body'] for r in responses]
        headers = [{k.lower(): v for k, v in r.get('headers', {}).items()} for r in responses]
        complete = all(200 <= r['status_code'] < 300 and not r['truncated'] for r in responses)
        verdict = 'inconclusive'; behavior = None; detail = '未取得足够信号，不能据此排除问题'
        if complete and kind == 'sql_boolean':
            # Raw reflection and unstable baselines cannot establish SQL causality.
            reflected = any("AND '1'=" in body or 'vm_control_' in body for body in bodies)
            stable = bodies[0] == bodies[3] == bodies[1] == bodies[5] and bodies[2] == bodies[4] and bodies[0] != bodies[2]
            if stable and not reflected and len(bodies[0].strip()) > 0:
                verdict = 'candidate'; behavior = 'repeatable_boolean_difference'
                detail = '两组相反顺序的真假条件响应一致，真条件与重复基线一致；仅为 SQL 注入候选，未读取数据库内容'
        elif complete and kind == 'xss_context':
            from html.parser import HTMLParser
            class Probe(HTMLParser):
                def __init__(self):
                    super().__init__(); self.ids = []; self.blocked = []
                def handle_starttag(self, tag, attrs):
                    if tag in {'textarea', 'title', 'script', 'style', 'template', 'xmp'}: self.blocked.append(tag)
                    if tag == 'vm-probe' and not self.blocked: self.ids.append(dict(attrs).get('data-id'))
                def handle_endtag(self, tag):
                    if tag in self.blocked: self.blocked.remove(tag)
            ids = []
            for body in bodies:
                p = Probe(); p.feed(body); ids.append(p.ids)
            if (all('text/html' in h.get('content-type', '').lower() for h in headers)
                    and not ids[0] and ids[1] == ['b19'] and ids[2] == ['c31']):
                verdict = 'candidate'; behavior = 'html_markup_injection'
                detail = '两个不同的惰性标签出现在 HTML 元素上下文；未运行浏览器，不能确认 JavaScript 执行或 XSS 可利用'
        elif complete and kind == 'cors':
            reflected = all(headers[i].get('access-control-allow-origin') == f'https://vm-origin-{i}.invalid' for i in (1, 2))
            credentials = all(headers[i].get('access-control-allow-credentials', '').lower() == 'true' for i in (1, 2))
            if reflected and credentials:
                verdict = 'candidate'; behavior = 'credentialed_origin_reflection'
                detail = '两个无关 Origin 均被允许且响应声明允许凭据；仍需浏览器凭据策略和敏感响应证明'
        elif complete and kind == 'security_headers':
            if all('text/html' in h.get('content-type', '').lower() for h in headers):
                missing = [name for name in ('content-security-policy', 'x-content-type-options') if all(name not in h for h in headers)]
                if missing:
                    verdict = 'candidate'; behavior = 'missing_defense_headers'; detail = 'HTML 响应重复缺少防御头：' + ', '.join(missing) + '；属于加固建议，不是独立漏洞证明'
        result = dict(action_id=action['id'], kind=kind, url=action['url'], method=action['method'], parameter=action['parameter'],
                      source=action['source'], verdict=verdict, behavior=behavior, detail=detail,
                      response_hashes=[r['sha256'] for r in responses], statuses=[r['status_code'] for r in responses])
    return {**result, 'category': action['category'], 'detector_version': action['detector_version']}


def evaluate_extended(action, responses):
    kind = action['kind']
    if len(responses) != CATALOG[kind][2]: raise ValueError('incomplete detector response set')
    verdict = 'inconclusive'; behavior = None; detail = '未取得足够信号，不能据此排除问题'
    usable = not any(r['truncated'] or r['status_code'] in {401, 403} for r in responses)
    if usable and kind == 'redirect_location':
        locations = [{k.lower(): v for k, v in r.get('headers', {}).items()}.get('location', '') for r in responses]
        if all(300 <= responses[i]['status_code'] < 400 and locations[i] == f'https://vm-redirect-{letter}.invalid/' for i, letter in [(1, 'a'), (2, 'b')]) and not locations[0].startswith('https://vm-redirect-'):
            verdict = 'candidate'; behavior = 'external_redirect_control'; detail = '两个独立惰性外域均原样出现在 Location；未跟随跳转，需确认业务是否有意提供外链跳转'
    elif usable and kind == 'nosql_error':
        signatures = ('mongoerror', 'mongoservererror', 'bsonerror', 'cast to string failed', '$where', 'argument must be a string')
        if any(s in responses[1]['body'].lower() and all(s not in responses[i]['body'].lower() for i in [0, 2]) for s in signatures):
            verdict = 'candidate'; behavior = 'nosql_type_error'; detail = '对象类型输入独有 NoSQL 错误；这是类型处理线索，不能确认查询语义被控制'
    elif usable and kind == 'response_disclosure' and all(200 <= r['status_code'] < 300 for r in responses):
        bodies = [r['body'] for r in responses]
        # A listing must have actual links, not just a page mentioning a directory.
        listing = lambda b: bool(re.search(r'(?is)(?:<title>[^<]*(?:listing|index of)|class=[\"\'](?:directory|view-tiles))', b) and re.search(r'(?i)href=[\"\'][^\"\']+\.(?:log|bak|zip|kdbx|yml|yaml|md|pdf)', b))
        debug = lambda b: bool(re.search(r'(?m)^\s*at\s+\S+.*(?:[/\\]node_modules[/\\]|:\d+:\d+\))', b))
        if all(listing(b) for b in bodies):
            verdict = 'candidate'; behavior = 'anonymous_directory_listing'; detail = '重复匿名响应包含目录列表及文件链接；未下载文件，文件是否敏感需按内容与访问策略复核'
        elif all(debug(b) for b in bodies):
            verdict = 'candidate'; behavior = 'debug_stack_disclosure'; detail = '重复匿名响应暴露服务端堆栈位置；需排除文档示例或有意公开的调试内容'
    return dict(action_id=action['id'], kind=kind, url=action['url'], method=action['method'], parameter=action['parameter'],
                category=action['category'], verdict=verdict, behavior=behavior, detail=detail,
                source=action.get('source') or {}, statuses=[r['status_code'] for r in responses],
                response_hashes=[r['sha256'] for r in responses])


def evaluate_idor(action,responses,own_bid):
    """Cross-account read check: own basket baseline plus two neighbouring baskets."""
    verdict='inconclusive';behavior=None
    detail='未取得足够信号，不能据此排除问题'
    def usable(r): return 200<=r['status_code']<300 and not r['truncated']
    def body(r):
        try: return json.loads(r['body'])
        except (TypeError,ValueError): return None
    baseline=body(responses[0]) if responses else None
    own_ok=bool(responses) and usable(responses[0]) and isinstance(baseline,dict) and isinstance(baseline.get('data'),dict)
    leaked=[]
    if own_ok:
        for response in responses[1:]:
            data=body(response)
            if not usable(response) or not isinstance(data,dict): continue
            payload=data.get('data')
            if isinstance(payload,dict) and payload and payload.get('id') not in (None,own_bid):
                leaked.append(payload.get('id'))
    if not own_ok:
        detail='本人购物篮基线未取得数据；会话或端点不可用，不做越权判断'
    elif leaked:
        verdict='candidate';behavior='cross_account_read'
        detail='以本人会话读取到其他购物篮（ID '+','.join(str(value) for value in leaked[:5])+'）；仅确认跨账号读取，未修改数据'
    elif responses[1:] and all(r['status_code'] in {401,403} for r in responses[1:]):
        detail='其他购物篮返回 401/403；当前会话下未观察到越权读取'
    return dict(action_id=action['id'],kind=action['kind'],url=action['url'],method='GET',parameter='',
        category=action['category'],verdict=verdict,behavior=behavior,detail=detail,source=action.get('source') or {},
        statuses=[r['status_code'] for r in responses],response_hashes=[r['sha256'] for r in responses])


def evaluate_probe(action, responses):
    kind = action['kind']
    bodies = [r['body'] for r in responses]
    verdict = 'inconclusive'; behavior = None; detail = '未取得足够信号，不能据此排除问题'
    usable = not any(r['truncated'] for r in responses)

    def login(body):
        try: data = json.loads(body)
        except (TypeError, ValueError): return None
        auth = data.get('authentication') if isinstance(data, dict) else None
        return auth if isinstance(auth, dict) and auth.get('token') else None

    if kind in {'sql_login', 'weak_password'}:
        if not usable:
            detail = '登录端点响应被截断；不据此判断'
        elif login(bodies[0]):
            detail = '对照请求也返回了会话，无法归因；不作为注入或弱口令证据'
        else:
            hit = next((i + 1 for i, body in enumerate(bodies[1:]) if login(body)), None)
            if hit:
                auth = login(bodies[hit]) or {}
                email = str(auth.get('umail', ''))[:120]
                if kind == 'sql_login':
                    verdict = 'candidate'; behavior = 'authentication_bypass'
                    detail = '注入载荷获得会话（用户 ' + email + '），对照请求未获得；仅确认认证绕过行为，未使用该会话'
                else:
                    verdict = 'candidate'; behavior = 'default_credentials'
                    detail = '弱口令获得会话（用户 ' + email + '）；仅确认口令强度问题，未使用该会话'
    elif kind == 'config_exposure':
        complete = all(200 <= r['status_code'] < 300 and not r['truncated'] for r in responses)
        if complete:
            try: data = json.loads(bodies[0])
            except (TypeError, ValueError): data = None
            if isinstance(data, dict) and isinstance(data.get('config'), dict) and data['config']:
                verdict = 'candidate'; behavior = 'anonymous_configuration'
                detail = '匿名响应返回应用配置 JSON；是否包含敏感项需按字段复核'
    elif kind == 'exposed_file':
        statuses_ok = all(200 <= r['status_code'] < 300 for r in responses)
        truncated = any(r['truncated'] for r in responses)
        body = bodies[0].strip()
        error_page = ('<title>Error' in bodies[0][:400] or '<title>404' in bodies[0][:400]
                      or bodies[0].strip().startswith('{"status":"error"'))
        if statuses_ok and body and not error_page:
            verdict = 'candidate'; behavior = 'anonymous_file_download'
            detail = ('匿名下载到非空文件（' + str(action.get('filename') or '') + '，' + str(len(body)) + ' 字符）；'
                      + ('响应被截断，仅部分内容进入证据' if truncated else '文件敏感度需按内容复核'))
    else:
        # well_known_exposure: classified by the probed endpoint. Metrics bodies
        # legitimately change between two requests (our own request increments
        # counters), so only logs/static listings require identical replies.
        complete = all(200 <= r['status_code'] < 300 and not r['truncated'] for r in responses)
        low = bodies[0].lower()
        if complete and urlsplit(action['url']).path.startswith('/metrics') \
                and all('# help' in body.lower() and '# type' in body.lower() for body in bodies):
            verdict = 'candidate'; behavior = 'anonymous_metrics'; detail = '匿名 /metrics 返回 Prometheus 指标；未评估其中业务敏感度'
        elif complete and bodies[0] == bodies[1]:
            path = urlsplit(action['url']).path
            if path.startswith('/support/logs') and 'href=' in low and '.log' in low:
                verdict = 'candidate'; behavior = 'log_directory_exposed'; detail = '匿名访问日志目录返回文件链接；未下载日志内容'
            elif path.startswith('/ftp') and 'href=' in low and any(ext in low for ext in ('.bak', '.md', '.kdbx', '.yml', '.zip')):
                verdict = 'candidate'; behavior = 'static_directory_listing'; detail = '匿名静态目录列出可下载文件；是否敏感需按文件名与内容复核'
    return dict(action_id=action['id'], kind=kind, url=action['url'], method=action['method'], parameter=action['parameter'],
                category=action['category'], verdict=verdict, behavior=behavior, detail=detail,
                source=action.get('source') or {}, statuses=[r['status_code'] for r in responses],
                response_hashes=[r['sha256'] for r in responses],
                **(dict(filename=action['filename']) if action.get('filename') else {}))
