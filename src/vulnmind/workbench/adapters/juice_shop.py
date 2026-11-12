"""Juice Shop demonstration adapter. Not a generic application protocol."""
import hashlib
import json
from urllib.parse import quote,urlsplit
from vulnmind.workbench.detectors import CATALOG

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



def probe_requests(action):
    kind=action['kind']
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



def seeded_requests(origin,own):
    ids=([own]+[v for v in (1,2,3) if v!=own])[:4]
    return [dict(method='GET',url=origin.rstrip('/')+'/rest/basket/'+str(value),body='',
        headers={'Accept':'application/json'},variant=i) for i,value in enumerate(ids)]


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
