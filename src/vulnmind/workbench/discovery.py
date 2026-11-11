"""Bounded, non-executing Express hints; not a JavaScript parser or taint proof."""
import hashlib
import os
import re
from pathlib import Path
from urllib.parse import urlsplit, parse_qs, unquote


def extend_snapshot(saved, scope=None):
    root = Path(saved['root'])
    texts = {}
    excluded = {'.git', '.venv', 'venv', 'node_modules', 'frontend', 'dist', 'build', 'coverage', '.devtools', 'test', 'tests'}
    total = 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in excluded and not Path(directory,d).is_symlink() and not Path(directory,d).is_junction())
        for name in sorted(names):
            path = Path(directory,name)
            if path.suffix not in {'.ts','.js'} or path.is_symlink() or path.is_junction(): continue
            if not path.resolve().is_relative_to(root): continue
            if len(texts) >= 400:
                saved['truncated'] = True
                continue
            if scope is not None:
                from vulnmind.security.scope import check_target
                from vulnmind.schemas import Target
                check_target(Target(type='repository',locator=str(path.parent)),scope)
            with path.open('rb') as stream: raw=stream.read(1_000_001)
            if len(raw)>1_000_000:
                saved['truncated']=True
                continue
            if not raw: continue
            total += len(raw)
            if total > 8_000_000: raise ValueError('Express indexing exceeds bounded input size')
            rel = path.relative_to(root).as_posix()
            saved['files'][rel] = hashlib.sha256(raw).hexdigest()
            texts[rel] = raw.decode('utf-8',errors='replace')
    for rel, text in texts.items():
        imports = {}
        for match in re.finditer(r"import\s*\{([^}]+)\}\s*from\s*['\"]([^'\"]+)['\"]",text):
            for entry in match[1].split(','):
                bits = entry.strip().split(' as ')
                imports[bits[-1].strip()] = (match[2], bits[0].strip())
        for match in re.finditer(r"\b(?:app|router)\.(get|post)\(\s*(['\"])(/[^'\"\n]*)\2\s*,([^\n]+)", text):
            method, _, path, tail = match.groups()
            body = tail
            handler = None
            handler_file = rel
            for alias, (module, exported) in imports.items():
                if not module.startswith('.') or not re.search(r'\b'+re.escape(alias)+r'\s*\(',tail): continue
                base = (root/rel).parent/module
                for suffix in ('.ts','.js'):
                    target = Path(str(base)+suffix).resolve()
                    if not target.is_relative_to(root): continue
                    target_rel = target.relative_to(root).as_posix()
                    content = texts.get(target_rel,'')
                    start = re.search(r'export\s+(?:async\s+)?function\s+'+re.escape(exported)+r'\b',content)
                    if start:
                        body = re.split(r'\nexport\s',content[start.start():],maxsplit=1)[0]
                        handler, handler_file = exported, target_rel
                        break
            # Ignore comments before extracting hints. Dynamic routes/imports remain unsupported.
            body = re.sub(r'/\*.*?\*/|//[^\n]*','',body,flags=re.S)
            params = sorted(set(re.findall(r'\breq\.(?:query|body)\.([A-Za-z_]\w*)',body)))[:6]
            signals = []
            if re.search(r'\.query\(\s*`[^`]*\$\{',body): signals.append('dynamic_sql')
            if '$where' in body: signals.append('dynamic_nosql')
            saved['routes'].append(dict(method=method.upper(),path=path,file=rel,line=text[:match.start()].count('\n')+1,
                handler=handler,handler_file=handler_file,parameters=params,signals=signals,encoding='json',
                source_hash=saved['files'][rel],basis='express_literal_heuristic',mapping_status='candidate'))
    saved['truncated'] = saved['truncated'] or len(saved['routes']) > 200
    saved['routes'] = saved['routes'][:200]
    saved['digest'] = hashlib.sha256(repr(sorted(saved['files'].items())).encode()).hexdigest()
    saved['indexing'] = dict(javascript_files=len(texts),limitation='Literal app/router registrations and named relative imports only; not runtime or taint proof')
    return saved


def discovered_routes(urls, origin):
    result = []
    for url in urls[:200]:
        if not isinstance(url,str): continue
        p = urlsplit(url)
        if f'{p.scheme}://{p.netloc}' != origin or p.username or p.password: continue
        path = p.path or '/'
        if any(c in unquote(path) for c in '{}<>') or Path(path).suffix in {'.js','.css','.png','.jpg','.svg','.woff','.ico'}: continue
        params = [k for k in parse_qs(p.query) if 0 < len(k) <= 64][:6]
        result.append(dict(path=path,method='GET',parameters=params,file=None,handler=None,
                           basis='crawler_observed',mapping_status='candidate'))
    return result


def price_actions(actions, routing, budget, *, authenticated=False):
    """Fix actual provider and reserve worst-case request costs before planning."""
    costs = {'hexstrike.sqlmap_scan':300,'hexstrike.dalfox_xss_scan':120,'hexstrike.nuclei_scan':20}
    for action in actions:
        choice = routing['choices'][action['id']]
        tool = choice['selected']
        # Exact builtin probes support JSON/auth; current MCP adapters do not.
        fallback = (authenticated or action['method'] != 'GET' or action['kind']=='cors'
                    or (tool in costs and budget < costs[tool]))
        if fallback and tool and tool.startswith('hexstrike.'):
            tool = 'builtin.'+action['kind']
            choice.update(selected=tool,reason='request_context_or_budget_builtin_fallback')
        action['builtin_cost'] = action['cost']
        action['execution_tool'] = tool
        action['cost'] = costs.get(tool,action['cost'])
    return actions


def independent_followup(action, result):
    """A bounded builtin check after an inconclusive external SQL hypothesis."""
    if (result.get('external_tool')=='hexstrike.sqlmap_scan' and result.get('verdict')=='inconclusive'
            and 'dynamic_sql' in action.get('source',{}).get('signals',[]) and not action.get('followup_of')):
        followup=dict(action)
        followup.update(id=hashlib.sha256((action['id']+':builtin-review').encode()).hexdigest()[:20],
                        cost=action['builtin_cost'],execution_tool='builtin.'+action['kind'],followup_of=action['id'])
        return followup
    return None
