"""Parse authorized source as data with a pinned TypeScript compiler."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
from vulnmind.schemas import Target
from vulnmind.security.scope import check_target

ROOT=Path(__file__).resolve().parents[3]
EXCLUDED_DIRS={'.git','.venv','node_modules','dist','build','test','tests','e2e','cypress','.devtools','coverage'}
EXCLUDED_PREFIXES=('data/static','drafts','testdata','fixtures')
MAX_ROUTES=400


def _merged(routes):
    """Merge duplicate (method, path) declarations and keep bounded provenance."""
    merged={}
    dropped=0
    for route in routes:
        key=(route['method'],route['path'])
        if key not in merged:
            merged[key]=dict(route,
                parameters=list(dict.fromkeys(route.get('parameters',[]))),
                parameter_specs=list(route.get('parameter_specs',[])),
                signals=list(dict.fromkeys(route.get('signals',[]))),
                sources=[f"{route.get('file')}:{route.get('line')}"])
            continue
        dropped+=1
        current=merged[key]
        current['parameters']=list(dict.fromkeys(current['parameters']+route.get('parameters',[])))
        current['signals']=list(dict.fromkeys(current['signals']+route.get('signals',[])))
        seen={(spec.get('location'),spec.get('name')) for spec in current['parameter_specs'] if isinstance(spec,dict)}
        for spec in route.get('parameter_specs',[]):
            if isinstance(spec,dict) and (spec.get('location'),spec.get('name')) not in seen:
                current['parameter_specs'].append(spec);seen.add((spec.get('location'),spec.get('name')))
        if len(current['sources'])<8:
            current['sources'].append(f"{route.get('file')}:{route.get('line')}")
    return list(merged.values()),dropped


def extend_ast_snapshot(saved,scope):
    root=Path(saved['root']);texts={};total=0;skipped=0
    compiler=ROOT/'.devtools/ast-parser/node_modules/typescript/lib/typescript.js'
    manifest=json.loads((Path(__file__).parent/'resources/ast_parser.json').read_text())
    if hashlib.sha256(compiler.read_bytes()).hexdigest()!=manifest['sha256']: raise ValueError('AST parser integrity mismatch')
    for directory,dirs,names in os.walk(root,followlinks=False):
        def wanted(name):
            candidate=Path(directory,name)
            if candidate.is_symlink() or candidate.is_junction(): return False
            # Build artifacts, fixtures and the bundled challenge "codefix" samples
            # are not deployable routes; indexing them polluted the action catalog.
            relative=candidate.relative_to(root).as_posix()
            return not any(relative==prefix or relative.startswith(prefix+'/') for prefix in EXCLUDED_PREFIXES)
        dirs[:]=sorted(d for d in dirs if d not in EXCLUDED_DIRS and wanted(d))
        for name in sorted(names):
            p=Path(directory,name)
            if p.suffix not in {'.ts','.js'}: continue
            if p.name.endswith(('.spec.ts','.test.ts','.spec.js','.test.js')): continue
            if p.is_symlink() or p.is_junction() or not p.resolve().is_relative_to(root): continue
            if len(texts)>=800: skipped+=1;continue
            check_target(Target(type='repository',locator=str(p.parent)),scope)
            with p.open('rb') as stream: raw=stream.read(1_000_001)
            if len(raw)>1_000_000: skipped+=1;continue
            total+=len(raw)
            if total>12_000_000: raise ValueError('AST source input exceeds bounded size')
            rel=p.relative_to(root).as_posix();texts[rel]=raw.decode('utf-8',errors='replace')
            saved['files'][rel]=hashlib.sha256(raw).hexdigest()
    out=subprocess.run(['node','--max-old-space-size=256',str(Path(__file__).with_name('ast_index.cjs')),str(compiler)],
        input=json.dumps(texts),text=True,encoding='utf-8',capture_output=True,timeout=45,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    if out.returncode: raise ValueError('bounded AST parser failed')
    parsed=json.loads(out.stdout)
    for route in parsed['routes']:
        route['source_hash']=saved.get('files',{}).get(route['file'])
        if route.get('mount_ambiguous'): route['signals'].append('unresolved_mount')
    combined=[r for r in saved['routes'] if r.get('basis')=='static_decorator']+parsed['routes']
    routes,dropped=_merged(combined)
    truncated=len(routes)>MAX_ROUTES
    saved['routes']=routes[:MAX_ROUTES]
    saved['legacy_digest']=saved['digest']
    saved['digest']=hashlib.sha256(repr(sorted(saved['files'].items())).encode()).hexdigest()
    saved['indexing']=dict(parser=parsed['parser_version'],files=len(texts),skipped=skipped,duplicates_removed=dropped,
        excluded=list(EXCLUDED_PREFIXES),route_limit=MAX_ROUTES,truncated=truncated,limitations=parsed['limitations'])
    clients,client_duplicates=_merged([dict(method=c['method'],path=c['path'],file=c['file'],line=c['line'],
        parameters=[],parameter_specs=[],signals=[]) for c in parsed['client_endpoints']])
    saved['client_endpoints']=clients[:300]
    saved['client_duplicates_removed']=client_duplicates
    return saved
