import pytest
from datetime import datetime, timedelta, timezone

from vulnmind.schemas import Authorization
from vulnmind.workbench.ast_discovery import extend_ast_snapshot, ROOT
from vulnmind.workbench.routes import snapshot


def scope_for(path):
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source='fixture', approved_by='test',
                         starts_at=now - timedelta(minutes=1), expires_at=now + timedelta(hours=1),
                         repository_roots=[str(path)], web_origins=['http://127.0.0.1:3000'],
                         allowed_ip_networks=['127.0.0.1/32'])


requires_parser = pytest.mark.skipif(
    not (ROOT / '.devtools/ast-parser/node_modules/typescript/lib/typescript.js').is_file(),
    reason='pinned compiler not installed')


@requires_parser
def test_codefix_and_fixture_directories_are_not_routes(tmp_path):
    (tmp_path / 'server.ts').write_text(
        "import router from './router';\napp.use('/api', router);\napp.get('/health', (req,res)=>res.json({ok:true}));\n")
    (tmp_path / 'router.ts').write_text(
        "import { Router } from 'express';\nconst router=Router();\nrouter.get('/find', (req,res)=>res.query.q);\nexport default router;\n")
    codefix = tmp_path / 'data/static/codefixes'
    codefix.mkdir(parents=True)
    (codefix / 'sample.ts').write_text("app.get('/fake-codefix', (req,res)=>res.send('x'));\n")
    drafts = tmp_path / 'drafts'
    drafts.mkdir()
    (drafts / 'old.ts').write_text("app.get('/fake-draft', (req,res)=>res.send('x'));\n")

    saved = extend_ast_snapshot(snapshot(str(tmp_path), scope_for(tmp_path), extended=True), scope_for(tmp_path))
    paths = {route['path'] for route in saved['routes']}
    assert '/fake-codefix' not in paths and '/fake-draft' not in paths
    assert '/health' in paths and '/api/find' in paths
    assert saved['indexing']['excluded']


@requires_parser
def test_duplicate_routes_merge_parameters_and_keep_provenance(tmp_path):
    (tmp_path / 'server.ts').write_text(
        "app.get('/rest/item', (req,res)=>req.query.q);\napp.get('/rest/item', (req,res)=>req.query.id);\n")
    saved = extend_ast_snapshot(snapshot(str(tmp_path), scope_for(tmp_path), extended=True), scope_for(tmp_path))
    routes = [route for route in saved['routes'] if route['path'] == '/rest/item']
    assert len(routes) == 1
    assert set(routes[0]['parameters']) == {'q', 'id'}
    assert len(routes[0]['sources']) >= 2
    assert saved['indexing']['duplicates_removed'] >= 1


@requires_parser
def test_client_urls_with_concatenation_are_extracted(tmp_path):
    (tmp_path / 'server.ts').write_text("app.get('/health', (req,res)=>res.json({ok:true}));\n")
    service = tmp_path / 'frontend/src/app/service.ts'
    service.parent.mkdir(parents=True)
    service.write_text(
        "export class S {\n"
        "  constructor(private http: HttpClient) {}\n"
        "  whoami() { return this.http.get(this.hostServer + '/rest/user/whoami'); }\n"
        "  search(q: string) { return this.http.get(`${this.hostServer}/rest/products/search?q=${q}`); }\n"
        "}\n")
    saved = extend_ast_snapshot(snapshot(str(tmp_path), scope_for(tmp_path), extended=True), scope_for(tmp_path))
    paths = {entry['path'] for entry in saved['client_endpoints']}
    assert '/rest/user/whoami' in paths
    assert '/rest/products/search' in paths
