"""Read the pinned upstream's real MCP tools/list; never start a scanner."""
import argparse
import asyncio
import importlib.metadata
import json
from pathlib import Path
import sys

from vulnmind.integrations.mcp.client import stdio_session, list_all_tools, fingerprint
from vulnmind.integrations.hexstrike.inventory_server import COMMIT, SOURCE_SHA256


async def sync(source, output, inventory):
    async with stdio_session(sys.executable, ['-m', 'vulnmind.integrations.hexstrike.inventory_server', str(source.resolve())],
                             timeout=60) as session:
        tools = await list_all_tools(session)
    recorded = json.loads(inventory.read_text(encoding='utf-8'))
    expected = {t['mcp_name'] for t in recorded['tools']}
    if {t['name'] for t in tools} != expected:
        raise ValueError('runtime names differ from reviewed inventory')
    entries = {t['mcp_name']: t for t in recorded['tools']}
    value = dict(schema_version='hexstrike-mcp-catalog-1', commit=COMMIT,
                 source_sha256=SOURCE_SHA256, sdk_version=importlib.metadata.version('mcp'),
                 declaration_count=recorded['declaration_count'], runtime_count=len(tools),
                 tools=[dict(**t, schema_sha256=fingerprint(t['inputSchema']),
                             source_declarations=entries[t['name']]['source_declarations'],
                             duplicate_declaration=entries[t['name']]['duplicate_declaration'])
                        for t in sorted(tools, key=lambda t: t['name'])])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(dict(runtime_tools=len(tools), sdk=value['sdk_version'], sha256=fingerprint(value))))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, default=Path('docs/HEXSTRIKE_TOOL_INVENTORY_20261110.json'))
    args = parser.parse_args()
    asyncio.run(sync(args.source, args.output, args.inventory))
