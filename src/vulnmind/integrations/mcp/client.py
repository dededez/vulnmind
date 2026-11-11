"""Bounded MCP sessions. Never retry a potentially executed tool call."""
from contextlib import asynccontextmanager
from datetime import timedelta
import asyncio
import hashlib
import json
from pathlib import Path


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(',', ':')).encode()).hexdigest()


def validate_arguments(schema, arguments):
    from jsonschema import Draft202012Validator
    # Remote references must never fetch data while validating untrusted schemas.
    def inspect(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {'$ref', '$dynamicRef'} and not str(item).startswith('#'):
                    raise ValueError('external schema references are disabled')
                inspect(item)
        elif isinstance(value, list):
            for item in value: inspect(item)
    inspect(schema)
    Draft202012Validator.check_schema(schema)
    if not isinstance(arguments, dict): raise ValueError('arguments must be an object')
    if set(arguments) - set(schema.get('properties', {})):
        raise ValueError('undeclared tool arguments')
    if len(json.dumps(arguments).encode()) > 1_000_000: raise ValueError('arguments too large')
    Draft202012Validator(schema).validate(arguments)


@asynccontextmanager
async def stdio_session(command, args=(), *, cwd=None, env=None, timeout=30, error_log=None):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    import sys
    log = open(error_log, 'a', encoding='utf-8') if error_log else None
    try:
        params = StdioServerParameters(command=str(command), args=list(args),
                                      cwd=str(cwd) if cwd else None, env=env)
        async with stdio_client(params, errlog=log or sys.stderr) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=timeout)) as session:
                await asyncio.wait_for(session.initialize(), timeout)
                yield session
    finally:
        if log: log.close()


async def list_all_tools(session, *, max_pages=100, max_tools=2000):
    tools, cursors, cursor = {}, set(), None
    for _ in range(max_pages):
        page = await session.list_tools(cursor=cursor)
        for tool in page.tools:
            if tool.name in tools: raise ValueError('duplicate runtime MCP tool name')
            value = tool.model_dump(mode='json', exclude_none=True)
            validate_arguments_schema(value['inputSchema'])
            tools[tool.name] = value
            if len(tools) > max_tools: raise ValueError('MCP tool limit exceeded')
        cursor = page.nextCursor
        if not cursor: return list(tools.values())
        if cursor in cursors: raise ValueError('MCP pagination cursor repeated')
        cursors.add(cursor)
    raise ValueError('MCP pagination limit exceeded')


def validate_arguments_schema(schema):
    # Use an empty instance only to inspect schema, not to require optional inputs.
    from jsonschema import ValidationError
    try: validate_arguments(schema, {})
    except ValidationError: pass


def normalize_result(result):
    """Execution status and vulnerability verdict are deliberately separate."""
    raw = result.model_dump(mode='json', exclude_none=True)
    if result.isError:
        return dict(status='protocol_error', payload=raw, sha256=fingerprint(raw))
    data = result.structuredContent
    if data is None:
        blocks = [b.text for b in result.content if b.type == 'text']
        if len(blocks) == 1:
            try: data = json.loads(blocks[0])
            except (ValueError, TypeError): pass
    if not isinstance(data, dict):
        return dict(status='parse_failed', payload=raw, sha256=fingerprint(raw))
    if data.get('success') is False or data.get('error'):
        status = 'tool_failed'
    else:
        status = 'succeeded'
    return dict(status=status, payload=data, sha256=fingerprint(raw))


async def call_once(session, name, arguments, *, schema, timeout=60, meta=None):
    validate_arguments(schema, arguments)
    try:
        result = await session.call_tool(name, arguments, read_timeout_seconds=timedelta(seconds=timeout), meta=meta)
    except (Exception, asyncio.CancelledError):
        # A broken connection cannot establish whether the server executed the call.
        return dict(status='unknown', reconciliation_required=True)
    return normalize_result(result)
