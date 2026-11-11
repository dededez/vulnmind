"""MCP provider: all upstream schemas, signed plan metadata, durable receipts.

The upstream Flask server is never imported or started. The reviewed upstream
MCP wrapper invokes only our explicit controlled endpoint implementations.
"""
import argparse
import asyncio
import json
from pathlib import Path

from vulnmind.integrations.hexstrike.catalog import load_catalog, get_tool, IMPLEMENTED, ROOT
from vulnmind.integrations.hexstrike.execution import ExecutionPlan, ExecutionLedger, verify_approval
from vulnmind.integrations.hexstrike.inventory_server import load_upstream
from vulnmind.integrations.hexstrike.backend import ControlledClient
from vulnmind.integrations.mcp.client import validate_arguments


async def run(root, upstream_path, key_file, distro):
    from mcp.server.lowlevel import Server
    from mcp.server.stdio import stdio_server
    from mcp import types
    from vulnmind.knowledge.skills import SkillLoader
    upstream=load_upstream(upstream_path)
    ledger=ExecutionLedger(root/'executions.sqlite3')
    key=key_file.read_bytes()
    server=Server('vulnmind-hexstrike-controlled')
    loader=SkillLoader(ROOT/'skills')
    @server.list_tools()
    async def list_tools():
        return [types.Tool(name=t['name'],description=t.get('description',''),inputSchema=t['inputSchema']) for t in load_catalog()] + [
            types.Tool(name='vulnmind_execution_status',description='Reconcile a previously accepted execution. Requires its signed original plan.',
                       inputSchema={'type':'object','properties':{},'additionalProperties':False})]

    @server.call_tool(validate_input=False)
    async def call_tool(name, arguments):
        meta=server.request_context.meta
        envelope=meta.model_dump().get('vulnmind',{}) if meta else {}
        try:
            plan=ExecutionPlan.model_validate(envelope.get('plan'))
            # Expired plans may read their own receipts, but never start new work.
            signature=envelope.get('signature','')
            if name=='vulnmind_execution_status':
                import hmac
                from vulnmind.integrations.hexstrike.execution import sign_plan
                if arguments or not hmac.compare_digest(sign_plan(plan,key),signature): raise ValueError('receipt authorization mismatch')
                saved=ledger.get(plan.execution_id,job_id=plan.job_id)
                if saved.get('digest') and saved['digest']!=plan.digest(): raise ValueError('receipt plan mismatch')
                return saved
            verify_approval(plan,signature,key)
            if plan.tool_id!='hexstrike.'+name or plan.arguments!=arguments: raise ValueError('plan arguments mismatch')
            tool=get_tool(plan.tool_id)
            if tool is None or name not in IMPLEMENTED: raise ValueError('scoped adapter is not implemented')
            validate_arguments(tool['inputSchema'], arguments)
            skill=loader.load(tool['skill_id'])
            if (plan.schema_sha256!=tool['schema_sha256'] or plan.profile_sha256!=tool['profile_sha256']
                    or plan.skill_sha256!=skill.sha256 or plan.tool_id not in skill.tools):
                raise ValueError('schema/profile/skill revision mismatch')
            if not ledger.accept(plan): return ledger.get(plan.execution_id,job_id=plan.job_id)
            ledger.start(plan.execution_id)
            try:
                bridge=upstream.setup_mcp_server(ControlledClient(root,plan,distro=distro))
                result=await bridge.call_tool(name,arguments)
                # FastMCP returns (content, structured content) for annotated dictionaries.
                if isinstance(result,tuple): value=result[1]
                else: value=json.loads(next(b.text for b in result if b.type=='text'))
                # SDK v1 wraps Dict[str, Any] return annotations in a result field.
                if isinstance(value,dict) and set(value)=={'result'} and isinstance(value['result'],dict):
                    value=value['result']
                if not isinstance(value,dict):
                    ledger.finish(plan.execution_id,'parse_failed',{'error':'structured result missing'})
                else:
                    ledger.finish(plan.execution_id,'tool_failed' if value.get('success') is False else 'succeeded',value)
            except ValueError:
                ledger.finish(plan.execution_id,'rejected',{'error':'controlled parameter or scope check failed'})
            except BaseException:
                ledger.finish(plan.execution_id,'unknown',{'error':'worker outcome requires reconciliation'})
                raise
            return ledger.get(plan.execution_id,job_id=plan.job_id)
        except (ValueError,TypeError):
            return types.CallToolResult(isError=True,content=[types.TextContent(type='text',text='Execution rejected: missing or mismatched approval, scope, adapter, or revision.')])

    async with stdio_server() as (read,write):
        await server.run(read,write,server.create_initialization_options())


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--root',required=True,type=Path)
    parser.add_argument('--upstream',required=True,type=Path)
    parser.add_argument('--key-file',required=True,type=Path)
    parser.add_argument('--distro',default='VulnMindLab')
    args=parser.parse_args()
    asyncio.run(run(args.root.resolve(),args.upstream,args.key_file,args.distro))
