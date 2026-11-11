"""Full provider directory. Coverage is not permission or runtime readiness."""
from functools import lru_cache
import json
from pathlib import Path

from vulnmind.integrations.mcp.client import fingerprint

ROOT = Path(__file__).with_name('resources')
FAMILIES = {
    'network': ('network', '''nmap_scan nmap_advanced_scan rustscan_fast_scan masscan_high_speed
        enum4linux_scan enum4linux_ng_advanced netexec_scan smbmap_scan rpcclient_enumeration
        nbtscan_netbios arp_scan_discovery responder_credential_harvest'''),
    'discovery': ('web', '''amass_scan subfinder_scan fierce_scan dnsenum_scan gau_discovery
        waybackurls_discovery paramspider_mining paramspider_discovery'''),
    'web_scanner': ('web', '''gobuster_scan nuclei_scan dirb_scan nikto_scan wpscan_analyze ffuf_scan
        feroxbuster_scan dotdotpwn_scan xsser_scan wfuzz_scan dirsearch_scan katana_crawl
        arjun_parameter_discovery x8_parameter_discovery jaeles_vulnerability_scan dalfox_xss_scan
        httpx_probe hakrawler_crawl arjun_scan wafw00f_scan'''),
    'sql_injection': ('web', 'sqlmap_scan'),
    'api': ('web', '''api_fuzzer graphql_scanner jwt_analyzer api_schema_analyzer comprehensive_api_audit'''),
    'browser': ('web', '''burpsuite_scan zap_scan http_framework_test browser_agent_inspect
        http_set_rules http_set_scope http_repeater http_intruder burpsuite_alternative_scan'''),
    'cloud': ('cloud', 'prowler_scan scout_suite_assessment cloudmapper_analysis pacu_exploitation'),
    'container': ('cluster', '''trivy_scan kube_hunter_scan kube_bench_cis docker_bench_security_scan
        clair_vulnerability_scan falco_runtime_monitoring checkov_iac_scan terrascan_iac_scan'''),
    'binary': ('sample', '''gdb_analyze radare2_analyze binwalk_analyze ropgadget_search checksec_analyze
        xxd_hexdump strings_extract objdump_analyze ghidra_analysis pwntools_exploit one_gadget_search
        libc_database_lookup gdb_peda_debug angr_symbolic_execution ropper_gadget_search pwninit_setup'''),
    'forensics': ('sample', '''volatility_analyze volatility3_analyze foremost_carving steghide_analysis
        exiftool_extract hashpump_attack'''),
    'authentication': ('network', 'hydra_attack john_crack hashcat_crack'),
    'payload': ('workspace', '''generate_payload metasploit_run msfvenom_generate ai_generate_payload
        ai_test_payload ai_generate_attack_suite advanced_payload_generation'''),
    'data': ('workspace', 'anew_data_processing qsreplace_parameter_replacement uro_url_filtering'),
    'maintenance': ('execution', '''create_file modify_file delete_file list_files install_python_package
        execute_python_script server_health get_cache_stats clear_cache get_telemetry list_active_processes
        get_process_status terminate_process pause_process resume_process get_process_dashboard execute_command
        display_system_metrics error_handling_statistics test_error_recovery'''),
    'intelligence': ('intelligence', '''monitor_cve_feeds generate_exploit_from_cve discover_attack_chains
        research_zero_day_opportunities correlate_threat_intelligence vulnerability_intelligence_dashboard
        threat_hunting_assistant'''),
    'reporting': ('workspace', '''get_live_dashboard create_vulnerability_report format_tool_output_visual
        create_scan_summary'''),
    'planning': ('intelligence', '''analyze_target_intelligence select_optimal_tools_ai optimize_tool_parameters_ai
        create_attack_chain_ai detect_technologies_ai'''),
    'workflow': ('web', '''autorecon_comprehensive autorecon_scan intelligent_smart_scan
        ai_reconnaissance_workflow ai_vulnerability_assessment bugbounty_reconnaissance_workflow
        bugbounty_vulnerability_hunting bugbounty_business_logic_testing bugbounty_osint_gathering
        bugbounty_file_upload_testing bugbounty_comprehensive_assessment bugbounty_authentication_bypass_testing'''),
}

# Capability names express investigation intent. A pending profile is never eligible.
OVERLAPS = {
    'sqlmap_scan': ['sql_boolean', 'sql_error'],
    'dalfox_xss_scan': ['xss_context', 'reflection'],
    'nuclei_scan': ['security_headers', 'cors'],
    'katana_crawl': ['crawl'],
    'httpx_probe': ['http_probe'],
    'arjun_parameter_discovery': ['param_discovery'],
    'ffuf_scan': ['content_discovery'],
    'checkov_iac_scan': ['iac_audit'],
}
# Reviewed controlled executors. Everything else fails closed in server.py.
IMPLEMENTED = {
    'server_health': 'health-v1',
    'strings_extract': 'offline-strings-v1',
    'xxd_hexdump': 'offline-xxd-v1',
    'objdump_analyze': 'offline-objdump-v1',
    'list_files': 'workspace-list-v1',
    'create_file': 'workspace-create-v1',
    'modify_file': 'workspace-modify-v1',
    'delete_file': 'workspace-delete-v1',
    'generate_payload': 'workspace-payload-v1',
    'anew_data_processing': 'workspace-anew-v1',
    'qsreplace_parameter_replacement': 'workspace-qsreplace-v1',
    'uro_url_filtering': 'workspace-uro-v1',
    'checkov_iac_scan': 'workspace-checkov-v1',
    'httpx_probe': 'egress-httpx-v1',
    'katana_crawl': 'egress-katana-v1',
    'nuclei_scan': 'egress-nuclei-v1',
    'dalfox_xss_scan': 'egress-dalfox-v1',
    'ffuf_scan': 'egress-ffuf-v1',
    'wafw00f_scan': 'egress-wafw00f-v1',
    'arjun_parameter_discovery': 'egress-arjun-discovery-v1',
    'arjun_scan': 'egress-arjun-scan-v1',
    'sqlmap_scan': 'egress-sqlmap-v1',
    'nmap_scan': 'netns-nmap-v1',
}
EGRESS_ENFORCED_WEB = frozenset({
    'httpx_probe', 'katana_crawl', 'nuclei_scan', 'dalfox_xss_scan', 'ffuf_scan',
    'wafw00f_scan', 'arjun_parameter_discovery', 'arjun_scan', 'sqlmap_scan',
})
# The maintenance family is otherwise execution-scoped; file/payload/IaC tools work on a per-job workspace.
SCOPES = {'list_files': 'workspace', 'create_file': 'workspace', 'modify_file': 'workspace',
          'delete_file': 'workspace', 'generate_payload': 'workspace', 'checkov_iac_scan': 'workspace'}

# Declared executable requirements per family. This is an environment-readiness
# baseline, not proof that an adapter exists or that a tool is verified.
FAMILY_PROGRAMS = {
    'network': ('nmap', 'masscan', 'rustscan', 'enum4linux', 'netexec', 'smbmap', 'rpcclient',
                'nbtscan', 'arp-scan', 'responder'),
    'discovery': ('amass', 'subfinder', 'fierce', 'dnsenum', 'gau', 'waybackurls', 'paramspider'),
    'web_scanner': ('gobuster', 'nuclei', 'dirb', 'nikto', 'wpscan', 'ffuf', 'feroxbuster', 'dotdotpwn',
                    'xsser', 'wfuzz', 'dirsearch', 'katana', 'arjun', 'x8', 'jaeles', 'dalfox', 'httpx',
                    'hakrawler', 'wafw00f'),
    'sql_injection': ('sqlmap',),
    'api': (),
    'browser': (),
    'cloud': ('prowler', 'scout', 'cloudmapper', 'pacu'),
    'container': ('trivy', 'kube-hunter', 'kube-bench', 'docker-bench-security', 'clair', 'falco',
                  'checkov', 'terrascan'),
    'binary': ('objdump', 'readelf', 'file', 'gdb', 'radare2', 'binwalk', 'ropgadget', 'checksec',
               'xxd', 'strings', 'ghidra', 'one_gadget', 'ropper', 'angr'),
    'forensics': ('volatility', 'volatility3', 'foremost', 'steghide', 'exiftool', 'hashpump'),
    'authentication': ('hydra', 'john', 'hashcat'),
    'payload': (),
    'data': ('anew', 'qsreplace', 'uro'),
    'maintenance': (),
    'intelligence': (),
    'reporting': (),
    'planning': (),
    'workflow': (),
}
PROBE_PROGRAMS = tuple(sorted({name for required in FAMILY_PROGRAMS.values() for name in required}))


def environment_summary(programs):
    """Map a probe result (name -> {found, ...}) to a per-family readiness view."""
    summary = {}
    for family, required in FAMILY_PROGRAMS.items():
        if programs is None:
            summary[family] = dict(required=list(required), present=[], missing=list(required),
                                   status='unchecked')
            continue
        present = [name for name in required if programs.get(name, {}).get('found')]
        missing = [name for name in required if name not in present]
        if not required:
            status = 'no_external_program'
        elif not missing:
            status = 'ready'
        elif present:
            status = 'partial'
        else:
            status = 'missing'
        summary[family] = dict(required=list(required), present=present, missing=missing, status=status)
    return summary


@lru_cache(maxsize=1)
def load_catalog():
    saved = json.loads((ROOT/'catalog.json').read_text(encoding='utf-8'))
    assignments = {}
    for family, (scope, names) in FAMILIES.items():
        for name in names.split():
            if name in assignments: raise ValueError('duplicate family assignment: '+name)
            assignments[name] = (family, scope)
    names = {t['name'] for t in saved['tools']}
    if names != set(assignments): raise ValueError('incomplete full-tool mapping: '+str(names ^ set(assignments)))
    result = []
    for entry in saved['tools']:
        family, scope = assignments[entry['name']]
        profile = dict(version=1, tool_id='hexstrike.'+entry['name'], family=family,
                       resource_scope=SCOPES.get(entry['name'], scope),
                       adapter=IMPLEMENTED.get(entry['name'], 'pending-scoped-adapter'),
                       capabilities=OVERLAPS.get(entry['name'], [entry['name']]),
                       upstream_commit=saved['commit'], schema_sha256=entry['schema_sha256'])
        result.append(dict(**entry, **{k:v for k,v in profile.items() if k not in entry},
                           profile=profile, profile_sha256=fingerprint(profile), provider='hexstrike',
                           skill_id='hexstrike-'+family+'-1'))
    return tuple(result)


def get_tool(tool_id):
    return next((dict(t) for t in load_catalog() if t['tool_id']==tool_id), None)


def directory(validation=None, environment=None):
    """Validation is a local development receipt, not remote self-reported health.

    ``environment`` is the read-only probe result (program -> observation). It
    only informs family readiness; it never makes a tool eligible.
    """
    from vulnmind.knowledge.skills import SkillLoader
    loader = SkillLoader(ROOT/'skills')
    skills = {m.skill_id:loader.load(m.skill_id) for m in loader.available()}
    rows = []
    for entry in load_catalog():
        skill = skills.get(entry['skill_id'])
        receipt = (validation or {}).get(entry['tool_id'], {})
        bound = bool(skill and entry['tool_id'] in skill.tools)
        implemented = entry['name'] in IMPLEMENTED
        validated = (implemented and bound and receipt.get('status')=='passed'
                     and receipt.get('schema_sha256')==entry['schema_sha256']
                     and receipt.get('profile_sha256')==entry['profile_sha256']
                     and receipt.get('skill_sha256')==skill.sha256)
        blockers = []
        if not implemented: blockers.append('scoped_adapter_pending')
        if not bound: blockers.append('skill_binding_missing')
        if not validated: blockers.append('environment_validation_required')
        if (entry['family'] in {'web_scanner','sql_injection','api','browser','workflow','discovery'}
                and entry['name'] not in EGRESS_ENFORCED_WEB):
            blockers.append('request_budget_and_egress_enforcement_required')
        if entry['family'] in {'cloud','container'} and entry['resource_scope'] != 'workspace':
            blockers.append('dedicated_resource_scope_required')
        rows.append(dict(tool_id=entry['tool_id'], name=entry['name'], provider='hexstrike',
                         family=entry['family'], resource_scope=entry['resource_scope'],
                         capabilities=entry['capabilities'], schema_sha256=entry['schema_sha256'],
                         profile_sha256=entry['profile_sha256'], skill_id=entry['skill_id'],
                         skill_sha256=skill.sha256 if skill else None, skill_bound=bound,
                         schema_verified=True, adapter_implemented=implemented, validated=validated,
                         eligible=not blockers, blockers=blockers, input_schema=entry['inputSchema'],
                         description=entry.get('description',''), duplicate_declaration=entry['duplicate_declaration']))
    return dict(policy='external_preferred', upstream_commit=load_catalog()[0]['upstream_commit'],
                totals=dict(catalog=len(rows), schemas=sum(r['schema_verified'] for r in rows),
                            adapters=sum(r['adapter_implemented'] for r in rows),
                            skills=sum(r['skill_bound'] for r in rows),
                            validated=sum(r['validated'] for r in rows), eligible=sum(r['eligible'] for r in rows)),
                environment=environment_summary(environment), tools=rows)
