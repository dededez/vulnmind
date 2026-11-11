"""Pure planning hints inspired by HexStrike's detector/optimizer/error handler.

No server globals, background loops, probability claims, or automatic retries.
"""


def investigation_hints(signals):
    normalized={str(s).lower() for s in signals}
    rules=[({'sql','sql_injection','database'},'sql_injection','sqlmap_scan',
            '核对参数和真假条件基线，检查受控出口与最低请求预算'),
           ({'html','xss','reflection'},'xss','dalfox_xss_scan',
            '先确定 HTML/DOM 上下文；没有浏览器执行证据不得确认脚本执行'),
           ({'routes','crawl','javascript'},'discovery','katana_crawl',
            '固定同源与深度，每次请求及浏览器子资源均计入预算')]
    return [dict(topic=topic,suggested_tool='hexstrike.'+tool,next_question=question,kind='method_hint')
            for triggers,topic,tool,question in rules if normalized & triggers]


def recovery_advice(status):
    return {
        'unknown':'reconcile_original_execution',
        'running':'query_original_execution',
        'accepted':'query_original_execution',
        'protocol_error':'inspect_protocol_and_receipt_before_replan',
        'parse_failed':'preserve_raw_output_and_review_parser',
        'tool_failed':'review_failure_and_prepare_new_plan',
        'succeeded':'review_evidence_no_automatic_retry',
    }.get(status,'stop_and_inspect')
