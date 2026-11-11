"""Offline ground-truth mapping for the authorized local Juice Shop lab.

Reads only challenge metadata (never hints/solutions), the seeded root-cause
classification and source comments that mark vulnerable lines. It never talks
to the target and is not imported by the runtime.
"""
import argparse
import collections
import json
import os
import pathlib
import re

import yaml

MODES = {"anon", "auth", "reg", "write", "browser", "osint", "env", "static", "na", "unclear"}
DYNAMIC = {"anon", "auth", "reg", "write", "browser", "osint"}
ANCHOR = re.compile(r"vuln-code-snippet\s+.*?\b(vuln-line)\b\s*(\w+)")
SKIP_DIRS = {".git", ".venv", "node_modules", "dist", "build", "coverage"}


def anchors(repo):
    found = collections.defaultdict(list)
    for directory, dirs, names in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in names:
            if not name.endswith((".ts", ".js", ".html")):
                continue
            path = pathlib.Path(directory, name)
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for number, line in enumerate(text.splitlines(), 1):
                match = ANCHOR.search(line)
                if match:
                    found[match.group(2)].append(f"{path.relative_to(repo).as_posix()}:{number}")
    return found


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=pathlib.Path, required=True)
    parser.add_argument("--seed", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--markdown", type=pathlib.Path, required=True)
    args = parser.parse_args()

    seed = json.loads(args.seed.read_text(encoding="utf-8"))
    roots = seed["root_causes"]
    tags = seed["tags"]
    challenges = yaml.safe_load((args.repo / "data/static/challenges.yml").read_text(encoding="utf-8"))
    metadata = {c["key"]: c for c in challenges if isinstance(c, dict) and "key" in c}

    problems = []
    if set(tags) != set(metadata):
        problems.append(f"seed/tag key mismatch: missing={sorted(set(metadata)-set(tags))} extra={sorted(set(tags)-set(metadata))}")
    for key, tag in tags.items():
        if len(tag) != 4:
            problems.append(f"{key}: tag needs 4 fields")
            continue
        root, mode = tag[0], tag[1]
        if root not in roots:
            problems.append(f"{key}: unknown root cause {root}")
        if mode not in MODES:
            problems.append(f"{key}: unknown mode {mode}")
    for key, root in roots.items():
        if len(root) != 3:
            problems.append(f"{key}: root cause needs [family, evidence, cost]")
    if problems:
        raise SystemExit("seed validation failed:\n" + "\n".join(problems))

    source_anchors = anchors(args.repo)
    entries = []
    for key in sorted(metadata):
        meta = metadata[key]
        root_id, mode, confidence, note = tags[key]
        family, evidence, cost = roots[root_id]
        entries.append(dict(
            challenge_key=key,
            name=meta.get("name"),
            category=meta.get("category"),
            difficulty=meta.get("difficulty"),
            declared_disabled_envs=meta.get("disabledEnv") or [],
            description=(meta.get("description") or "").strip()[:240],
            root_cause_id=root_id,
            family=family,
            mode=mode,
            confidence=confidence,
            prerequisites=evidence if mode != "na" else "",
            expected_evidence=evidence,
            estimated_request_cost=cost if mode in {"anon", "auth", "write", "browser"} else None,
            source_anchors=source_anchors.get(key, []),
            classification_evidence="source_anchor" if key in source_anchors else "seeded_judgement",
            note=note,
        ))

    def distinct(modes):
        return {e["root_cause_id"] for e in entries if e["mode"] in modes}

    dynamic_roots = distinct(DYNAMIC)
    eligible = distinct({"anon"})
    static_roots = distinct({"static"})
    env_roots = distinct({"env"})
    counts = collections.Counter(e["mode"] for e in entries)
    by_root = collections.defaultdict(list)
    for e in entries:
        by_root[e["root_cause_id"]].append(e["challenge_key"])

    summary = dict(
        challenges=len(entries),
        modes=dict(counts),
        dynamic_root_causes=len(dynamic_roots),
        eligible_anonymous_root_causes=len(eligible),
        static_root_causes=len(static_roots),
        environment_blocked_root_causes=len(env_roots),
        dynamic_ratio=round(len(eligible) / len(dynamic_roots), 3) if dynamic_roots else None,
        confidence=dict(collections.Counter(e["confidence"] for e in entries)),
        anchored_challenges=sum(bool(e["source_anchors"]) for e in entries),
        multi_challenge_roots={k: v for k, v in sorted(by_root.items()) if len(v) > 1},
        target_overall_dynamic_coverage=0.5,
        target_achievable_under_fixed_config=len(eligible) / len(dynamic_roots) > 0.5 if dynamic_roots else False,
        note="总体动态覆盖率分母使用 dynamic_root_causes；固定配置内分母使用 eligible_anonymous_root_causes。na/static/env/unclear 不入总体分母。",
    )
    payload = dict(schema_version="juice-shop-truth-1", created_date=seed["created_date"], status="classified",
                   source=dict(repository=str(args.repo), seed=str(args.seed),
                               challenge_metadata="data/static/challenges.yml (key/name/category/difficulty/disabledEnv/description only)",
                               anchors="vuln-code-snippet vuln-line comments"),
                   evaluation_only=True, runtime_must_not_read="challenges.yml, this file",
                   summary=summary, entries=entries)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")

    lines = ["# Juice Shop 覆盖缺口（离线真值映射）", "",
             f"生成：`{args.output.as_posix()}`；挑战 {summary['challenges']} 项。", "",
             "## 分母", "",
             "| 指标 | 值 |", "|---|---:|",
             f"| 动态根因（总体分母） | {summary['dynamic_root_causes']} |",
             f"| 无认证可动态验证根因（配置内分母） | {summary['eligible_anonymous_root_causes']} |",
             f"| 比率 | {summary['dynamic_ratio']} |",
             f"| 静态根因 | {summary['static_root_causes']} |",
             f"| 环境阻断根因 | {summary['environment_blocked_root_causes']} |",
             f"| 非漏洞/教学项 | {counts.get('na', 0)} |",
             f"| 待人工复核 | {counts.get('unclear', 0)} |",
             f"| 有源码锚点的挑战 | {summary['anchored_challenges']} |", "",
             "## 结论", "",
             (">50% 总体目标在无认证、无注册、无浏览器条件下**可达**。" if summary["target_achievable_under_fixed_config"]
              else ">50% 总体目标在无认证、无注册、无浏览器条件下**不可达**：匿名可验证根因占总体动态根因仅 "
                   + f"{round(summary['dynamic_ratio']*100,1)}%，需要用户决定是否调整配置（登录态/注册/浏览器）或改按配置内分母验收。"),
             "", "## 模式分布", "",
             "| 模式 | 挑战数 | 说明 |", "|---|---:|---|"]
    for mode, count in counts.most_common():
        lines.append(f"| {mode} | {count} | {seed['modes'].get(mode,'')} |")
    lines += ["", "## 待人工复核（unclear）", ""]
    lines += [f"- `{e['challenge_key']}`：{e['note']}" for e in entries if e["mode"] == "unclear"] or ["- 无"]
    lines += ["", "## 无认证可验证根因清单", ""]
    for root in sorted(eligible):
        keys = ", ".join(by_root[root])
        lines.append(f"- `{root}`（{roots[root][0]}）：{keys}")
    lines += ["", "## 按根因去重后仍多挑战计数的项", ""]
    multi = summary["multi_challenge_roots"]
    lines += [f"- `{k}`：{len(v)} 项（{', '.join(v)}）" for k, v in multi.items()] or ["- 无"]
    args.markdown.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(dict(output=str(args.output), markdown=str(args.markdown), **summary), ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
