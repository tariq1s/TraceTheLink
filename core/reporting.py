from __future__ import annotations

import json
from typing import Any


def format_output(results: list[dict[str, Any]], output_format: str) -> str:
    normalized = output_format.lower()
    if normalized == "json":
        return json.dumps(results, indent=2, ensure_ascii=False)
    if normalized == "markdown":
        return render_markdown_report(results)
    return render_text_report(results)


def save_output(content: str, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def render_text_report(results: list[dict[str, Any]]) -> str:
    sections = [render_text_result(result) for result in results]
    return "\n\n".join(sections)


def render_text_result(result: dict[str, Any]) -> str:
    lines = [
        f"Original URL: {result['original_url']}",
        f"Final URL: {result['final_url']}",
        f"Final Status: {result['final_status_code']} ({result['final_status_text']})",
        f"Risk Level: {result['risk_level'].upper()} ({result['risk_score']}/100)",
        f"Page Title: {result.get('title') or 'N/A'}",
        f"Recommended Action: {result['recommended_action']}",
        "",
        "Redirect Chain:",
    ]

    for hop in result["redirect_chain"]:
        lines.append(
            f"  - Hop {hop['hop']}: [{hop['status_code']}] {hop['url']}"
            + (f" -> {hop['location']}" if hop.get("location") else "")
        )

    lines.extend(
        [
            "",
            "Domain Changes:",
        ]
    )
    if result["domain_changes"]:
        for change in result["domain_changes"]:
            lines.append(f"  - {change['from']} -> {change['to']}")
    else:
        lines.append("  - None observed")

    lines.extend(
        [
            "",
            "Suspicious Indicators:",
        ]
    )
    if result["suspicious_indicators"]:
        for indicator in result["suspicious_indicators"]:
            lines.append(f"  - {indicator}")
    else:
        lines.append("  - None identified")

    lines.extend(
        [
            "",
            "Risk Reasoning:",
        ]
    )
    for item in result["risk_reasoning"]:
        lines.append(f"  - {item}")

    if result.get("error"):
        lines.extend(["", f"Error: {result['error']}"])

    return "\n".join(lines)


def render_markdown_report(results: list[dict[str, Any]]) -> str:
    sections = ["# TraceTheLink Report"]
    for result in results:
        sections.append(render_markdown_result(result))
    return "\n\n".join(sections)


def render_markdown_result(result: dict[str, Any]) -> str:
    lines = [
        f"## {result['original_url']}",
        "",
        f"- **Final URL:** `{result['final_url']}`",
        f"- **Final Status:** `{result['final_status_code']}` ({result['final_status_text']})",
        f"- **Risk Level:** `{result['risk_level'].upper()}` ({result['risk_score']}/100)",
        f"- **Page Title:** {result.get('title') or 'N/A'}",
        f"- **Recommended Action:** {result['recommended_action']}",
        "",
        "### Redirect Chain",
    ]

    for hop in result["redirect_chain"]:
        chain_line = f"- **Hop {hop['hop']}** `[{hop['status_code']}]` `{hop['url']}`"
        if hop.get("location"):
            chain_line += f" -> `{hop['location']}`"
        lines.append(chain_line)

    lines.extend(["", "### Domain Changes"])
    if result["domain_changes"]:
        for change in result["domain_changes"]:
            lines.append(f"- `{change['from']}` -> `{change['to']}`")
    else:
        lines.append("- None observed")

    lines.extend(["", "### Suspicious Indicators"])
    if result["suspicious_indicators"]:
        for indicator in result["suspicious_indicators"]:
            lines.append(f"- {indicator}")
    else:
        lines.append("- None identified")

    lines.extend(["", "### Risk Reasoning"])
    for item in result["risk_reasoning"]:
        lines.append(f"- {item}")

    metadata = result.get("metadata") or {}
    lines.extend(["", "### Metadata"])
    lines.append(f"- **Content-Type:** {metadata.get('content_type') or 'N/A'}")
    lines.append(f"- **Server:** {metadata.get('server') or 'N/A'}")
    lines.append(f"- **Meta Description:** {metadata.get('meta_description') or 'N/A'}")

    if result.get("error"):
        lines.extend(["", f"> Error: {result['error']}"])

    return "\n".join(lines)
