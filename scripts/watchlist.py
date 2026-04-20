#!/usr/bin/env python3
"""Topic watchlist management for last30days."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

SCRIPT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(SCRIPT_DIR))

import store
from lib import schema


# --- Webhook Delivery Functions ---
#
# Security model (read before extending)
# --------------------------------------
# `delivery_channel` is a user-supplied URL stored in the watchlist SQLite
# DB via `store.set_setting()`. The only validation at send time is
# `channel.startswith("https://")`. That is *intentionally* lax for the
# current payload: today the body is a single short notification message
# that contains the topic name and integer counts — no findings content,
# no excerpts, no tokens, no PII beyond the topic string the user themself
# typed. Combined with the fact that `delivery_channel` can only be written
# by the user running the watchlist CLI subcommands on their own machine
# (there is no LLM- or env-file-driven write path), the SSRF/exfil surface
# is accepted as negligible for the current feature scope.
#
# DO NOT extend `_format_delivery_message()` or `_send_generic_webhook()`
# to include any of the following without also tightening validation:
#   - Finding titles, URLs, content snippets, or excerpts.
#   - Raw pipeline output, transcripts, top comments, or quotes.
#   - API keys, tokens, config values, or file paths.
#   - User identity information beyond the topic name already present.
#
# If you need to ship any of the above, restructure the validation before
# merging:
#   - Add an allowlist of known webhook providers (hooks.slack.com,
#     discord.com/api/webhooks, teams.microsoft.com/webhook, etc.) and
#     require an explicit `DELIVERY_CHANNEL_ALLOW_CUSTOM=true` opt-in for
#     anything else.
#   - Reject RFC1918 / loopback / 169.254.* destinations after DNS
#     resolution; consider pinning the resolved IP to mitigate DNS
#     rebinding.
#   - Redact anything sensitive server-side; do not rely on the notification
#     endpoint being trustworthy.
#
# See the review history (branch: security/session-hook-eval-and-pat-path)
# for the decision record — Option 1 with documentation was chosen because
# the watchlist payload is message-only and the write surface is
# user-local. Any enrichment of the payload invalidates that premise.


def _deliver_findings(topic_name: str, counts: dict) -> None:
    """Send webhook notification if delivery is configured and there are new findings."""
    channel = store.get_setting("delivery_channel", "")
    if not channel or counts.get("new", 0) == 0:
        return
    
    mode = store.get_setting("delivery_mode", "announce")
    message = _format_delivery_message(topic_name, counts, mode)
    
    try:
        if "hooks.slack.com" in channel:
            _send_slack_webhook(channel, message)
        elif channel.startswith("https://"):
            _send_generic_webhook(channel, message)
    except Exception as e:
        # Don't fail the research run if delivery fails
        print(f"Delivery failed: {e}", file=sys.stderr)


def _format_delivery_message(topic: str, counts: dict, mode: str) -> str:
    """Format notification message based on delivery mode."""
    new = counts.get("new", 0)
    updated = counts.get("updated", 0)
    
    if mode == "announce":
        return f"📰 *last30days update: {topic}*\n{new} new, {updated} updated"
    elif mode == "silent":
        return f"last30days: {new} new findings for '{topic}'"
    else:
        return f"last30days: Research complete for '{topic}'"


def _send_slack_webhook(url: str, text: str) -> None:
    """POST to Slack incoming webhook."""
    if not requests:
        raise RuntimeError("requests library not available for webhook delivery")
    
    response = requests.post(
        url,
        json={"text": text},
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    response.raise_for_status()


def _send_generic_webhook(url: str, text: str) -> None:
    """POST JSON payload to generic webhook.

    The URL is user-supplied and only validated with `startswith("https://")`
    at the caller. This is safe ONLY because the payload is a short message
    string with no finding content. If you enrich the payload, read the
    security model notes at the top of this module before merging.
    """
    if not requests:
        raise RuntimeError("requests library not available for webhook delivery")
    
    response = requests.post(
        url,
        json={
            "message": text,
            "source": "last30days",
            "timestamp": time.time(),
        },
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    response.raise_for_status()


# --- Command Handlers ---

def cmd_add(args):
    schedule = "0 8 * * 1" if args.weekly else (args.schedule or "0 8 * * *")
    queries = [query.strip() for query in (args.queries or "").split(",") if query.strip()] or None
    topic = store.add_topic(args.topic, search_queries=queries, schedule=schedule)
    sched_desc = "weekly (Mondays 8am)" if args.weekly else f"daily ({schedule})"
    print(json.dumps({
        "action": "added",
        "topic": topic["name"],
        "schedule": sched_desc,
        "message": f'Added "{topic["name"]}" to watchlist. Schedule: {sched_desc}.',
    }, default=str))


def cmd_remove(args):
    removed = store.remove_topic(args.topic)
    if not removed:
        print(json.dumps({"action": "not_found", "topic": args.topic, "message": f'Topic not found: "{args.topic}"'}))
        return
    remaining = store.list_topics()
    print(json.dumps({
        "action": "removed",
        "topic": args.topic,
        "message": f'Removed "{args.topic}" from watchlist.',
        "remaining": len(remaining),
    }))


def cmd_list(args):
    del args
    topics = store.list_topics()
    budget_used = store.get_daily_cost()
    budget_limit = float(store.get_setting("daily_budget", "5.00"))
    print(json.dumps({
        "topics": topics,
        "budget_used": budget_used,
        "budget_limit": budget_limit,
    }, default=str))


def cmd_run_one(args):
    topic = store.get_topic(args.topic)
    if not topic:
        print(json.dumps({"error": f'Topic not found: "{args.topic}"'}))
        sys.exit(1)
    print(json.dumps(_run_topic(topic), default=str))


def cmd_run_all(args):
    del args
    topics = [topic for topic in store.list_topics() if topic["enabled"]]
    if not topics:
        print(json.dumps({"message": "No enabled topics to research."}))
        return

    budget_limit = float(store.get_setting("daily_budget", "5.00"))
    results = []
    for topic in topics:
        if store.get_daily_cost() >= budget_limit:
            results.append({
                "topic": topic["name"],
                "status": "skipped",
                "reason": f"Budget exceeded: ${store.get_daily_cost():.2f}/${budget_limit:.2f}",
            })
            continue
        results.append(_run_topic(topic))

    print(json.dumps({
        "action": "run_all",
        "results": results,
        "budget_used": store.get_daily_cost(),
        "budget_limit": budget_limit,
    }, default=str))


def _run_topic(topic: dict) -> dict:
    start_time = time.time()
    topic_id = topic["id"]
    run_id = store.record_run(topic_id, source_mode="v3", status="running")

    try:
        search_queries = json.loads(topic["search_queries"]) if topic.get("search_queries") else None
        search_term = search_queries[0] if search_queries else topic["name"]
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "last30days.py"),
                search_term,
                "--emit=json",
                "--quick",
                "--lookback-days",
                "90",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        duration = time.time() - start_time
        if result.returncode != 0:
            store.update_run(
                run_id,
                status="failed",
                error_message=result.stderr[:500],
                duration_seconds=duration,
            )
            return {
                "topic": topic["name"],
                "status": "failed",
                "error": result.stderr[:200],
                "duration": duration,
            }

        report = schema.report_from_dict(json.loads(result.stdout))
        findings = store.findings_from_report(report, limit=25)
        counts = store.store_findings(run_id, topic_id, findings)
        store.update_run(
            run_id,
            status="completed",
            duration_seconds=duration,
            findings_new=counts["new"],
            findings_updated=counts["updated"],
        )
        
        # Deliver webhook notification if configured
        _deliver_findings(topic["name"], counts)
        
        return {
            "topic": topic["name"],
            "status": "completed",
            "new": counts["new"],
            "updated": counts["updated"],
            "duration": duration,
        }
    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        store.update_run(
            run_id,
            status="failed",
            error_message="Research timed out after 300s",
            duration_seconds=duration,
        )
        return {"topic": topic["name"], "status": "failed", "error": "timeout"}
    except json.JSONDecodeError as exc:
        duration = time.time() - start_time
        store.update_run(
            run_id,
            status="failed",
            error_message=f"Invalid JSON output: {exc}",
            duration_seconds=duration,
        )
        return {"topic": topic["name"], "status": "failed", "error": f"parse error: {exc}"}
def cmd_config(args):
    if args.key == "budget":
        store.set_setting("daily_budget", str(args.value))
        print(json.dumps({"action": "config", "key": "daily_budget", "value": str(args.value)}))
        return
    if args.key == "delivery":
        store.set_setting("delivery_channel", str(args.value))
        print(json.dumps({"action": "config", "key": "delivery_channel", "value": str(args.value)}))
        return
    raise SystemExit(f"Unknown config key: {args.key}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage the last30days watchlist")
    sub = parser.add_subparsers(dest="command")

    add = sub.add_parser("add")
    add.add_argument("topic")
    add.add_argument("--schedule")
    add.add_argument("--weekly", action="store_true")
    add.add_argument("--queries")
    add.set_defaults(func=cmd_add)

    remove = sub.add_parser("remove")
    remove.add_argument("topic")
    remove.set_defaults(func=cmd_remove)

    list_parser = sub.add_parser("list")
    list_parser.set_defaults(func=cmd_list)

    run_one = sub.add_parser("run-one")
    run_one.add_argument("topic")
    run_one.set_defaults(func=cmd_run_one)

    run_all = sub.add_parser("run-all")
    run_all.set_defaults(func=cmd_run_all)

    config = sub.add_parser("config")
    config.add_argument("key", choices=["delivery", "budget"])
    config.add_argument("value")
    config.set_defaults(func=cmd_config)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not getattr(args, "command", None):
        parser.print_help()
        return 1
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
