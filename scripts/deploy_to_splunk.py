#!/usr/bin/env python3
"""
deploy_to_splunk.py

Create or update a Splunk saved search (alert) from CLI args.
Designed to be CI-friendly for GitHub Actions.

Usage example:
  python scripts/deploy_to_splunk.py \
    --url "$SPLUNK_URL" \
    --token "$SPLUNK_TOKEN" \
    --rule "windows_suspicious_powershell" \
    --query 'index=win EventCode=4104 | stats count by User' \
    --actions "log" \
    --schedule "*/15 * * * *" \
    --severity 3 \
    --app "search" \
    --owner "nobody"

Notes:
- Works with Splunk Management (REST) port (default 8089).
- Supports Bearer (Token-based auth) and Splunk session-key style.
- Minimal fields by default; extend as needed per your environment.
"""

import argparse
import sys
import requests
from urllib.parse import quote

def parse_args():
    p = argparse.ArgumentParser(description="Create/update Splunk saved search (alert).")
    p.add_argument("--url", required=True, help="Base Splunk mgmt URL, e.g. https://splunk.example.com:8089")
    p.add_argument("--token", required=True, help="API token (GitHub Secret).")
    p.add_argument("--auth-type", choices=["bearer", "splunk"], default="bearer",
                   help="Authorization header type. 'bearer' for token-based auth; 'splunk' for session key style.")
    p.add_argument("--rule", required=True, help="Saved search (alert) name.")
    p.add_argument("--query", required=True, help="SPL query text.")
    p.add_argument("--description", default="Deployed via CI from Sigma conversion.",
                   help="Saved search description.")
    p.add_argument("--app", default="search", help="App context (e.g., 'search' or your TA).")
    p.add_argument("--owner", default="nobody", help="Owner context (e.g., 'nobody' for app-level visibility).")
    p.add_argument("--schedule", default=None,
                   help="Cron schedule (e.g., '*/15 * * * *'). If omitted, search is not scheduled.")
    p.add_argument("--disabled", action="store_true", help="Create/Update as disabled.")
    p.add_argument("--severity", type=int, default=3,
                   help="Alert severity (1=highest .. 6=lowest).")
    p.add_argument("--actions", default="", help="Comma-separated actions (e.g., 'email,webhook').")
    p.add_argument("--webhook-url", default=None,
                   help="If 'webhook' in actions, set the webhook URL here.")
    p.add_argument("--email-to", default=None,
                   help="If 'email' in actions, comma-separated recipients.")
    p.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificates.")
    p.add_argument("--dry-run", action="store_true", help="Print what would be sent; don’t call Splunk.")
    return p.parse_args()

def auth_header(token: str, auth_type: str) -> dict:
    if auth_type == "bearer":
        # Token-based auth (modern Splunk): Authorization: Bearer <token>
        return {"Authorization": f"Bearer {token}"}
    # Session key style: Authorization: Splunk <sessionKey>
    return {"Authorization": f"Splunk {token}"}

def endpoint_base(url: str, owner: str, app: str) -> str:
    # /servicesNS/{owner}/{app}/saved/searches
    return f"{url.rstrip('/')}/servicesNS/{quote(owner)}/{quote(app)}/saved/searches"

def saved_search_exists(url_base: str, headers: dict, name: str, verify: bool) -> bool:
    # GET /servicesNS/{owner}/{app}/saved/searches/{name}
    get_url = f"{url_base}/{quote(name)}"
    r = requests.get(get_url, headers=headers, verify=verify)
    return r.status_code == 200

def create_saved_search(url_base: str, headers: dict, payload: dict, verify: bool):
    r = requests.post(url_base, headers=headers, data=payload, verify=verify)
    return r

def update_saved_search(url_base: str, headers: dict, name: str, payload: dict, verify: bool):
    put_url = f"{url_base}/{quote(name)}"
    r = requests.post(put_url, headers=headers, data=payload, verify=verify)
    return r

def build_payload(args) -> dict:
    data = {
        # Required-ish fields
        "name": args.rule,               # only used on create; ignored on update endpoint
        "search": args.query,
        "description": args.description,

        # On/Off
        "disabled": "1" if args.disabled else "0",
    }

    # Scheduling
    if args.schedule:
        data["is_scheduled"] = "1"
        data["cron_schedule"] = args.schedule
        # Dispatch timeframe defaults (tweak to your needs)
        # data["dispatch.earliest_time"] = "-15m"
        # data["dispatch.latest_time"] = "now"
    else:
        data["is_scheduled"] = "0"

    # Alerting basics
    # Splunk expects severity 1..6; store in 'alert.severity'
    data["alert.severity"] = str(max(1, min(args.severity, 6)))

    actions = [a.strip() for a in args.actions.split(",") if a.strip()]
    if actions:
        data["actions"] = ",".join(actions)

        # Webhook action config
        if "webhook" in actions and args.webhook_url:
            data["action.webhook"] = "1"
            data["action.webhook.param.url"] = args.webhook_url

        # Email action config
        if "email" in actions and args.email_to:
            data["action.email"] = "1"
            data["action.email.to"] = args.email_to

    # Misc common alert types can be further configured here (throttling, condition, etc.)
    # e.g., data["alert.track"] = "1"  # track alert in triggered alerts
    return data

def main():
    args = parse_args()
    headers = auth_header(args.token, args.auth_type)
    headers["Content-Type"] = "application/x-www-form-urlencoded"

    base = endpoint_base(args.url, args.owner, args.app)
    payload = build_payload(args)

    if args.dry_run:
        print("[dry-run] Would send:")
        print(f"  Endpoint base: {base}")
        print(f"  Exists?       (skipped check)")
        print(f"  Payload: {payload}")
        return 0

    try:
        verify = args.verify_ssl
        exists = saved_search_exists(base, headers, args.rule, verify)

        if not exists:
            # Create
            r = create_saved_search(base, headers, payload, verify)
            if r.status_code not in (200, 201):
                print(f"ERROR: Create failed [{r.status_code}] -> {r.text}", file=sys.stderr)
                return 2
            print(f"✓ Created saved search '{args.rule}' in app='{args.app}', owner='{args.owner}'")
            return 0

        # Update
        # Remove 'name' from payload on update to avoid conflicts
        payload_update = {k: v for k, v in payload.items() if k != "name"}
        r = update_saved_search(base, headers, args.rule, payload_update, verify)
        if r.status_code not in (200, 201):
            print(f"ERROR: Update failed [{r.status_code}] -> {r.text}", file=sys.stderr)
            return 3
        print(f"✓ Updated saved search '{args.rule}' in app='{args.app}', owner='{args.owner}'")
        return 0

    except requests.exceptions.RequestException as e:
        print(f"ERROR: HTTP error -> {e}", file=sys.stderr)
        return 4

if __name__ == "__main__":
    sys.exit(main())
