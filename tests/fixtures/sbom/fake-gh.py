#!/usr/bin/env python3
"""Model release state for workflow tests; never contact GitHub."""

import json
import os
import sys
from pathlib import Path


path = Path(os.environ["FAKE_GH_STATE"])
state = json.loads(path.read_text())
args = sys.argv[1:]
state.setdefault("commands", []).append(args)
status = 0
output = ""

if args[:2] == ["release", "view"]:
    if not state.get("exists"):
        status = 1
    elif args[args.index("--json") + 1] == "isDraft":
        output = str(state["draft"]).lower()
    elif state.get("fail_asset_list"):
        status = 1
    else:
        output = "\n".join(state.get("assets", []))
elif args[:2] == ["release", "create"]:
    state.update(exists=True, draft="--draft" in args)
    state["notes"] = Path(args[args.index("--notes-file") + 1]).read_text()
elif args[:2] == ["release", "upload"]:
    if state.get("fail_upload"):
        status = 1
    else:
        assets = set(state.get("assets", []))
        assets.update(Path(arg).name for arg in args[3:] if not arg.startswith("--"))
        state["assets"] = sorted(assets)
elif args[:2] == ["release", "edit"]:
    state["draft"] = "--draft=false" not in args
else:
    raise SystemExit(f"unexpected gh invocation: {args}")

path.write_text(json.dumps(state))
if output:
    print(output)
raise SystemExit(status)
