#!/bin/bash
# Generates a new scan_id and updates config.json before a manual scan
SCAN_ID=$(python3 -c "import uuid; print(str(uuid.uuid4()))")
python3 << PYEOF
import json
with open('/opt/dast-platform/config.json') as f:
    config = json.load(f)
config['scan_id'] = "$SCAN_ID"
with open('/opt/dast-platform/config.json', 'w') as f:
    json.dump(config, f, indent=2)
PYEOF
echo "New scan_id: $SCAN_ID"
