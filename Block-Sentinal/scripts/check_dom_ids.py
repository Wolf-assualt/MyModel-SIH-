import re
from pathlib import Path

html_content = Path("backend/app/templates/index.html").read_text(encoding="utf-8")
js_app = Path("backend/app/static/js/app.js").read_text(encoding="utf-8")
js_graph = Path("backend/app/static/js/graph.js").read_text(encoding="utf-8")

# Extract all IDs from HTML
html_ids = set(re.findall(r'id=["\']([^"\']+)["\']', html_content))

# Extract all getElementById from JS
app_ids = set(re.findall(r"getElementById\(['\"]([^'\"]+)['\"]\)", js_app))
graph_ids = set(re.findall(r"getElementById\(['\"]([^'\"]+)['\"]\)", js_graph))

all_js_ids = app_ids.union(graph_ids)
missing_ids = []

for elem_id in all_js_ids:
    # Filter out dynamic IDs like stage-view-${phaseNum} or stage-item-${stageIndex}
    if "${" in elem_id:
        continue
    if elem_id not in html_ids:
        missing_ids.append(elem_id)

print(f"Total HTML IDs: {len(html_ids)}")
print(f"Total JS Referenced IDs: {len(all_js_ids)}")
print(f"Missing IDs in HTML: {missing_ids}")
