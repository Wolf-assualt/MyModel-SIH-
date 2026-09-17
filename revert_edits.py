import json
import os

with open('transcript_edits_full.jsonl', 'r', encoding='utf-16') as f:
    lines = f.readlines()

edits = []
for line in lines:
    try:
        data = json.loads(line)
        if 'tool_calls' in data:
            for tc in data['tool_calls']:
                if tc['name'] in ('replace_file_content', 'multi_replace_file_content'):
                    edits.append(tc)
    except Exception as e:
        pass

# Reverse order to undo
edits.reverse()

print(f"Found {len(edits)} edits to undo.")

for tc in edits:
    args = tc['args']
    # Handle the fact that args might be strings if it's the raw json tool call
    if isinstance(args, str):
        args = json.loads(args)
        
    target_file = args.get('TargetFile')
    if not target_file:
        continue
    
    # Strip quotes if necessary
    if target_file.startswith('"') and target_file.endswith('"'):
        target_file = target_file[1:-1]
        
    print(f"Undoing edit in {target_file}")
    
    if not os.path.exists(target_file):
        print(f"  File not found: {target_file}")
        continue
        
    with open(target_file, 'r', encoding='utf-8') as f:
        content = f.read().replace('\r\n', '\n')
        
    changed = False
    if tc['name'] == 'replace_file_content':
        target_content = args.get('TargetContent', '').replace('\r\n', '\n')
        rep_content = args.get('ReplacementContent', '').replace('\r\n', '\n')
        if isinstance(target_content, str) and target_content.startswith('"') and target_content.endswith('"'):
            target_content = target_content[1:-1]
            rep_content = rep_content[1:-1]
            
        # Reverse!
        if rep_content in content:
            content = content.replace(rep_content, target_content)
            changed = True
        else:
            print(f"  Warning: Replacement content not found in {target_file} (already reverted or modified again?)")
            
    elif tc['name'] == 'multi_replace_file_content':
        chunks = args.get('ReplacementChunks', [])
        if isinstance(chunks, str):
            chunks = json.loads(chunks)
            
        for chunk in chunks:
            target_content = chunk.get('TargetContent', '').replace('\r\n', '\n')
            rep_content = chunk.get('ReplacementContent', '').replace('\r\n', '\n')
            
            if rep_content in content:
                content = content.replace(rep_content, target_content)
                changed = True
            else:
                print(f"  Warning: Replacement content not found in {target_file}")
                
    if changed:
        with open(target_file, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"  Successfully reverted.")
