import json

agent_events = []
seq = 0
mitm_file = '/home/harshith/simple_agent_local/obs/mitm/codex_20260305_220851.mitm.jsonl'

def get_str(c):
    if isinstance(c, str): return c
    if isinstance(c, list):
        return '\n'.join(item['text'] if isinstance(item, dict) and 'text' in item else str(item) for item in c)
    return str(c)

with open(mitm_file) as f:
    lines = f.read().splitlines()

for line in lines:
    if not line.strip():
        continue
    record = json.loads(line)
    if record.get('direction') != 'response':
        continue

    req_body = record.get('request_body') or {}
    resp_body = record.get('response_body') or {}
    model = record.get('model', '')
    messages = req_body.get('messages', [])
    if not messages and 'input' in req_body:
        messages = req_body['input']
    choices = resp_body.get('choices', [])

    print(f"\n--- Processing response record, input_count={len(messages)}, choices={len(choices)}, has_raw={bool(resp_body.get('_raw'))} ---")

    if not choices and resp_body.get('_raw'):
        content_pieces = []
        tool_calls_dict = {}
        for rline in resp_body['_raw'].splitlines():
            if rline.startswith('data: '):
                try:
                    data = json.loads(rline[6:])
                    dtype = data.get('type')
                    if dtype in ['response.text.delta', 'response.output_text.delta']:
                        content_pieces.append(data.get('delta', ''))
                    elif dtype == 'response.output_item.added':
                        item = data.get('item', {})
                        if item.get('type') == 'function_call':
                            item_id = item.get('id')
                            t_id = item.get('call_id')
                            tool_calls_dict[item_id] = {'call_id': t_id, 'name': item.get('name'), 'arguments': ''}
                    elif dtype == 'response.function_call_arguments.delta':
                        item_id = data.get('item_id')
                        if item_id in tool_calls_dict:
                            tool_calls_dict[item_id]['arguments'] += data.get('delta', '')
                except Exception:
                    pass
        print(f"  SSE parsed: content_pieces={len(content_pieces)}, tool_calls_dict keys={list(tool_calls_dict.keys())}")
        if content_pieces or tool_calls_dict:
            tcs = [{'id': tc.get('call_id', tid), 'function': {'name': tc['name'], 'arguments': tc['arguments']}} for tid, tc in tool_calls_dict.items()]
            choices = [{'message': {'content': ''.join(content_pieces), 'tool_calls': tcs}}]

    # user prompts
    emitted_prompt_count = sum(1 for e in agent_events if e.get('event_type') == 'user_prompt')
    current_user_msgs = [m for m in messages if m.get('role') == 'user']
    new_prompts = current_user_msgs[emitted_prompt_count:]
    print(f"  user_prompts: already_emitted={emitted_prompt_count}, total_in_input={len(current_user_msgs)}, new={len(new_prompts)}")
    for msg in new_prompts:
        seq += 1
        agent_events.append({'seq': seq, 'event_type': 'user_prompt', 'payload': {'content': get_str(msg.get('content', ''))[:40]}})

    # tool results
    emitted_tool_results = {e['payload']['tool_call_id'] for e in agent_events if e.get('event_type') == 'tool_call_finished'}
    tool_result_msgs = [m for m in messages if m.get('role') == 'tool' or m.get('type') == 'function_call_output']
    print(f"  tool_results_in_input={len(tool_result_msgs)}, already_emitted_tool_finished={len(emitted_tool_results)}")
    for msg in messages:
        is_tool_chat = msg.get('role') == 'tool'
        is_tool_resp = msg.get('type') == 'function_call_output'
        if not (is_tool_chat or is_tool_resp):
            continue
        tid = msg.get('tool_call_id') or msg.get('call_id', '')
        if not tid or tid in emitted_tool_results:
            print(f"    skipping call_id={tid!r} (already_emitted={tid in emitted_tool_results})")
            continue
        emitted_tool_results.add(tid)
        tool_name = 'unknown'
        for m2 in messages:
            if m2.get('type') == 'function_call' and m2.get('call_id') == tid:
                tool_name = m2.get('name', 'unknown')
                break
        seq += 1
        agent_events.append({'seq': seq, 'event_type': 'tool_call_finished', 'payload': {'tool_call_id': tid, 'tool_name': tool_name}})
        print(f"    emitted tool_call_finished: tool_name={tool_name}, call_id={tid!r}")

    # choices
    print(f"  choices: {len(choices)}")
    for choice in choices:
        msg = choice.get('message') or {}
        content = msg.get('content')
        tool_calls = msg.get('tool_calls') or []
        if content:
            seq += 1
            agent_events.append({'seq': seq, 'event_type': 'assistant_response', 'payload': {'content': content[:40]}})
            print(f"    emitted assistant_response: {content[:40]!r}")
        for tc in tool_calls:
            func = tc.get('function', {})
            seq += 1
            agent_events.append({'seq': seq, 'event_type': 'tool_call_started', 'payload': {'tool_call_id': tc.get('id', ''), 'tool_name': func.get('name', '?')}})
            print(f"    emitted tool_call_started: {func.get('name', '?')!r}")

print('\nTotal events:', len(agent_events))
for e in agent_events:
    p = e['payload']
    print(f"  [{e['seq']}] {e['event_type']}: {str(p)[:90]}")
