"""Research-session MCP transport; JSON commands arrive on stdin, evidence saved locally."""
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
os.environ['GHIDRA_INSTALL_DIR'] = str(root / '.tools/ghidra_12.1.4_PUBLIC')
os.environ['JAVA_HOME'] = str(next((root / '.tools').glob('jdk-25*')))
os.environ['REA_GHIDRA_STARTUP_TIMEOUT_MS'] = '1800000'
destination = root / 'analysis/ghidra'
stderr = (destination / 'rea_stderr.log').open('a', encoding='utf-8')
process = subprocess.Popen([str(root / '.tools/node.exe'), str(root / '.tools/rea/node_modules/rea-agents/scripts/rea.mjs'), 'mcp'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, text=True, encoding='utf-8', bufsize=1)
counter = 0


def rpc(method, params):
    global counter
    counter += 1
    process.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': counter, 'method': method, 'params': params}) + '\n')
    process.stdin.flush()
    while True:
        line = process.stdout.readline()
        if not line:
            raise RuntimeError('REA exited: ' + str(process.poll()))
        message = json.loads(line)
        if message.get('id') == counter:
            return message


try:
    initialized = rpc('initialize', {'protocolVersion': '2025-03-26', 'capabilities': {}, 'clientInfo': {'name': 'manager-research', 'version': '1'}})
    assert initialized['result']['serverInfo'] == {'name': 'rea', 'version': '6.8.0'}, initialized
    print('REA 6.8.0 initialized', flush=True)
    process.stdin.write(json.dumps({'jsonrpc': '2.0', 'method': 'notifications/initialized'}) + '\n')
    process.stdin.flush()
    catalog = rpc('tools/list', {})
    (destination / 'rea_tools.json').write_text(json.dumps(catalog, indent=2), encoding='utf-8')
    assert any(t['name'] == 'open_binary' for t in catalog['result']['tools'])
    print('READY tools=' + str(len(catalog['result']['tools'])), flush=True)
    for line in sys.stdin:
        try:
            command = json.loads(line)
            if command.get('quit'):
                break
            name = command['name']
            print('RUNNING ' + name, flush=True)
            result = rpc('tools/call', {'name': name, 'arguments': command.get('arguments', {})})
            output = destination / command.get('save', name + '.json')
            if output.resolve().parent != destination.resolve():
                raise ValueError('save must be a filename inside analysis/ghidra')
            output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf-8')
            print('SAVED ' + str(output) + '\n' + json.dumps(result, ensure_ascii=True)[:3500], flush=True)
            if result.get('error') or result.get('result', {}).get('isError'):
                print('STOP: inspect the saved error before another request', flush=True)
                break
        except (ValueError, KeyError) as exc:
            print('COMMAND ERROR ' + str(exc), flush=True)
finally:
    process.stdin.close()
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.terminate()
    stderr.close()
