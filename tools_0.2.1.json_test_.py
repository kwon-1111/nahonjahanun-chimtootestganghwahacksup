#!/usr/bin/env python3
"""
generate_nmap_commands.py
Loads an nmap action-space JSON and generates random (safe) example nmap command strings.
Does NOT execute nmap.

Usage:
  python3 generate_nmap_commands.py /path/to/nmap_action_space.json --count 5
"""
import json, random, re, argparse, os, sys

def load_schema(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

# --- simple samplers ---
def sample_ip_targets():
    choices = [
        "192.168.1.0/24",
        "10.0.0.5",
        "172.16.0.0/28",
        "example.com",
        "test.local"
    ]
    if random.random() < 0.3:
        return " ".join(random.sample(choices, k=random.randint(1,3)))
    return random.choice(choices)

def sample_ports_list():
    common = [22,80,443,21,23,25,53,3306,1433,3389]
    ports = []
    for _ in range(random.randint(1,4)):
        if random.random() < 0.6:
            p = str(random.choice(common))
        else:
            p = str(random.randint(1,65535))
        if p not in ports:
            ports.append(p)
    return ",".join(ports)

def sample_top_n():
    return random.randint(10,1000)

def sample_timing(schema):
    if 'types' in schema and 'timing' in schema['types'] and 'enum' in schema['types']['timing']:
        return random.choice(schema['types']['timing']['enum'])
    return random.choice(["T0","T1","T2","T3","T4","T5"])

def sample_bool(default=False):
    return random.choice([True, False]) if random.random() < 0.9 else default

def sample_filename(prefix="scan"):
    suf = random.randint(1,9999)
    return f"{prefix}_{suf}"

def sample_min_max_rate():
    return random.randint(10,5000)

def sample_retries():
    return random.randint(0,5)

def sample_host_timeout():
    return random.randint(1,600)

# --- minimal templating to render the provided mustache-like templates ---
def render_template(tmpl, ctx, globals_):
    out = tmpl
    # replace globals placeholders first
    out = re.sub(r"\{\{\s*globals\.([a-zA-Z0-9_]+)\s*\}\}", lambda m: str(globals_.get(m.group(1), "")), out)
    # handle sections: {{#key}} ... {{/key}}
    def section_repl(m):
        key = m.group(1)
        inner = m.group(2)
        val = ctx.get(key)
        if val:
            return render_template(inner, ctx, globals_)
        return ""
    out = re.sub(r"\{\{\#\s*([a-zA-Z0-9_]+)\s*\}\}(.+?)\{\{/\s*\1\s*\}\}", section_repl, out, flags=re.DOTALL)
    # defaults: {{name|default:VALUE}}
    def default_repl(m):
        name = m.group(1)
        default = m.group(2)
        val = ctx.get(name)
        if val is None:
            return str(default)
        return str(val)
    out = re.sub(r"\{\{\s*([a-zA-Z0-9_]+)\s*\|\s*default\s*:\s*(.*?)\s*\}\}", default_repl, out)
    # simple vars
    out = re.sub(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}", lambda m: str(ctx.get(m.group(1), "")), out)
    out = re.sub(r"\s+\n", "\n", out)
    out = re.sub(r"\s{2,}", " ", out)
    return out.strip()

def generate_random_action(schema):
    action = random.choice(schema['actions'])
    space = action.get('action_space', {})
    globals_ = schema.get('globals', {})
    ctx = {}
    for name, meta in space.items():
        t = meta.get('type')
        if name == 'targets' or t == 'ip_targets':
            ctx[name] = sample_ip_targets()
        elif name == 'ports' or t == 'port_list':
            ctx[name] = sample_ports_list()
        elif t == 'top_n' or name == 'top_n':
            ctx[name] = sample_top_n()
        elif t == 'timing' or name == 'timing':
            ctx[name] = sample_timing(schema)
        elif t == 'bool' or name in ('save','no_ping'):
            default = meta.get('default', False)
            ctx[name] = sample_bool(default)
        elif t == 'filename' or name == 'out_prefix':
            ctx[name] = sample_filename(prefix=meta.get('default','scan'))
        elif name == 'min_rate' or name == 'max_rate':
            ctx[name] = sample_min_max_rate()
        elif name == 'retries':
            ctx[name] = sample_retries()
        elif name == 'host_timeout':
            ctx[name] = sample_host_timeout()
        else:
            ctx[name] = meta.get('default', '')
    cmd = render_template(action.get('command_template',''), ctx, globals_)
    return {"action": action.get('name'), "args": ctx, "command": cmd}

def generate_n(schema, n=5):
    return [generate_random_action(schema) for _ in range(n)]

def main():
    json_path = './tools_0.2.1.json'
    p = argparse.ArgumentParser()
    count = 5
    schema = load_schema(json_path)
    samples = generate_n(schema, count)
    print(json.dumps(samples, indent=2, ensure_ascii=False))

if __name__ == '__main__':
    main()
