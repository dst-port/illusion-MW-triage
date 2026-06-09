#!/usr/bin/env python3
import os

ROOT = os.path.abspath(os.path.dirname(__file__) + "/..")
EXTS = {'.rs', '.c', '.cpp', '.h', '.hpp', '.js', '.ts', '.java', '.go', '.kt', '.swift', '.cs'}
modified = []


def process_line(line: str):
    out_chars = []
    i = 0
    in_double = False
    in_single = False
    escaped = False
    L = len(line)
    while i < L:
        ch = line[i]
        nxt = line[i + 1] if i + 1 < L else ''
        if escaped:
            out_chars.append(ch)
            escaped = False
            i += 1
            continue
        if ch == '\\' and (in_double or in_single):
            out_chars.append(ch)
            escaped = True
            i += 1
            continue
        if ch == '"' and not in_single:
            out_chars.append(ch)
            in_double = not in_double
            i += 1
            continue
        if ch == "'" and not in_double:
            out_chars.append(ch)
            in_single = not in_single
            i += 1
            continue
        if ch == '/' and nxt == '/' and not in_double and not in_single:
            break
        out_chars.append(ch)
        i += 1
    new_line = ''.join(out_chars)
    if new_line.strip() == '':
        return None
    else:
        if line.endswith('\n'):
            return new_line.rstrip() + '\n'
        else:
            return new_line


def process_file(path: str):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception:
        return False
    changed = False
    new_lines = []
    for line in lines:
        if '//' not in line:
            new_lines.append(line)
            continue
        pl = process_line(line)
        if pl is None:
            changed = True
        else:
            if pl != line:
                changed = True
            new_lines.append(pl)
    if changed:
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
        except Exception:
            return False
        modified.append(path)
        return True
    return False


def is_text_file(path: str):
    _, ext = os.path.splitext(path)
    return ext.lower() in EXTS


for dirpath, dirnames, filenames in os.walk(ROOT):
    skip_dirs = {'.git', 'target', 'runs', 'quarantine', 'hunt_reports'}
    dirnames[:] = [d for d in dirnames if d not in skip_dirs]
    for name in filenames:
        path = os.path.join(dirpath, name)
        if not is_text_file(path):
            continue
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = f.read()
        except Exception:
            continue
        if '//' in data:
            process_file(path)

if modified:
    print('Modified files:')
    for m in modified:
        print(m)
else:
    print('No files modified.')
