import re
import ipaddress
from pathlib import Path

def extract_quoted(s):
    """Список значений в двойных кавычках из строки."""
    return re.findall(r'"([^"]*)"', s)

def extract_domain_from_token_fallback(token):
    """fallback: если не нашли явный fqdn, вернём всё после первой точки."""
    if '.' in token:
        return token.split('.', 1)[1]
    return token

def capture_block_lines(lines, target_config):
    captured = []
    in_block = False
    depth = 0
    for raw in lines:
        line = raw.strip()
        if line.startswith('config '):
            if not in_block and line == target_config:
                in_block = True
                depth = 1
                continue
            elif in_block:
                depth += 1
        if in_block:
            if line == 'end':
                depth -= 1
                if depth == 0:
                    in_block = False
                    break
                else:
                    captured.append(raw)
                    continue
            else:
                captured.append(raw)
    return captured

def parse_edit_blocks(block_lines):
    edits = []
    current_name = None
    current_lines = []
    in_edit = False
    for raw in block_lines:
        line = raw.strip()
        if line.startswith('edit '):
            if in_edit:
                edits.append((current_name, current_lines))
            m = re.match(r'edit\s+"([^"]*)"', line)
            if m:
                current_name = m.group(1) if m.group(1) != '' else '<unnamed>'
            else:
                rest = line[5:].strip()
                current_name = rest or '<unnamed>'
            current_lines = []
            in_edit = True
            continue
        if line == 'next':
            if in_edit:
                edits.append((current_name, current_lines))
                in_edit = False
                current_name = None
                current_lines = []
            continue
        if in_edit:
            current_lines.append(raw.rstrip('\n'))
    if in_edit and current_name is not None:
        edits.append((current_name, current_lines))
    return edits

def build_global_edit_map(lines):
    """
    Пробегаем по всему файлу и собираем map всех edit "NAME" -> body_lines.
    """
    edit_map = {}
    in_edit = False
    current_name = None
    current_lines = []
    for raw in lines:
        line = raw.strip()
        if line.startswith('edit '):
            if in_edit and current_name is not None:
                edit_map[current_name] = current_lines
            m = re.match(r'edit\s+"([^"]*)"', line)
            if m:
                current_name = m.group(1) if m.group(1) != '' else '<unnamed>'
            else:
                rest = line[5:].strip()
                current_name = rest or '<unnamed>'
            current_lines = []
            in_edit = True
            continue
        if line == 'next':
            if in_edit and current_name is not None:
                edit_map[current_name] = current_lines
            in_edit = False
            current_name = None
            current_lines = []
            continue
        if in_edit:
            current_lines.append(raw.rstrip('\n'))
    if in_edit and current_name is not None:
        edit_map[current_name] = current_lines
    return edit_map

def find_fqdn_in_edit(body_lines):
    """
    Ищем внутри тела edit строку 'set fqdn "..."' и возвращаем значение в кавычках.
    """
    for raw in body_lines:
        line = raw.strip()
        if line.startswith('set fqdn '):
            quoted = extract_quoted(line)
            if quoted:
                return quoted[0]
    return None

def find_subnet_in_edit(body_lines):
    """
    Ищем 'set subnet <ip> <mask>' и вернём строку "<ip>/<prefix>".
    Если нашли несколько — вернём первый.
    """
    for raw in body_lines:
        line = raw.strip()
        if line.startswith('set subnet '):
            parts = line.split()
            # Ожидаем: ['set', 'subnet', '31.186.103.69', '255.255.255.255' ...]
            if len(parts) >= 4:
                ip = parts[2]
                mask = parts[3]
                try:
                    net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                    prefix = net.prefixlen
                    return f"{ip}/{prefix}"
                except Exception:
                    return ip
    return None

def process_block(block_lines, block_type, global_edit_map):
    """
    Парсит edit-блоки и извлекает интересующие поля.
    Логика резолвинга member'ов:
      - h-<ip>  -> ищем edit и set subnet, иначе ip/32
      - содержит точку -> ищем edit -> set fqdn -> set subnet -> fallback (после первой точки)
      - иначе (имена типа AC_*) -> ищем edit -> set subnet -> set fqdn -> fallback (оставить имя)
    """
    edits = parse_edit_blocks(block_lines)
    results = {}
    for name, body in edits:
        entry = {'members': [], 'raw': body}
        for raw in body:
            line = raw.strip()
            if line.startswith('set member '):
                quoted = extract_quoted(line)
                if not quoted:
                    after = line[len('set member '):].strip()
                    if after:
                        parts = after.split()
                        quoted = [p.strip('"') for p in parts if p.strip()]
                entry['members'].extend(quoted)

        if block_type.endswith('addrgrp'):
            processed = []
            for tok in entry['members']:
                # 1) Объекты вида h-<ip>
                m_ipobj = re.match(r'^h-(\d{1,3}(?:\.\d{1,3}){3})$', tok)
                if m_ipobj:
                    edit_body = global_edit_map.get(tok)
                    if edit_body:
                        subnet_str = find_subnet_in_edit(edit_body)
                        if subnet_str:
                            processed.append(subnet_str)
                            continue
                    ip_only = m_ipobj.group(1)
                    processed.append(f"{ip_only}/32")
                    continue

                # 2)Токен содержит точку -> вероятный FQDN/Internet_* объект
                if '.' in tok:
                    edit_body = global_edit_map.get(tok)
                    if edit_body:
                        fqdn = find_fqdn_in_edit(edit_body)
                        if fqdn:
                            processed.append(fqdn)
                            continue
                        subnet_str = find_subnet_in_edit(edit_body)
                        if subnet_str:
                            processed.append(subnet_str)
                            continue
                    # fallback: старое поведение (всё после первой точки)
                    processed.append(extract_domain_from_token_fallback(tok))
                    continue

                # 3)Прочие имена (AC_*, NetApp_*, Internet_Check)
                # Попробуем найти edit с таким именем и взять subnet или fqdn
                edit_body = global_edit_map.get(tok)
                if edit_body:
                    subnet_str = find_subnet_in_edit(edit_body)
                    if subnet_str:
                        processed.append(subnet_str)
                        continue
                    fqdn = find_fqdn_in_edit(edit_body)
                    if fqdn:
                        processed.append(fqdn)
                        continue
                # если ничего не найдено — оставляем оригинальное имя
                processed.append(tok)

            entry['processed_members'] = processed

        results[name] = entry
    return results

def format_output(results, block_type):
    """
    Форматируем так, чтобы IP и DNS имена были в отдельных секциях:
    NAME:
        IP:
        <ip1>
        <ip2>
        DNS:
        <dns1>
        <dns2>
    """
    lines = []

    def is_ip_token(token):
        # Попробуем распарсить как сеть/адрес — если получилось, считаем IP
        try:
            ipaddress.ip_network(token, strict=False)
            return True
        except Exception:
            return False

    for name, data in results.items():
        members = data.get('processed_members', data.get('members', []))
        if not members:
            continue

        ip_list = []
        dns_list = []
        for m in members:
            if is_ip_token(m):
                ip_list.append(m)
            else:
                dns_list.append(m)

        # Если нет ни IP, ни DNS — пропускаем
        if not ip_list and not dns_list:
            continue

        lines.append(f"{name}:")
        # сначала IP
        if ip_list:
            lines.append("    IP:")
            for ip in ip_list:
                lines.append(f"    {ip}")
        # затем DNS
        if dns_list:
            lines.append("    DNS:")
            for d in dns_list:
                lines.append(f"    {d}")
        lines.append("")

    return '\n'.join(lines).rstrip() + '\n' if lines else ''

def write_output_file(content, filename):
    script_dir = Path(__file__).resolve().parent
    path = script_dir / filename
    path.write_text(content, encoding='utf-8')
    return str(path)


if __name__ == '__main__':
    script_dir = Path(__file__).resolve().parent

    config_file = input("Введите имя файла конфига (например config.txt): ").strip()
    config_path = script_dir / config_file
    if not config_path.exists():
        print(f"Файл не найден: {config_path}")
        exit(1)

    with config_path.open('r', encoding='utf-8', errors='ignore') as f:
        lines = f.read().splitlines()

    # Сначала строим глобальную карту всех edit "NAME"->body_lines
    global_edit_map = build_global_edit_map(lines)

    target = input("Enter config (например: config firewall addrgrp): ").strip()
    block = capture_block_lines(lines, target)
    if not block:
        print("Указанный блок не найден.")
        exit(0)

    results = process_block(block, target, global_edit_map)
    out = format_output(results, target)

    if out:
        out_file = f"{target.replace(' ', '_')}_parsed.txt"
        out_path = script_dir / out_file
        out_path.write_text(out, encoding='utf-8')
        print(f"\nФайл создан: {out_path}")
    else:
        print("В блоке нет set member.")
