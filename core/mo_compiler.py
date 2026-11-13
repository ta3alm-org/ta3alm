"""
core/mo_compiler.py
مترجم تلقائي لملفات الترجمة (.po -> .mo) بلغة بايثون الخالصة (بدون الحاجة لـ gettext / msgfmt).
يعمل تلقائياً عند تشغيل المشروع لتحديث ملف django.mo فور أي تعديل في django.po.
"""
import array
import ast
import gettext
import os
import struct
from pathlib import Path


def _parse_po_file(po_path: Path) -> dict[str, str]:
    """قراءة ملف .po واستخراج أزواج msgid و msgstr غير الفارغة وغير الضبابية (non-fuzzy)."""
    messages: dict[str, str] = {}
    lines = po_path.read_text(encoding='utf-8').splitlines()

    current_msgid: list[str] = []
    current_msgstr: list[str] = []
    state = None  # 'msgid' | 'msgstr' | None
    is_fuzzy = False

    def commit_entry():
        nonlocal current_msgid, current_msgstr, state, is_fuzzy
        if state == 'msgstr':
            msgid_str = ''.join(current_msgid)
            msgstr_str = ''.join(current_msgstr)
            # نحفظ الترويسة (msgid == "") وأي ترجمة غير فارغة وغير fuzzy
            if not is_fuzzy and (msgid_str == '' or msgstr_str != ''):
                # في حالة وجود تكرار لنفس الـ msgid، نفضل الترجمة غير الفارغة
                if msgid_str not in messages or msgstr_str:
                    messages[msgid_str] = msgstr_str
        current_msgid = []
        current_msgstr = []
        state = None
        is_fuzzy = False

    for raw_line in lines:
        line = raw_line.strip()

        if not line:
            commit_entry()
            continue

        if line.startswith('#,'):
            if state == 'msgstr':
                commit_entry()
            if 'fuzzy' in line:
                is_fuzzy = True
            continue

        if line.startswith('#'):
            if state == 'msgstr':
                commit_entry()
            continue

        if line.startswith('msgid '):
            if state == 'msgstr':
                commit_entry()
            state = 'msgid'
            val = line[6:].strip()
            current_msgid = [ast.literal_eval(val)]
        elif line.startswith('msgstr '):
            state = 'msgstr'
            val = line[7:].strip()
            current_msgstr = [ast.literal_eval(val)]
        elif line.startswith('"') and line.endswith('"'):
            val = ast.literal_eval(line)
            if state == 'msgid':
                current_msgid.append(val)
            elif state == 'msgstr':
                current_msgstr.append(val)

    commit_entry()
    return messages


def _generate_mo_bytes(messages: dict[str, str]) -> bytes:
    """توليد البيانات الثنائية لملف .mo وفق معيار GNU gettext."""
    keys = sorted(messages.keys())
    offsets = []
    ids = b''
    strs = b''

    for k in keys:
        v = messages[k]
        id_bytes = k.encode('utf-8')
        str_bytes = v.encode('utf-8')
        offsets.append((len(ids), len(id_bytes), len(strs), len(str_bytes)))
        ids += id_bytes + b'\x00'
        strs += str_bytes + b'\x00'

    # الهيدر طوله 7 أعداد صحيحة (28 بايت)
    keystart = 7 * 4 + 16 * len(keys)
    valuestart = keystart + len(ids)

    koffsets = []
    voffsets = []
    for o1, l1, o2, l2 in offsets:
        koffsets += [l1, o1 + keystart]
        voffsets += [l2, o2 + valuestart]

    all_offsets = koffsets + voffsets
    output = struct.pack(
        'Iiiiiii',
        0x950412de,        # Magic number
        0,                 # Version
        len(keys),         # Number of entries
        7 * 4,             # Start of key index
        7 * 4 + len(keys) * 8,  # Start of value index
        0, 0               # Size and offset of hash table
    )
    output += array.array('i', all_offsets).tobytes()
    output += ids
    output += strs
    return output


def ensure_mo_compiled(base_dir: Path | str | None = None) -> bool:
    """
    يتحقق من جميع ملفات django.po داخل مجلد locale ويقوم بترجمتها تلقائياً إلى django.mo
    إذا كان ملف .po أحدث من .mo أو إذا لم يكن .mo موجوداً.
    """
    if base_dir is None:
        from django.conf import settings
        base_dir = Path(settings.BASE_DIR)
    else:
        base_dir = Path(base_dir)

    locale_dir = base_dir / 'locale'
    if not locale_dir.exists():
        return False

    updated = False
    for po_path in locale_dir.glob('*/LC_MESSAGES/django.po'):
        mo_path = po_path.with_suffix('.mo')
        try:
            need_compile = (
                not mo_path.exists()
                or po_path.stat().st_mtime >= mo_path.stat().st_mtime
            )
            if need_compile:
                messages = _parse_po_file(po_path)
                mo_bytes = _generate_mo_bytes(messages)
                mo_path.write_bytes(mo_bytes)
                updated = True
        except Exception as exc:
            print(f"[mo_compiler] Error compiling {po_path}: {exc}")

    if updated:
        try:
            gettext._translations.clear()
            from django.utils.translation import trans_real
            trans_real._translations.clear()
        except Exception:
            pass

    return updated

