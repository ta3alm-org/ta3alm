"""
core/profanity_filter.py
محرك كشف الألفاظ القبيحة والجنسية والشتائم متعدد الطبقات (مضاد للزخرفة وتبديل الحروف والفواصل والفرانكو) مع حظر فوري في الشات.
"""
from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProfanityMatch:
    detected: bool
    matched_term: str = ''
    category: str = ''
    strategy: str = ''


_ZERO_WIDTH_OR_TATWEEL_RE = re.compile(
    r'[\u0610-\u061A\u0640\u064B-\u065F\u0670\u06D6-\u06ED\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\u00AD]'
)

_AR_CHAR_MAP = str.maketrans({
    'أ': 'ا', 'إ': 'ا', 'آ': 'ا', 'ٱ': 'ا', 'ٲ': 'ا', 'ٳ': 'ا', 'ٵ': 'ا',
    'ى': 'ي', 'ئ': 'ي', 'ی': 'ي', 'ے': 'ي', 'ې': 'ي', 'ۍ': 'ي',
    'ة': 'ه', 'ھ': 'ه', 'ۀ': 'ه', 'ە': 'ه',
    'ؤ': 'و', 'ۆ': 'و', 'ۊ': 'و', 'ۋ': 'و',
    'گ': 'ك', 'ک': 'ك', 'ڭ': 'ك', 'ګ': 'ك',
    'پ': 'ب', 'ٻ': 'ب',
    'چ': 'ج', 'ڃ': 'ج',
    'ڤ': 'ف', 'ڢ': 'ف',
    'ڨ': 'ق', 'ڤ': 'ف',
    'ژ': 'ز',
    'ٹ': 'ت', 'ٺ': 'ت',
    'ڈ': 'د',
    'ڑ': 'ر',
    'ں': 'ن',
})

_LATIN_CONFUSABLES_MAP = str.maketrans({
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y',
    'х': 'x', 'і': 'i', 'ј': 'j', 'к': 'k', 'м': 'm', 'т': 't',
    'в': 'b', 'н': 'h', 'α': 'a', 'ε': 'e', 'ι': 'i', 'ο': 'o',
    'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'κ': 'k',
    '$': 's', '@': 'a', '€': 'e', '¡': 'i', '£': 'l',
})

_LATIN_LEET_MAP = str.maketrans({
    '0': 'o',
    '1': 'i',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '7': 't',
    '8': 'b',
    '9': 'g',
})

_INLINE_AR_DIGIT_MAP = str.maketrans({
    '0': 'و',
    '1': 'ا',
    '2': 'ا',
    '3': 'ع',
    '4': 'ش',
    '5': 'خ',
    '6': 'ط',
    '7': 'ح',
    '8': 'ق',
    '9': 'ص',
})

_PHONETIC_AR_MAP = str.maketrans({
    'ط': 'ت',
    'ض': 'د',
    'ظ': 'ز',
    'ذ': 'ز',
    'ص': 'س',
    'ث': 'س',
    'ق': 'ك',
    'ج': 'ك',
})

# كلمات وعبارات علمية/تعليمية آمنة لا يُسمح بظلم الطالب بسببها
_SAFE_PHRASES = (
    'قضيب مغناطيسي',
    'قضيب حديد',
    'قضيب من الحديد',
    'قضيب معدني',
    'قضيب نحاس',
    'قضيب نحاسي',
    'قضيب زجاجي',
    'اسم الجنس',
    'لا نافيه للجنس',
    'النافيه للجنس',
    'تحديد الجنس',
    'الجنس البشري',
    'حلمات التذوق',
    'عنصر النيكل',
    'سبيكه النيكل',
    'عمليه الاحلال',
    'تفاعل الاحلال',
    'تفاعل احلال',
)

_SAFE_EXACT_TOKENS = frozenset({
    'نيكل', 'النيكل', 'سكشن', 'السكشن', 'سكاشن', 'تحليل', 'التحليل',
    'مني', 'عني', 'احلال', 'الاحلال', 'اسكندريه', 'الاسكندريه',
    'سكسونيا', 'سكسوفون', 'كونت', 'باسكال', 'ديكارت', 'حول', 'عرس',
    'معرصه',  # احتياطاً لا تضاف كآمنة هنا! فقط الكلمات العلمية الآمنة أدناه:
} - {'معرصه'})

_SAFE_EXACT_TOKENS = frozenset({
    'نيكل', 'النيكل', 'سكشن', 'السكشن', 'سكاشن', 'تحليل', 'التحليل',
    'مني', 'عني', 'احلال', 'الاحلال', 'اسكندريه', 'الاسكندريه',
    'سكسونيا', 'سكسوفون', 'كونت', 'باسكال', 'ديكارت', 'حول', 'عرس',
    'تحليلات', 'متحليل', 'مقضيب', 'جنسيه',  # البطاقة الشخصية / الجنسية المصرية
    'الجنسيه', 'جنسيتي', 'الجنسين',
})

# جذور عربية صريحة (شتائم / قذف / إيحاءات جنسية / تحرش / سباب)
_AR_TOKEN_ROOTS = {
    'كسم', 'كسمك', 'كسمه', 'كسمها', 'كسمهم', 'كسمكم', 'كسمين', 'كسميات',
    'كوسم', 'كوسمك', 'كوسومك', 'كوسوم', 'كسختك', 'كسخت', 'كسامك',
    'كس', 'كسك', 'كسها', 'كسهم', 'كسين', 'اكساس',
    'شرموط', 'شرموطه', 'شرموطة', 'شراميط', 'متشرمط', 'بتشرمط', 'شرمطه',
    'متناك', 'متناكه', 'متناكين', 'منيوك', 'منيوكه', 'منايك', 'منايكه',
    'نيك', 'انيك', 'انيكك', 'هنيكك', 'نيكك', 'نيكت', 'تتناك', 'بتتناك', 'بيتناك', 'نايك', 'نايكه', 'منيك',
    'قحبه', 'قحاب', 'مقحب', 'قحبت',
    'عاهره', 'عاهر', 'عاهرات', 'دعاره',
    'لبوه', 'لبوات', 'ملبو',
    'عرص', 'عرصات', 'معرص', 'معرصه', 'معرصين', 'تعريص',
    'خول', 'خولات', 'مخول', 'خولنه',
    'ديوث', 'دياثه', 'قواد', 'قواده',
    'زبي', 'زب', 'ازبار', 'زبر', 'زبرك', 'زبره',
    'طيز', 'طيزك', 'طيزي', 'طيزها', 'طيزه', 'اطياز',
    'بزاز', 'بزازك', 'بزازها', 'بز', 'بزك',
    'فشخ', 'افشخك', 'مفشوخ', 'فشخت', 'فشخك',
    'احا', 'احه', 'احيه', 'احيييه',
    'شخر', 'شخره', 'اشخر', 'خخخ',
    'وسخه', 'وسخ', 'ياوسخ', 'يوسخ', 'ابنالوسخه',
    'سافل', 'سافله', 'سفاله', 'منحط', 'منحطه', 'حقير', 'حقيره', 'واطي', 'واطيه', 'نجس', 'نجسه',
    'ملعون', 'يلعن', 'يلعنك', 'يلعندين', 'لعن', 'يلعنابوك', 'يلعنامك',
    'كلب', 'ياكلب', 'ابنكلب', 'كلبه', 'حيوان', 'حيوانه', 'حمار', 'حماره', 'خنزير', 'خنزيره', 'بهيمه',
    'تفه', 'تفو', 'تفي', 'اتفه',
    'سكس', 'سيكس', 'بورن', 'بورنو', 'اباحي', 'اباحيه', 'افلامسكس', 'نودز', 'سكسيه',
    'ممحون', 'ممحونه', 'محن', 'هيجان', 'هيجانه', 'هايج', 'هايجه',
    'شهوه', 'استمناء', 'عادهسريه', 'جماع', 'مضاجعه', 'اغتصاب', 'هغتصب',
    'مؤخره', 'مؤخرتك', 'مؤخرتها', 'حلمه', 'حلمات', 'بظر', 'مهبل', 'فرج', 'قضيب', 'شرج', 'شرجي',
    'لوطي', 'لواط', 'شاذ', 'مخنث', 'خنيث', 'مخانيث', 'سحاق', 'سحاقيه', 'مثلين',
    'صايع', 'صايعه', 'فاجر', 'فاجره', 'زاني', 'زانيه', 'زنا',
    'منيكه', 'متخلف', 'غبي', 'اهبل', 'عبيط', 'معتوه', 'تافه', 'مقرف', 'قذر', 'قذره',
    'مص', 'بوس', 'لحس', 'عريان', 'عاريه', 'قلعي', 'اقلعي', 'نقلع', 'قلع', 'تقلع',
    'بعبص', 'بعبوص', 'بعبصه', 'يبعبص', 'مبعبص',
    'خرا', 'خري', 'زق', 'كلزق', 'ياخرا', 'زفت',
}

# جذور آمنة في الالتصاق العام فقط إذا طولها >= 4 وتطابق صريح بدون التباس
_AR_JOINED_UNAMBIGUOUS_SUBSTRINGS = {
    'كسمك', 'كسمه', 'كسمها', 'كسمهم', 'كسمكم', 'كسخت', 'كوسم', 'كسامك',
    'شرموط', 'شراميط', 'شرمطه', 'متناك', 'منيوك', 'منايك', 'بتتناك', 'هنيكك', 'انيكك',
    'قحبه', 'قحاب', 'عاهره', 'عاهرات', 'لبوه', 'معرص', 'تعريص', 'خولات',
    'ديوث', 'دياثه', 'قواده', 'اطياز', 'طيزك', 'طيزها', 'بزاز', 'ازبار',
    'زبرك', 'افشخك', 'مفشوخ', 'يلعندين', 'يلعنابو', 'يلعنام', 'ممحون',
    'مخنث', 'خنيث', 'مخانيث', 'سحاقيه', 'اباحيه', 'عادهسريه', 'استمناء',
    'مضاجعه', 'اغتصاب', 'هغتصب', 'مؤخرتك', 'مؤخرتها', 'بعبص', 'بعبصه', 'يبعبص',
    'ابنالشرموط', 'ابنالمتناكه', 'ابنالقحبه', 'ابنالوسخه', 'ابنالحرام',
}

# عبارات متعددة الكلمات (تُفحص بعد تطبيع الجملة)
_AR_BAD_PHRASES = (
    'كس ام', 'كس اخت', 'امك المتناكه', 'ابن الوسخه', 'ابن الكلب', 'ابن الشرموط',
    'ابن المتناكه', 'ابن القحبه', 'ابن الحرام', 'دين امك', 'رب امك', 'يلعن دين',
    'يلعن ابوك', 'يلعن امك', 'افلام اباحيه', 'افلام سكس', 'مص زب', 'عاده سريه',
    'كل خرا', 'كل زق', 'يا ابن', 'كسم امك',
)

# كلمات إنجليزية وفرانكو صريحة
_LATIN_TOKEN_ROOTS = {
    'fuck', 'fuk', 'fck', 'fuuck', 'fucker', 'fucking', 'fucked', 'motherfucker', 'mf', 'mfer',
    'shit', 'bullshit', 'bitch', 'btch', 'biatch', 'bastard', 'asshole', 'arsehole',
    'dick', 'cock', 'pussy', 'cunt', 'whore', 'slut', 'prostitute', 'skank', 'hoe',
    'porn', 'porno', 'pornography', 'pornhub', 'xnxx', 'xvideos', 'onlyfans', 'xxx', 'sex', 'sexy',
    'nude', 'nudes', 'naked', 'boobs', 'tits', 'titties', 'penis', 'vagina', 'anal', 'anus',
    'blowjob', 'handjob', 'rimjob', 'cum', 'cumshot', 'jizz', 'orgasm', 'masturbate', 'fap',
    'horny', 'dildo', 'vibrator', 'rape', 'rapist', 'incest', 'pedophile', 'pedo',
    'faggot', 'fag', 'nigga', 'nigger', 'retard', 'retarded', 'stfu', 'gtfo', 'milf', 'bdsm',
    # Franco-Arab
    'a7a', 'a7eh', 'aha', '5awal', 'khawal', 'khawalat', '5awalat', '3ars', '3rs', 'm3aras', 'm3rs',
    'sharmoot', 'sharmoota', 'sharmout', 'sharmouta', 'sharmota', 'sharmotaa', 'sharamit',
    'metnak', 'metnaka', 'mitnak', 'mtnak', 'mtnaka', 'manyook', 'manyak', 'manyaak', 'mnak',
    'kosom', 'kosomak', 'kosmk', 'ksmk', 'kosomhom', 'kossomak', 'kosomha', 'koso5tak', 'kos5tak',
    'neek', 'aneek', 'neekak', 'nik', 'zob', 'zobr', 'zbri', 'zobri', 'zeb', 'zebbi',
    'teez', 'tiz', 'teezak', 'bazz', 'bzaz', 'bzazak', 'labwa', 'qa7ba', '2a7ba', 'ahba', 'ka7ba',
    'dayouth', 'dayooth', 'wes5a', 'weskha', 'ibnws5a', 'kalb', '7omar', '7ayawan', 'khanzir',
    'm5anas', 'mokhanas', 'khaneeth', 'mema7on', 'mam7oon', 'b3bs', 'ba3bas', 'b3bosa',
}

_LATIN_JOINED_UNAMBIGUOUS = {
    'fuck', 'fucker', 'fucking', 'motherfucker', 'bitch', 'asshole', 'pussy', 'cunt',
    'whore', 'slut', 'prostitute', 'porno', 'pornhub', 'xnxx', 'xvideos', 'onlyfans',
    'blowjob', 'handjob', 'cumshot', 'masturbate', 'dildo', 'faggot', 'nigger',
    'sharmoot', 'sharmout', 'sharmota', 'metnak', 'mitnak', 'manyook', 'manyak',
    'kosom', 'ksmk', 'kosmk', 'koso5t', 'khawal', '5awal', 'm3aras', 'qa7ba', '2a7ba',
    'dayouth', 'labwa', 'teezak', 'bzaz', 'weskha', 'wes5a',
}

# كلمات قصيرة خطرة في التبديل الحرفي الصريح (ط/ت، س/ص/ث، ق/ك)
_EXPLICIT_SWAP_VARIANTS = {
    'تيز', 'تيزك', 'تيزها', 'تيزي', 'ذب', 'ذبي', 'ذبرك',
    'عرث', 'معرث', 'كثم', 'كثمك', 'كصم', 'كصمك', 'كص', 'كصك', 'كسح', 'كومك', 'كومها', 'كومهم',
    'كحبه', 'جحبه', 'كهبه', 'شرموت', 'شرموته', 'سرموط', 'سرموطه', 'ثرموط',
    'مطناكه', 'مطناج', 'منيوج', 'منيوق', 'منيوقه', 'خنيس', 'مخنس', 'حول', 'قواد', 'كواد',
    'هول',  # kept ONLY if exact 'خول' phonetic swap not colliding -> exclude 'حول' & 'هول' from swaps
} - {'حول', 'هول'}

_AR_PREFIXES = ('وال', 'بال', 'فال', 'كال', 'ال', 'لل', 'و', 'ف', 'ب', 'ل', 'ك', 'ي', 'يا', 'بت', 'هت', 'م')
_AR_SUFFIXES = ('كم', 'كن', 'هم', 'هن', 'ها', 'نا', 'ين', 'ون', 'ات', 'ان', 'يه', 'وا', 'ك', 'ه', 'ي', 'ت')


def _dedup_n(s: str, max_repeat: int = 1) -> str:
    if not s:
        return ''
    out = []
    prev = ''
    count = 0
    for ch in s:
        if ch == prev:
            count += 1
        else:
            prev = ch
            count = 1
        if count <= max_repeat:
            out.append(ch)
    return ''.join(out)


def normalize_unicode_and_decorations(text: str) -> str:
    raw = unicodedata.normalize('NFKC', str(text or ''))
    raw = _ZERO_WIDTH_OR_TATWEEL_RE.sub('', raw)
    cleaned_chars = []
    for ch in raw:
        if unicodedata.category(ch) in ('Mn', 'Me', 'Cf'):
            continue
        cleaned_chars.append(ch)
    norm = ''.join(cleaned_chars).lower()
    norm = norm.translate(_AR_CHAR_MAP).translate(_LATIN_CONFUSABLES_MAP)
    return norm


def _is_arabic_char(ch: str) -> bool:
    return '\u0600' <= ch <= '\u06FF'


def _build_inline_arabic_view(norm: str) -> str:
    chars = list(norm)
    out = []
    n = len(chars)
    for i, ch in enumerate(chars):
        if ch in '0123456789':
            prev_ar = i > 0 and _is_arabic_char(chars[i - 1])
            next_ar = i + 1 < n and _is_arabic_char(chars[i + 1])
            if prev_ar or next_ar:
                out.append(ch.translate(_INLINE_AR_DIGIT_MAP))
                continue
        out.append(ch)
    return ''.join(out)


def _mask_safe_content(norm: str) -> str:
    masked = norm
    for phrase in _SAFE_PHRASES:
        masked = masked.replace(phrase, ' ')
    tokens = re.split(r'\s+', masked)
    kept = []
    for tok in tokens:
        bare = re.sub(r'[^\w\u0600-\u06FF]', '', tok)
        if bare in _SAFE_EXACT_TOKENS:
            kept.append(' ')
        else:
            kept.append(tok)
    return ' '.join(kept)


def _strip_arabic_affixes(word: str) -> set[str]:
    candidates = {word}
    for pref in _AR_PREFIXES:
        if word.startswith(pref) and len(word) - len(pref) >= 2:
            candidates.add(word[len(pref):])
    current = list(candidates)
    for c in current:
        for suf in _AR_SUFFIXES:
            if c.endswith(suf) and len(c) - len(suf) >= 2:
                candidates.add(c[:-len(suf)])
    return candidates


def _damerau_within_one(a: str, b: str) -> bool:
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if a == b:
        return True
    if la == lb:
        diffs = [i for i in range(la) if a[i] != b[i]]
        if len(diffs) == 1:
            return True
        if len(diffs) == 2 and diffs[1] == diffs[0] + 1:
            return a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]]
        return False
    # deletion/insertion by 1
    if la > lb:
        a, b = b, a
        la, lb = lb, la
    i = j = diffs = 0
    while i < la and j < lb:
        if a[i] == b[j]:
            i += 1
            j += 1
        else:
            diffs += 1
            if diffs > 1:
                return False
            j += 1
    return True


_AR_ROOTS_DEDUP1 = {_dedup_n(w, 1) for w in _AR_TOKEN_ROOTS}
_AR_PHONETIC_ROOTS = {
    w.translate(_PHONETIC_AR_MAP)
    for w in (_AR_TOKEN_ROOTS | _AR_ROOTS_DEDUP1)
    if len(w) >= 4
}
_AR_FUZZY_ROOTS = [w for w in (_AR_TOKEN_ROOTS | _AR_ROOTS_DEDUP1) if len(w) >= 5]
_LATIN_ROOTS_DEDUP1 = {_dedup_n(w, 1) for w in _LATIN_TOKEN_ROOTS}
_LATIN_FUZZY_ROOTS = [w for w in (_LATIN_TOKEN_ROOTS | _LATIN_ROOTS_DEDUP1) if len(w) >= 5]


def _merge_single_char_tokens(tokens: list[str]) -> list[str]:
    merged: list[str] = []
    buf: list[str] = []
    for tok in tokens:
        if len(tok) == 1:
            buf.append(tok)
        else:
            if len(buf) >= 2:
                merged.append(''.join(buf))
            elif len(buf) == 1:
                merged.append(buf[0])
            buf.clear()
            merged.append(tok)
    if len(buf) >= 2:
        merged.append(''.join(buf))
    elif len(buf) == 1:
        merged.append(buf[0])
    return merged


def detect_profanity(text: str) -> ProfanityMatch:
    """
    فحص شامل متعدد الطبقات للنص لاكتشاف الألفاظ القبيحة أو الجنسية أو الشتائم بأي شكل تمويه.
    """
    if not text or not str(text).strip():
        return ProfanityMatch(detected=False)

    norm = normalize_unicode_and_decorations(text)
    masked = _mask_safe_content(norm)
    inline_ar = _build_inline_arabic_view(masked)
    latin_leet = re.sub(r'(?<=[a-z0-9])[!|](?=[a-z0-9])', 'i', masked.translate(_LATIN_LEET_MAP))

    views = [
        ('raw', masked),
        ('inline_ar', inline_ar),
        ('latin_leet', latin_leet),
    ]

    for view_name, view_text in views:
        spaced = re.sub(r'[^a-z0-9\u0600-\u06FF]+', ' ', view_text).strip()
        if not spaced:
            continue

        # 1) فحص العبارات المركبة
        for phrase in _AR_BAD_PHRASES:
            if phrase in spaced:
                return ProfanityMatch(True, phrase, 'profanity', f'{view_name}_phrase')

        raw_toks = spaced.split()
        merged_toks = _merge_single_char_tokens(raw_toks)
        all_toks = list(dict.fromkeys(raw_toks + merged_toks))

        # 2) فحص الكلمات والجذور وتكرار الحروف وتجريد اللواصق
        for tok in all_toks:
            if tok in _SAFE_EXACT_TOKENS:
                continue
            forms = {tok, _dedup_n(tok, 2), _dedup_n(tok, 1)}
            expanded: set[str] = set()
            for f in forms:
                expanded.update(_strip_arabic_affixes(f))
                expanded.add(_dedup_n(f, 1))

            for cand in expanded:
                if cand in _SAFE_EXACT_TOKENS:
                    continue
                if cand in _AR_TOKEN_ROOTS or cand in _AR_ROOTS_DEDUP1 or cand in _EXPLICIT_SWAP_VARIANTS:
                    return ProfanityMatch(True, cand, 'profanity', f'{view_name}_exact')
                if cand in _LATIN_TOKEN_ROOTS or cand in _LATIN_ROOTS_DEDUP1:
                    return ProfanityMatch(True, cand, 'profanity', f'{view_name}_latin')

                # 3) فحص التبديل الصوتي/الشكل للحروف (>= 4 أحرف)
                if len(cand) >= 4:
                    phon = cand.translate(_PHONETIC_AR_MAP)
                    phon_d1 = _dedup_n(phon, 1)
                    if phon in _AR_PHONETIC_ROOTS or phon_d1 in _AR_PHONETIC_ROOTS:
                        return ProfanityMatch(True, cand, 'profanity', f'{view_name}_phonetic')

            # 4) فحص تبديل/إبدال/نقص حرف واحد للكلمات الطويلة غير الملتبسة (>= 5 أحرف)
            d1_tok = _dedup_n(tok, 1)
            if len(d1_tok) >= 5 and d1_tok not in _SAFE_EXACT_TOKENS:
                is_ar = any(_is_arabic_char(c) for c in d1_tok)
                pool = _AR_FUZZY_ROOTS if is_ar else _LATIN_FUZZY_ROOTS
                for root in pool:
                    if abs(len(d1_tok) - len(root)) <= 1 and d1_tok[0] == root[0]:
                        if _damerau_within_one(d1_tok, root):
                            return ProfanityMatch(True, root, 'profanity', f'{view_name}_fuzzy')

        # 5) فحص دمج النص بالكامل ضد الفواصل والشُرط والنقاط (شـ*ـر.مـ_ـو.ط)
        ar_only = ''.join(re.findall(r'[\u0600-\u06FF]+', view_text))
        ar_joined_variants = {ar_only, _dedup_n(ar_only, 1)}
        for ar_stream in ar_joined_variants:
            if len(ar_stream) >= 4:
                for sub in _AR_JOINED_UNAMBIGUOUS_SUBSTRINGS:
                    if sub in ar_stream:
                        return ProfanityMatch(True, sub, 'profanity', f'{view_name}_joined_ar')
                ar_phon_stream = ar_stream.translate(_PHONETIC_AR_MAP)
                for sub in _AR_JOINED_UNAMBIGUOUS_SUBSTRINGS:
                    if len(sub) >= 5 and sub.translate(_PHONETIC_AR_MAP) in ar_phon_stream:
                        return ProfanityMatch(True, sub, 'profanity', f'{view_name}_joined_ar_phon')

        lat_only = ''.join(re.findall(r'[a-z0-9]+', view_text))
        for lat_stream in (lat_only, _dedup_n(lat_only, 1)):
            if len(lat_stream) >= 4:
                for sub in _LATIN_JOINED_UNAMBIGUOUS:
                    if sub in lat_stream:
                        return ProfanityMatch(True, sub, 'profanity', f'{view_name}_joined_lat')

    return ProfanityMatch(detected=False)


def handle_chat_profanity_violation(request, user, text: str, source_label: str = 'الشات'):
    """
    يفحص رسالة الشات؛ إن احتوت على لفظ مسيء يُنفّذ حظراً فورياً للحساب والجهاز للطلاب ويُرجع تفاصيل المنع.
    Returns: (violated: bool, payload: dict | None)
    """
    match = detect_profanity(text)
    if not match.detected:
        return False, None

    role = getattr(user, 'role', '') if user is not None else ''
    is_admin = bool(
        user is not None
        and (getattr(user, 'is_superuser', False) or role == 'admin')
    )

    if role == 'student' and not is_admin:
        from api_v1.device_security_service import get_or_create_web_installation_id
        from api_v1.security_engine import enforce_security_ban
        from core.notifications_service import notify_platform_admins

        inst_id = ''
        if request is not None:
            meta = getattr(request, 'META', {}) or {}
            inst_id = str(
                meta.get('HTTP_X_DEVICE_ID')
                or meta.get('HTTP_X_APP_INSTALLATION_ID')
                or meta.get('HTTP_X_INSTALLATION_ID')
                or ''
            ).strip()
            if not inst_id:
                try:
                    inst_id = get_or_create_web_installation_id(request)
                except Exception:
                    inst_id = ''

        reason = f'حظر فوري تلقائي لإرسال ألفاظ غير لائقة في {source_label}.'
        enforce_security_ban(
            user=user,
            installation_id=inst_id,
            mode='device_and_user',
            block_type='permanent',
            reason=reason,
            request=request,
        )
        try:
            display = user.get_full_name() or user.email or user.username
            notify_platform_admins(
                f'حظر تلقائي لطالب بسبب ألفاظ غير لائقة ({source_label})',
                f'تم حظر الطالب {display} وجهازه فورياً بسبب استخدام لفظ مسيء في {source_label}.',
                link='/admin-panel/security/',
                roles=('owner', 'moderator', 'support'),
            )
        except Exception:
            logger.exception('Failed to notify admins about profanity ban')

        return True, {
            'banned': True,
            'is_banned': True,
            'code': 'DEVICE_BLOCKED',
            'error': 'تم حظر حسابك وجهازك نهائياً وبشكل فوري بسبب إرسال ألفاظ غير لائقة.',
        }

    return True, {
        'banned': False,
        'code': 'PROFANITY_BLOCKED',
        'error': 'غير مسموح بإرسال ألفاظ مسيئة أو غير لائقة.',
    }
