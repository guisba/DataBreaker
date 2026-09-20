import json
from pathlib import Path

def test_translation_key_parity():
    root=Path(__file__).parents[1]/'databreaker'/'static'/'i18n'
    en=json.loads((root/'en.json').read_text(encoding='utf-8'))
    pt=json.loads((root/'pt-BR.json').read_text(encoding='utf-8'))
    assert en.keys()==pt.keys()
    assert all(str(v).strip() for v in en.values())
    assert all(str(v).strip() for v in pt.values())
