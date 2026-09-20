from pathlib import Path
import zipfile
import pytest
from databreaker.engine import clean_file, scan_file
from databreaker.models import CleanMode, NormalizationProfile
from databreaker.security import is_safe_archive_member, safe_filename

def test_safe_filename_and_traversal():
    assert safe_filename('../../evil?.jpg')=='evil_.jpg'
    assert not is_safe_archive_member('../secret.txt')
    assert not is_safe_archive_member('C:/secret.txt')
    assert is_safe_archive_member('folder/file.txt')

def test_archive_traversal_is_reported_and_not_rewritten(tmp_path:Path):
    p=tmp_path/'evil.zip'
    with zipfile.ZipFile(p,'w') as z:z.writestr('../escape.txt',b'x')
    scan=scan_file(p)
    assert any('Unsafe archive path' in w for w in scan.warnings)
    with pytest.raises(ValueError): clean_file(p,tmp_path,CleanMode.SAFE,NormalizationProfile.MINIMAL)
