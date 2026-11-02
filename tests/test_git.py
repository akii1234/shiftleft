from pathlib import Path
from shiftleft.git import detect_languages, get_changed_files
from unittest.mock import patch


def test_detect_languages_python():
    files = [Path("src/app.py"), Path("src/utils.py")]
    langs = detect_languages(files)
    assert "python" in langs


def test_detect_languages_mixed():
    files = [Path("a.py"), Path("b.js"), Path("c.ts"), Path("d.java")]
    langs = detect_languages(files)
    assert langs == {"python", "javascript", "typescript", "java"}


def test_detect_languages_empty():
    assert detect_languages([]) == set()


def test_get_changed_files_uses_git_diff(tmp_path):
    mock_output = "src/app.py\nsrc/utils.js\n"
    with patch("shiftleft.git.subprocess.run") as mock_run:
        mock_run.return_value.stdout = mock_output
        mock_run.return_value.returncode = 0
        files = get_changed_files(tmp_path)
    assert Path("src/app.py") in files
    assert Path("src/utils.js") in files


def test_get_changed_files_empty_diff(tmp_path):
    with patch("shiftleft.git.subprocess.run") as mock_run:
        mock_run.return_value.stdout = ""
        mock_run.return_value.returncode = 0
        files = get_changed_files(tmp_path)
    assert files == []
