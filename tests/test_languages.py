"""Multi-language catalog: entrypoints, inventory, codemap, sinks, strategies."""

from __future__ import annotations

from pathlib import Path

from vulnforge.languages import (
    SOURCE_EXTS,
    is_entrypoint_name,
    language_for_extension,
    languages_from_extensions,
    summarize_stack,
)
from vulnforge.strategies import list_source_files
from vulnforge.tools.codemap import build_codemap
from vulnforge.tools.grep_index import build_file_index
from vulnforge.tools.sink_preindex import build_sink_preindex


def test_language_for_core_extensions():
    assert language_for_extension(".c") == "c"
    assert language_for_extension("cpp") == "cpp"
    assert language_for_extension(".adb") == "ada"
    assert language_for_extension(".java") == "java"
    assert language_for_extension(".pl") == "perl"
    assert language_for_extension(".f90") == "fortran"
    assert language_for_extension(".cob") == "cobol"


def test_entrypoints_multi_language():
    assert is_entrypoint_name("main.c")
    assert is_entrypoint_name("main.cpp")
    assert is_entrypoint_name("CMakeLists.txt")
    assert is_entrypoint_name("Main.java")
    assert is_entrypoint_name("pom.xml")
    assert is_entrypoint_name("main.adb")
    assert is_entrypoint_name("widget.gpr")  # Ada project suffix
    assert is_entrypoint_name("cpanfile")
    assert is_entrypoint_name("Makefile.PL")
    assert is_entrypoint_name("app.psgi")
    assert is_entrypoint_name("Foo.sln")
    assert is_entrypoint_name("Bar.vcxproj")
    assert not is_entrypoint_name("random_helper.py")


def test_source_exts_cover_requested_langs():
    for ext in (
        ".c",
        ".cpp",
        ".h",
        ".ads",
        ".adb",
        ".java",
        ".pl",
        ".pm",
        ".f90",
        ".cob",
        ".pas",
        ".cs",
        ".go",
        ".rs",
    ):
        assert ext in SOURCE_EXTS, ext


def test_languages_from_extensions_aggregates():
    langs = languages_from_extensions({".c": 3, ".h": 2, ".cpp": 1, ".java": 4})
    assert langs["c"] == 5  # .c + .h
    assert langs["cpp"] == 1
    assert langs["java"] == 4
    stack = summarize_stack({".c": 2, ".adb": 1, ".pl": 3})
    assert stack["has_c_cpp"]
    assert stack["has_ada"]
    assert stack["has_perl"]


def test_inventory_and_codemap_on_polyglot_tree(tmp_path: Path):
    root = tmp_path / "poly"
    (root / "src").mkdir(parents=True)
    (root / "src" / "main.c").write_text(
        '#include "util.h"\nint main(void) { char b[8]; strcpy(b, argv[1]); }\n',
        encoding="utf-8",
    )
    (root / "src" / "util.h").write_text("void util(void);\n", encoding="utf-8")
    (root / "CMakeLists.txt").write_text("project(poly)\n", encoding="utf-8")
    (root / "Ada").mkdir()
    (root / "Ada" / "main.adb").write_text(
        "with Ada.Text_IO;\nprocedure Main is begin null; end Main;\n",
        encoding="utf-8",
    )
    (root / "Ada" / "app.gpr").write_text('project App is end App;\n', encoding="utf-8")
    (root / "java").mkdir()
    (root / "java" / "Main.java").write_text(
        "import java.sql.*;\nclass Main { void q(String s){ Statement st=null; st.execute(s);} }\n",
        encoding="utf-8",
    )
    (root / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    (root / "perl").mkdir()
    (root / "perl" / "app.psgi").write_text(
        "use DBI;\nmy $sth = $dbh->prepare($sql);\n",
        encoding="utf-8",
    )
    (root / "cpanfile").write_text("requires 'DBI';\n", encoding="utf-8")

    inv = build_file_index(root, [])
    assert inv["file_count"] >= 8
    assert "c" in inv["languages"] or "cpp" in inv["languages"]
    assert "ada" in inv["languages"]
    assert "java" in inv["languages"]
    assert "perl" in inv.get("languages") or any(
        p.endswith(".psgi") for p in inv["sample_paths"]
    )
    eps = inv["entrypoints"]
    assert any(p.endswith("main.c") or p == "src/main.c" for p in eps)
    assert any("CMakeLists.txt" in p for p in eps)
    assert any("main.adb" in p for p in eps)
    assert any("pom.xml" in p for p in eps)
    assert any("cpanfile" in p for p in eps)
    assert any(p.endswith(".gpr") or "app.gpr" in p for p in eps)

    cm = build_codemap(root, inv)
    langs = (cm.get("summary") or {}).get("languages") or {}
    assert any(k in langs for k in ("c", "ada", "java", "perl")), langs
    ep_paths = [
        str(e.get("path") or "")
        for e in (cm.get("entrypoints") or [])
        if isinstance(e, dict)
    ]
    assert any("main.c" in p for p in ep_paths)

    sinks = build_sink_preindex(root)
    kinds = {s.get("kind") for s in sinks}
    # strcpy → memory; Statement.execute → sql; DBI → sql-ish/exec patterns
    assert "memory" in kinds or "sql" in kinds, sinks

    sources = list_source_files(root)
    assert any(p.endswith("main.c") for p in sources)
    assert any(p.endswith("Main.java") for p in sources)
    assert any(p.endswith("main.adb") for p in sources)
