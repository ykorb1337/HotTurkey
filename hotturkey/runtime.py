"""Resolve the interpreter shipped with an application without a host-Python fallback."""
from pathlib import Path


def application_python(app):
    resources=Path(app)/'Contents/Resources'
    value=(resources/'python-path.txt').read_text().strip()
    if not value:raise ValueError('应用缺少运行时配置')
    path=Path(value)
    if not path.is_absolute():
        path=resources/path
        try:path.resolve().relative_to(resources.resolve())
        except ValueError:raise ValueError('应用运行时路径越界') from None
    if not path.is_file():raise ValueError('应用内置运行时不存在，请重新构建')
    return path.absolute()
