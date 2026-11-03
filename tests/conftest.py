"""Shared test setup."""

import gc

import pytest


@pytest.fixture(autouse=True)
def _delete_windows_after_test():
    """Tests open main windows and dialogs and only close them; closed widgets stay alive, and every later
    theme change would re-style all of them. Delete leftover windows after each test.

    Deletion happens right here on the main thread, followed by a garbage collection: windows created
    without a parent are owned by Python, and if one were left for the collector it could be freed later
    on a worker thread (a pull's QThread runs Python code) while Qt still holds events for it."""
    yield
    try:
        import shiboken6
        from PySide6.QtCore import QThread
        from PySide6.QtWidgets import QApplication
    except ImportError:  # PySide6 (or its system libraries) missing: GUI tests are skipped anyway
        return
    app = QApplication.instance()
    if app is None:
        return
    for widget in app.topLevelWidgets():
        if not shiboken6.isValid(widget) or widget.parentWidget() is not None:
            continue
        for thread in widget.findChildren(QThread):  # never delete a running thread
            thread.quit()
            thread.wait(5000)
        widget.close()
        shiboken6.delete(widget)
    gc.collect()
