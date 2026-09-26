"""ISC-55: one log call writes exactly one line to the log file.

Before the fix, Config.setup_logging() put a FileHandler for logs/tip.log on
the root logger while ErrorHandler put a RotatingFileHandler for the same file
on the propagating 'cve2capec' logger, so every pipeline log line landed twice.
"""
import logging

import pytest

from tip.utils import error_handler as eh
from tip.utils.config import get_config


@pytest.fixture
def isolated_logging(tmp_path):
    """Point logging at tmp files and restore the global logging state after."""
    config = get_config()
    saved_cfg = dict(config.get('logging'))
    root = logging.getLogger()
    tip_logger = logging.getLogger('cve2capec')
    # pytest re-adds its own capture handlers per phase; do not save or restore them.
    saved_root = ([h for h in root.handlers if not type(h).__module__.startswith('_pytest')], root.level)
    saved_tip = (tip_logger.handlers[:], tip_logger.level, tip_logger.propagate)
    saved_eh_logger = eh.global_error_handler.logger

    log_file = tmp_path / "tip.log"
    config.set('logging.file', str(log_file))
    config.set('logging.json_file', str(tmp_path / "tip_errors.json"))

    yield log_file

    for h in root.handlers + tip_logger.handlers:
        if h not in saved_root[0] and h not in saved_tip[0]:
            h.close()
    root.handlers = saved_root[0] + [
        h for h in root.handlers if type(h).__module__.startswith('_pytest')
    ]
    root.level = saved_root[1]
    tip_logger.handlers, tip_logger.level, tip_logger.propagate = saved_tip
    eh.global_error_handler.logger = saved_eh_logger
    config.config['logging'] = saved_cfg


def _configure():
    # Start from a bare root (pytest capture handlers included) so only handlers
    # installed by the code under test can write, and basicConfig is not a no-op.
    logging.getLogger().handlers = []
    logging.getLogger('cve2capec').handlers = []
    get_config().setup_logging()
    eh.global_error_handler.logger = eh.ErrorHandler().logger


def _lines_with(path, marker):
    for h in logging.getLogger().handlers + logging.getLogger('cve2capec').handlers:
        h.flush()
    return [ln for ln in path.read_text(encoding='utf-8').splitlines() if marker in ln]


def test_pipeline_logger_writes_one_line(isolated_logging):
    _configure()
    eh.get_logger('cve_processor').info("isc55-pipeline-marker")
    assert len(_lines_with(isolated_logging, "isc55-pipeline-marker")) == 1


def test_log_info_helper_writes_one_line(isolated_logging):
    _configure()
    eh.log_info("isc55-helper-marker")
    assert len(_lines_with(isolated_logging, "isc55-helper-marker")) == 1


def test_module_logger_writes_one_line(isolated_logging):
    _configure()
    logging.getLogger('tip.core.owasp_processor').info("isc55-module-marker")
    assert len(_lines_with(isolated_logging, "isc55-module-marker")) == 1


def test_repeated_setup_does_not_duplicate(isolated_logging):
    _configure()
    get_config().setup_logging()
    eh.global_error_handler.logger = eh.ErrorHandler().logger
    get_config().setup_logging()
    eh.get_logger('x').warning("isc55-repeat-marker")
    assert len(_lines_with(isolated_logging, "isc55-repeat-marker")) == 1
