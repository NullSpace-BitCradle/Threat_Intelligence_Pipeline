"""
Comprehensive error handling and logging system for Threat Intelligence Pipeline
"""
import logging
import logging.handlers
import json
import os
from datetime import datetime
from typing import Dict, Any, Optional, Callable
from enum import Enum
from dataclasses import dataclass
from functools import wraps
from tip.utils.config import get_config

config = get_config()

class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ErrorCategory(Enum):
    """Error categories for better classification"""
    API_ERROR = "api_error"
    DATA_VALIDATION = "data_validation"
    FILE_OPERATION = "file_operation"
    NETWORK_ERROR = "network_error"
    CONFIGURATION = "configuration"
    DATABASE_ERROR = "database_error"
    PROCESSING_ERROR = "processing_error"
    SYSTEM_ERROR = "system_error"
    UNKNOWN = "unknown"

@dataclass
class ErrorContext:
    """Context information for errors"""
    operation: str
    component: str
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    capec_id: Optional[str] = None
    technique_id: Optional[str] = None
    additional_data: Optional[Dict[str, Any]] = None

class TIPException(Exception):
    """Base exception class for Threat Intelligence Pipeline"""
    
    def __init__(self, message: str, category: ErrorCategory = ErrorCategory.UNKNOWN,
                 severity: ErrorSeverity = ErrorSeverity.MEDIUM, 
                 context: Optional[ErrorContext] = None):
        super().__init__(message)
        self.category = category
        self.severity = severity
        self.context = context or ErrorContext(operation="unknown", component="unknown")
        self.timestamp = datetime.now().isoformat()

class FileOperationError(TIPException):
    """File operation errors"""
    def __init__(self, message: str, file_path: Optional[str] = None,
                 context: Optional[ErrorContext] = None):
        super().__init__(message, ErrorCategory.FILE_OPERATION, ErrorSeverity.MEDIUM, context)
        self.file_path = file_path

class NetworkError(TIPException):
    """Network-related errors"""
    def __init__(self, message: str, url: Optional[str] = None,
                 context: Optional[ErrorContext] = None):
        super().__init__(message, ErrorCategory.NETWORK_ERROR, ErrorSeverity.HIGH, context)
        self.url = url

class NVDUnavailableError(NetworkError):
    """NVD upstream was unreachable/too slow and the retry budget was exhausted.

    Raised (instead of silently returning an empty list) so callers can tell an
    NVD brownout apart from a genuine "no new CVEs" result. ``partial_count`` is
    how many CVEs were collected this run before giving up; ``last_index`` is the
    pagination cursor (resume is handled by the progress file, not this object).
    """
    def __init__(self, message: str, url: Optional[str] = None,
                 partial_count: int = 0, last_index: int = 0,
                 context: Optional[ErrorContext] = None):
        super().__init__(message, url=url, context=context)
        self.partial_count = partial_count
        self.last_index = last_index

class ProcessingError(TIPException):
    """Data processing errors"""
    def __init__(self, message: str, processing_stage: Optional[str] = None,
                 context: Optional[ErrorContext] = None):
        super().__init__(message, ErrorCategory.PROCESSING_ERROR, ErrorSeverity.MEDIUM, context)
        self.processing_stage = processing_stage

class ErrorHandler:
    """Centralized error handling and logging system"""
    
    def __init__(self):
        self.logger = self._setup_logger()
    
    def _setup_logger(self) -> logging.Logger:
        """Setup the 'cve2capec' logger.

        Console and logging.file output are owned by the root handlers that
        Config.setup_logging installs; this logger propagates to them. It only
        adds its own JSON handler, which writes a different file.
        """
        config.setup_logging()

        logger = logging.getLogger('cve2capec')
        logger.setLevel(getattr(logging, config.get('logging.level', 'INFO').upper()))
        logger.propagate = True
        
        # Clear existing handlers
        logger.handlers.clear()
        
        # JSON handler for structured logging
        json_log_file = config.get('logging.json_file', 'logs/cve2capec_errors.json')
        if json_log_file:
            os.makedirs(os.path.dirname(json_log_file), exist_ok=True)
            
            json_handler = logging.handlers.RotatingFileHandler(
                json_log_file, maxBytes=10*1024*1024, backupCount=5
            )
            json_handler.setFormatter(JsonFormatter())
            logger.addHandler(json_handler)
        
        return logger

class JsonFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    
    def format(self, record):
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add error record if present
        if hasattr(record, 'error_record'):
            log_entry['error_record'] = record.error_record
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': self.formatException(record.exc_info)
            }
        
        return json.dumps(log_entry, default=str)

def log_operation(operation: str, component: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator for operation logging"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger = global_error_handler.logger
            logger.info(f"Starting {operation} in {component}")
            
            start_time = datetime.now()
            try:
                result = func(*args, **kwargs)
                duration = (datetime.now() - start_time).total_seconds()
                logger.info(f"Completed {operation} in {component} in {duration:.2f}s")
                return result
            except Exception as e:
                duration = (datetime.now() - start_time).total_seconds()
                logger.error(f"Failed {operation} in {component} after {duration:.2f}s: {e}")
                raise
        
        return wrapper
    return decorator

def create_api_context(operation: str, url: Optional[str] = None) -> ErrorContext:
    """Create error context for API operations"""
    return ErrorContext(
        operation=operation,
        component="api",
        additional_data={"url": url} if url else None
    )

def create_data_context(operation: str, cve_id: Optional[str] = None,
                        cwe_id: Optional[str] = None) -> ErrorContext:
    """Create error context for data processing operations"""
    return ErrorContext(
        operation=operation,
        component="data_processing",
        cve_id=cve_id,
        cwe_id=cwe_id
    )

# Global error handler instance
global_error_handler = ErrorHandler()

# Convenience functions
def get_logger(name: str = 'cve2capec') -> logging.Logger:
    """Get a logger instance"""
    return global_error_handler.logger.getChild(name)

def log_info(message: str, **kwargs: Any) -> None:
    """Log info message"""
    global_error_handler.logger.info(message, extra=kwargs)

def log_warning(message: str, **kwargs: Any) -> None:
    """Log warning message"""
    global_error_handler.logger.warning(message, extra=kwargs)

def log_error(message: str, **kwargs: Any) -> None:
    """Log error message"""
    global_error_handler.logger.error(message, extra=kwargs)

def log_critical(message: str, **kwargs: Any) -> None:
    """Log critical message"""
    global_error_handler.logger.critical(message, extra=kwargs)
