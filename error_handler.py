"""
Comprehensive error handling and logging system for Threat Intelligence Pipeline
"""
import logging
import logging.handlers
import json
import traceback
import sys
import os
from datetime import datetime
from typing import Dict, Any, Optional, List, Union, Callable
from enum import Enum
from dataclasses import dataclass, asdict
from pathlib import Path
import threading
from functools import wraps
from config import get_config

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

@dataclass
class ErrorRecord:
    """Structured error record"""
    timestamp: str
    error_id: str
    category: ErrorCategory
    severity: ErrorSeverity
    message: str
    exception_type: str
    exception_message: str
    traceback: str
    context: ErrorContext
    retry_count: int = 0
    resolved: bool = False

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

class APIError(TIPException):
    """API-related errors"""
    def __init__(self, message: str, status_code: Optional[int] = None,
                 context: Optional[ErrorContext] = None):
        super().__init__(message, ErrorCategory.API_ERROR, ErrorSeverity.HIGH, context)
        self.status_code = status_code

class DataValidationError(TIPException):
    """Data validation errors"""
    def __init__(self, message: str, invalid_data: Optional[Dict] = None,
                 context: Optional[ErrorContext] = None):
        super().__init__(message, ErrorCategory.DATA_VALIDATION, ErrorSeverity.MEDIUM, context)
        self.invalid_data = invalid_data

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

class ConfigurationError(TIPException):
    """Configuration-related errors"""
    def __init__(self, message: str, config_key: Optional[str] = None,
                 context: Optional[ErrorContext] = None):
        super().__init__(message, ErrorCategory.CONFIGURATION, ErrorSeverity.CRITICAL, context)
        self.config_key = config_key

class DatabaseError(TIPException):
    """Database-related errors"""
    def __init__(self, message: str, query: Optional[str] = None,
                 context: Optional[ErrorContext] = None):
        super().__init__(message, ErrorCategory.DATABASE_ERROR, ErrorSeverity.HIGH, context)
        self.query = query

class ProcessingError(TIPException):
    """Data processing errors"""
    def __init__(self, message: str, processing_stage: Optional[str] = None,
                 context: Optional[ErrorContext] = None):
        super().__init__(message, ErrorCategory.PROCESSING_ERROR, ErrorSeverity.MEDIUM, context)
        self.processing_stage = processing_stage

class ErrorHandler:
    """Centralized error handling and logging system"""
    
    def __init__(self):
        self.error_records: List[ErrorRecord] = []
        self.error_counts: Dict[str, int] = {}
        self._lock = threading.Lock()
        self.logger = self._setup_logger()
        self.alert_thresholds = {
            ErrorSeverity.CRITICAL: 1,
            ErrorSeverity.HIGH: 5,
            ErrorSeverity.MEDIUM: 20,
            ErrorSeverity.LOW: 50
        }
    
    def _setup_logger(self) -> logging.Logger:
        """Setup structured logger with file rotation"""
        logger = logging.getLogger('cve2capec')
        logger.setLevel(getattr(logging, config.get('logging.level', 'INFO').upper()))
        
        # Clear existing handlers
        logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
        
        # File handler with rotation
        log_file = config.get('logging.file', 'logs/cve2capec.log')
        if log_file:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            
            file_handler = logging.handlers.RotatingFileHandler(
                log_file, maxBytes=10*1024*1024, backupCount=5
            )
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
            )
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
        
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
    
    def handle_error(self, error: Exception, context: Optional[ErrorContext] = None,
                    retry_count: int = 0) -> ErrorRecord:
        """Handle and log an error"""
        with self._lock:
            # Create error record
            error_record = self._create_error_record(error, context, retry_count)
            
            # Add to records
            self.error_records.append(error_record)
            
            # Update error counts
            error_key = f"{error_record.category.value}_{error_record.severity.value}"
            self.error_counts[error_key] = self.error_counts.get(error_key, 0) + 1
            
            # Log the error
            self._log_error(error_record)
            
            # Check for alerts
            self._check_alerts(error_record)
            
            return error_record
    
    def _create_error_record(self, error: Exception, context: Optional[ErrorContext],
                           retry_count: int) -> ErrorRecord:
        """Create structured error record"""
        # Determine category and severity
        if isinstance(error, TIPException):
            category = error.category
            severity = error.severity
        else:
            category = self._classify_error(error)
            severity = self._determine_severity(error)
        
        # Generate unique error ID
        error_id = f"{category.value}_{int(datetime.now().timestamp())}"
        
        return ErrorRecord(
            timestamp=datetime.now().isoformat(),
            error_id=error_id,
            category=category,
            severity=severity,
            message=str(error),
            exception_type=type(error).__name__,
            exception_message=str(error),
            traceback=traceback.format_exc(),
            context=context or ErrorContext(operation="unknown", component="unknown"),
            retry_count=retry_count
        )
    
    def _classify_error(self, error: Exception) -> ErrorCategory:
        """Classify error based on exception type"""
        error_type = type(error).__name__.lower()
        
        if 'request' in error_type or 'http' in error_type or 'connection' in error_type:
            return ErrorCategory.NETWORK_ERROR
        elif 'file' in error_type or 'io' in error_type or 'permission' in error_type:
            return ErrorCategory.FILE_OPERATION
        elif 'json' in error_type or 'decode' in error_type or 'validation' in error_type:
            return ErrorCategory.DATA_VALIDATION
        elif 'config' in error_type or 'setting' in error_type:
            return ErrorCategory.CONFIGURATION
        elif 'database' in error_type or 'sql' in error_type:
            return ErrorCategory.DATABASE_ERROR
        else:
            return ErrorCategory.UNKNOWN
    
    def _determine_severity(self, error: Exception) -> ErrorSeverity:
        """Determine error severity based on exception type"""
        error_type = type(error).__name__.lower()
        
        if any(critical in error_type for critical in ['critical', 'fatal', 'system']):
            return ErrorSeverity.CRITICAL
        elif any(high in error_type for high in ['connection', 'timeout', 'api']):
            return ErrorSeverity.HIGH
        elif any(medium in error_type for medium in ['validation', 'file', 'data']):
            return ErrorSeverity.MEDIUM
        else:
            return ErrorSeverity.LOW
    
    def _log_error(self, error_record: ErrorRecord):
        """Log error with appropriate level"""
        log_message = f"[{error_record.error_id}] {error_record.message}"
        
        if error_record.context.cve_id:
            log_message += f" (CVE: {error_record.context.cve_id})"
        if error_record.context.cwe_id:
            log_message += f" (CWE: {error_record.context.cwe_id})"
        
        # Log with appropriate level
        if error_record.severity == ErrorSeverity.CRITICAL:
            self.logger.critical(log_message, extra={'error_record': asdict(error_record)})
        elif error_record.severity == ErrorSeverity.HIGH:
            self.logger.error(log_message, extra={'error_record': asdict(error_record)})
        elif error_record.severity == ErrorSeverity.MEDIUM:
            self.logger.warning(log_message, extra={'error_record': asdict(error_record)})
        else:
            self.logger.info(log_message, extra={'error_record': asdict(error_record)})
    
    def _check_alerts(self, error_record: ErrorRecord):
        """Check if error thresholds are exceeded and send alerts"""
        error_key = f"{error_record.category.value}_{error_record.severity.value}"
        count = self.error_counts.get(error_key, 0)
        threshold = self.alert_thresholds.get(error_record.severity, 100)
        
        if count >= threshold:
            alert_message = f"ALERT: {count} {error_record.severity.value} {error_record.category.value} errors detected"
            self.logger.critical(alert_message)
            
            # Reset counter after alert
            self.error_counts[error_key] = 0
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get error summary statistics"""
        with self._lock:
            total_errors = len(self.error_records)
            errors_by_category = {}
            errors_by_severity = {}
            
            for record in self.error_records:
                # Count by category
                cat = record.category.value
                errors_by_category[cat] = errors_by_category.get(cat, 0) + 1
                
                # Count by severity
                sev = record.severity.value
                errors_by_severity[sev] = errors_by_severity.get(sev, 0) + 1
            
            return {
                'total_errors': total_errors,
                'errors_by_category': errors_by_category,
                'errors_by_severity': errors_by_severity,
                'recent_errors': [asdict(record) for record in self.error_records[-10:]]
            }
    
    def clear_errors(self):
        """Clear error records (for testing or maintenance)"""
        with self._lock:
            self.error_records.clear()
            self.error_counts.clear()

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

def error_handler(operation: str, component: str, 
                 retry_count: int = 0, 
                 reraise: bool = True):
    """Decorator for error handling"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            context = ErrorContext(
                operation=operation,
                component=component,
                additional_data={'function': func.__name__, 'args_count': len(args)}
            )
            
            try:
                return func(*args, **kwargs)
            except Exception as e:
                error_record = global_error_handler.handle_error(e, context, retry_count)
                
                if reraise:
                    raise
                else:
                    return None
        
        return wrapper
    return decorator

def log_operation(operation: str, component: str):
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

# Global error handler instance
global_error_handler = ErrorHandler()

# Convenience functions
def handle_error(error: Exception, context: Optional[ErrorContext] = None) -> ErrorRecord:
    """Handle an error using the global error handler"""
    return global_error_handler.handle_error(error, context)

def get_logger(name: str = 'cve2capec') -> logging.Logger:
    """Get a logger instance"""
    return global_error_handler.logger.getChild(name)

def log_info(message: str, **kwargs):
    """Log info message"""
    global_error_handler.logger.info(message, extra=kwargs)

def log_warning(message: str, **kwargs):
    """Log warning message"""
    global_error_handler.logger.warning(message, extra=kwargs)

def log_error(message: str, **kwargs):
    """Log error message"""
    global_error_handler.logger.error(message, extra=kwargs)

def log_critical(message: str, **kwargs):
    """Log critical message"""
    global_error_handler.logger.critical(message, extra=kwargs)

def get_error_summary() -> Dict[str, Any]:
    """Get error summary"""
    return global_error_handler.get_error_summary()
