#!/usr/bin/env python3
"""
Request tracking utilities for Threat Intelligence Pipeline
Provides request ID tracking and context management for better debugging
"""
import uuid
import threading
import logging
import time
from typing import Dict, Any, Optional, Callable
from functools import wraps
from contextvars import ContextVar
from dataclasses import dataclass, asdict
from datetime import datetime

# Context variable for request tracking
request_context: ContextVar[Dict[str, Any]] = ContextVar('request_context', default={})

logger = logging.getLogger(__name__)

@dataclass
class RequestInfo:
    """Request information container"""
    request_id: str
    start_time: float
    operation: str
    component: str
    user_agent: Optional[str] = None
    source_ip: Optional[str] = None
    additional_data: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        """Calculate duration after initialization"""
        self.duration = time.time() - self.start_time

class RequestTracker:
    """Centralized request tracking system"""
    
    def __init__(self):
        self.active_requests: Dict[str, RequestInfo] = {}
        self.completed_requests: Dict[str, RequestInfo] = {}
        self._lock = threading.Lock()
        self._max_completed = 1000  # Keep last 1000 requests
    
    def start_request(self, operation: str, component: str, 
                     user_agent: Optional[str] = None,
                     source_ip: Optional[str] = None,
                     additional_data: Optional[Dict[str, Any]] = None) -> str:
        """Start tracking a new request"""
        request_id = str(uuid.uuid4())
        
        request_info = RequestInfo(
            request_id=request_id,
            start_time=time.time(),
            operation=operation,
            component=component,
            user_agent=user_agent,
            source_ip=source_ip,
            additional_data=additional_data or {}
        )
        
        with self._lock:
            self.active_requests[request_id] = request_info
        
        # Set context variable
        request_context.set({
            'request_id': request_id,
            'operation': operation,
            'component': component,
            'start_time': request_info.start_time
        })
        
        logger.debug(f"Started request {request_id}: {operation} in {component}")
        return request_id
    
    def end_request(self, request_id: str, success: bool = True, 
                   error_message: Optional[str] = None) -> Optional[RequestInfo]:
        """End tracking a request"""
        with self._lock:
            if request_id not in self.active_requests:
                logger.warning(f"Request {request_id} not found in active requests")
                return None
            
            request_info = self.active_requests.pop(request_id)
            request_info.duration = time.time() - request_info.start_time
            
            # Add completion info
            request_info.additional_data = request_info.additional_data or {}
            request_info.additional_data.update({
                'success': success,
                'error_message': error_message,
                'end_time': time.time()
            })
            
            # Move to completed requests
            self.completed_requests[request_id] = request_info
            
            # Clean up old completed requests
            if len(self.completed_requests) > self._max_completed:
                oldest_id = min(self.completed_requests.keys(), 
                              key=lambda k: self.completed_requests[k].start_time)
                del self.completed_requests[oldest_id]
        
        status = "SUCCESS" if success else "FAILED"
        logger.debug(f"Ended request {request_id}: {status} in {request_info.duration:.3f}s")
        
        return request_info
    
    def get_request_info(self, request_id: str) -> Optional[RequestInfo]:
        """Get information about a specific request"""
        with self._lock:
            if request_id in self.active_requests:
                return self.active_requests[request_id]
            elif request_id in self.completed_requests:
                return self.completed_requests[request_id]
            return None
    
    def get_active_requests(self) -> Dict[str, RequestInfo]:
        """Get all active requests"""
        with self._lock:
            return self.active_requests.copy()
    
    def get_completed_requests(self, limit: int = 100) -> Dict[str, RequestInfo]:
        """Get recent completed requests"""
        with self._lock:
            # Sort by start time and return most recent
            sorted_requests = sorted(
                self.completed_requests.items(),
                key=lambda x: x[1].start_time,
                reverse=True
            )
            return dict(sorted_requests[:limit])
    
    def get_request_stats(self) -> Dict[str, Any]:
        """Get request statistics"""
        with self._lock:
            active_count = len(self.active_requests)
            completed_count = len(self.completed_requests)
            
            # Calculate success rate
            successful = sum(1 for req in self.completed_requests.values() 
                           if req.additional_data and req.additional_data.get('success', False))
            success_rate = (successful / completed_count * 100) if completed_count > 0 else 0
            
            # Calculate average duration
            durations = [req.duration for req in self.completed_requests.values()]
            avg_duration = sum(durations) / len(durations) if durations else 0
            
            return {
                'active_requests': active_count,
                'completed_requests': completed_count,
                'success_rate': round(success_rate, 2),
                'average_duration': round(avg_duration, 3),
                'total_requests': active_count + completed_count
            }

# Global request tracker
request_tracker = RequestTracker()

def get_current_request_id() -> Optional[str]:
    """Get the current request ID from context"""
    context = request_context.get()
    return context.get('request_id') if context else None

def get_current_request_context() -> Dict[str, Any]:
    """Get the current request context"""
    return request_context.get()

def set_request_context(request_id: str, operation: str, component: str):
    """Set request context manually"""
    request_context.set({
        'request_id': request_id,
        'operation': operation,
        'component': component,
        'start_time': time.time()
    })

def track_request(operation: str, component: str):
    """Decorator for automatic request tracking"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            request_id = request_tracker.start_request(operation, component)
            
            try:
                result = func(*args, **kwargs)
                request_tracker.end_request(request_id, success=True)
                return result
            except Exception as e:
                request_tracker.end_request(request_id, success=False, error_message=str(e))
                raise
        
        return wrapper
    return decorator

def track_async_request(operation: str, component: str):
    """Decorator for tracking async requests"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request_id = request_tracker.start_request(operation, component)
            
            try:
                result = await func(*args, **kwargs)
                request_tracker.end_request(request_id, success=True)
                return result
            except Exception as e:
                request_tracker.end_request(request_id, success=False, error_message=str(e))
                raise
        
        return wrapper
    return decorator

class RequestContextManager:
    """Context manager for request tracking"""
    
    def __init__(self, operation: str, component: str, **kwargs):
        self.operation = operation
        self.component = component
        self.kwargs = kwargs
        self.request_id = None
    
    def __enter__(self):
        self.request_id = request_tracker.start_request(
            self.operation, 
            self.component, 
            **self.kwargs
        )
        return self.request_id
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.request_id:
            success = exc_type is None
            error_message = str(exc_val) if exc_val else None
            request_tracker.end_request(self.request_id, success, error_message)

def create_request_context(operation: str, component: str, **kwargs) -> RequestContextManager:
    """Create a request context manager"""
    return RequestContextManager(operation, component, **kwargs)

def log_with_request_context(message: str, level: int = logging.INFO, **kwargs):
    """Log a message with request context"""
    context = get_current_request_context()
    request_id = context.get('request_id', 'unknown')
    
    # Add request ID to the message
    formatted_message = f"[{request_id}] {message}"
    
    # Add context to extra data
    extra = kwargs.get('extra', {})
    extra.update({
        'request_id': request_id,
        'operation': context.get('operation', 'unknown'),
        'component': context.get('component', 'unknown')
    })
    kwargs['extra'] = extra
    
    logger.log(level, formatted_message, **kwargs)

def get_request_summary() -> Dict[str, Any]:
    """Get a summary of all requests"""
    stats = request_tracker.get_request_stats()
    active_requests = request_tracker.get_active_requests()
    recent_completed = request_tracker.get_completed_requests(10)
    
    return {
        'statistics': stats,
        'active_requests': {k: asdict(v) for k, v in active_requests.items()},
        'recent_completed': {k: asdict(v) for k, v in recent_completed.items()}
    }

# Enhanced logging formatter that includes request context
class RequestAwareFormatter(logging.Formatter):
    """Log formatter that includes request context"""
    
    def format(self, record):
        # Add request context to log record
        context = get_current_request_context()
        if context:
            record.request_id = context.get('request_id', 'N/A')
            record.operation = context.get('operation', 'N/A')
            record.component = context.get('component', 'N/A')
        else:
            record.request_id = 'N/A'
            record.operation = 'N/A'
            record.component = 'N/A'
        
        return super().format(record)

# Convenience functions for common operations
def start_api_request(api_name: str, endpoint: str) -> str:
    """Start tracking an API request"""
    return request_tracker.start_request(
        operation=f"api_call_{api_name}",
        component="api",
        additional_data={"api_name": api_name, "endpoint": endpoint}
    )

def start_database_operation(operation: str, table: str = None) -> str:
    """Start tracking a database operation"""
    return request_tracker.start_request(
        operation=f"db_{operation}",
        component="database",
        additional_data={"table": table}
    )

def start_file_operation(operation: str, file_path: str) -> str:
    """Start tracking a file operation"""
    return request_tracker.start_request(
        operation=f"file_{operation}",
        component="file_operations",
        additional_data={"file_path": file_path}
    )

if __name__ == "__main__":
    # Example usage
    import time
    
    # Example 1: Using decorator
    @track_request("test_operation", "test_component")
    def test_function():
        time.sleep(0.1)
        return "success"
    
    # Example 2: Using context manager
    with create_request_context("manual_operation", "test_component") as req_id:
        time.sleep(0.1)
        print(f"Request ID: {req_id}")
    
    # Example 3: Manual tracking
    req_id = request_tracker.start_request("manual", "test")
    time.sleep(0.1)
    request_tracker.end_request(req_id, success=True)
    
    # Print summary
    print("Request Summary:")
    print(get_request_summary())
