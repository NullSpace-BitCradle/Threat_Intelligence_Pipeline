"""
Error recovery and retry mechanisms for Threat Intelligence Pipeline
"""
import time
import random
import logging
from typing import Callable, Any, Optional, Dict, List, Union
from functools import wraps
from enum import Enum
from dataclasses import dataclass
from error_handler import (
    ErrorHandler, ErrorContext, ErrorCategory, ErrorSeverity,
    APIError, NetworkError, DatabaseError, ProcessingError,
    global_error_handler
)

logger = logging.getLogger(__name__)

class RetryStrategy(Enum):
    """Retry strategies"""
    FIXED = "fixed"
    EXPONENTIAL = "exponential"
    LINEAR = "linear"
    RANDOM = "random"

@dataclass
class RetryConfig:
    """Retry configuration"""
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    backoff_multiplier: float = 2.0
    jitter: bool = True
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL

class CircuitBreakerState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Circuit is open, failing fast
    HALF_OPEN = "half_open"  # Testing if service is back

@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration"""
    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    expected_exception: type = Exception

class CircuitBreaker:
    """Circuit breaker pattern implementation"""
    
    def __init__(self, config: CircuitBreakerConfig):
        self.config = config
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.last_failure_time = None
        self.logger = logging.getLogger(f"{__name__}.CircuitBreaker")
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection"""
        if self.state == CircuitBreakerState.OPEN:
            if self._should_attempt_reset():
                self.state = CircuitBreakerState.HALF_OPEN
                self.logger.info("Circuit breaker transitioning to HALF_OPEN")
            else:
                raise Exception("Circuit breaker is OPEN - failing fast")
        
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except self.config.expected_exception as e:
            self._on_failure()
            raise e
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset"""
        if self.last_failure_time is None:
            return True
        
        return (time.time() - self.last_failure_time) >= self.config.recovery_timeout
    
    def _on_success(self):
        """Handle successful call"""
        self.failure_count = 0
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.state = CircuitBreakerState.CLOSED
            self.logger.info("Circuit breaker reset to CLOSED")
    
    def _on_failure(self):
        """Handle failed call"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.config.failure_threshold:
            self.state = CircuitBreakerState.OPEN
            self.logger.warning(f"Circuit breaker opened after {self.failure_count} failures")

class RetryManager:
    """Advanced retry management with multiple strategies"""
    
    def __init__(self, config: RetryConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.RetryManager")
    
    def retry(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with retry logic"""
        last_exception = None
        
        for attempt in range(1, self.config.max_attempts + 1):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                
                if attempt == self.config.max_attempts:
                    self.logger.error(f"All {self.config.max_attempts} attempts failed")
                    break
                
                delay = self._calculate_delay(attempt)
                self.logger.warning(f"Attempt {attempt} failed: {e}. Retrying in {delay:.2f}s...")
                time.sleep(delay)
        
        raise last_exception
    
    def _calculate_delay(self, attempt: int) -> float:
        """Calculate delay based on retry strategy"""
        if self.config.strategy == RetryStrategy.FIXED:
            delay = self.config.base_delay
        elif self.config.strategy == RetryStrategy.EXPONENTIAL:
            delay = self.config.base_delay * (self.config.backoff_multiplier ** (attempt - 1))
        elif self.config.strategy == RetryStrategy.LINEAR:
            delay = self.config.base_delay * attempt
        elif self.config.strategy == RetryStrategy.RANDOM:
            delay = random.uniform(0, self.config.base_delay * (2 ** (attempt - 1)))
        else:
            delay = self.config.base_delay
        
        # Apply jitter
        if self.config.jitter:
            jitter_range = delay * 0.1
            delay += random.uniform(-jitter_range, jitter_range)
        
        # Cap at max delay
        return min(delay, self.config.max_delay)

class ErrorRecoveryManager:
    """Centralized error recovery management"""
    
    def __init__(self):
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.retry_managers: Dict[str, RetryManager] = {}
        self.recovery_strategies: Dict[str, Callable] = {}
        self.logger = logging.getLogger(f"{__name__}.ErrorRecoveryManager")
    
    def register_circuit_breaker(self, name: str, config: CircuitBreakerConfig):
        """Register a circuit breaker"""
        self.circuit_breakers[name] = CircuitBreaker(config)
        self.logger.info(f"Registered circuit breaker: {name}")
    
    def register_retry_manager(self, name: str, config: RetryConfig):
        """Register a retry manager"""
        self.retry_managers[name] = RetryManager(config)
        self.logger.info(f"Registered retry manager: {name}")
    
    def register_recovery_strategy(self, name: str, strategy: Callable):
        """Register a recovery strategy"""
        self.recovery_strategies[name] = strategy
        self.logger.info(f"Registered recovery strategy: {name}")
    
    def execute_with_recovery(self, func: Callable, operation_name: str,
                            context: Optional[ErrorContext] = None,
                            use_circuit_breaker: bool = True,
                            use_retry: bool = True,
                            recovery_strategy: Optional[str] = None) -> Any:
        """Execute function with comprehensive error recovery"""
        
        # Get circuit breaker and retry manager
        circuit_breaker = self.circuit_breakers.get(operation_name) if use_circuit_breaker else None
        retry_manager = self.retry_managers.get(operation_name) if use_retry else None
        
        try:
            # Execute with circuit breaker
            if circuit_breaker:
                if retry_manager:
                    return circuit_breaker.call(retry_manager.retry, func)
                else:
                    return circuit_breaker.call(func)
            elif retry_manager:
                return retry_manager.retry(func)
            else:
                return func()
                
        except Exception as e:
            # Handle error with recovery strategy
            if recovery_strategy and recovery_strategy in self.recovery_strategies:
                try:
                    self.logger.info(f"Attempting recovery with strategy: {recovery_strategy}")
                    return self.recovery_strategies[recovery_strategy](e, context)
                except Exception as recovery_error:
                    self.logger.error(f"Recovery strategy failed: {recovery_error}")
            
            # Log error and re-raise
            global_error_handler.handle_error(e, context)
            raise

# Global recovery manager
global_recovery_manager = ErrorRecoveryManager()

# Predefined recovery strategies
def api_recovery_strategy(error: Exception, context: Optional[ErrorContext]) -> Any:
    """Recovery strategy for API errors"""
    if isinstance(error, (APIError, NetworkError)):
        logger.warning(f"API recovery: Attempting alternative approach for {context.operation}")
        # Implement alternative API call or fallback data
        return None
    raise error

def data_recovery_strategy(error: Exception, context: Optional[ErrorContext]) -> Any:
    """Recovery strategy for data processing errors"""
    if isinstance(error, ProcessingError):
        logger.warning(f"Data recovery: Skipping problematic data for {context.operation}")
        # Return empty result or skip processing
        return {}
    raise error

def file_recovery_strategy(error: Exception, context: Optional[ErrorContext]) -> Any:
    """Recovery strategy for file operation errors"""
    logger.warning(f"File recovery: Attempting to create missing directories or files")
    # Implement file recovery logic
    return None

# Register default recovery strategies
global_recovery_manager.register_recovery_strategy("api", api_recovery_strategy)
global_recovery_manager.register_recovery_strategy("data", data_recovery_strategy)
global_recovery_manager.register_recovery_strategy("file", file_recovery_strategy)

# Register default circuit breakers
global_recovery_manager.register_circuit_breaker(
    "api_calls",
    CircuitBreakerConfig(
        failure_threshold=5,
        recovery_timeout=60.0,
        expected_exception=APIError
    )
)

global_recovery_manager.register_circuit_breaker(
    "database_operations",
    CircuitBreakerConfig(
        failure_threshold=3,
        recovery_timeout=30.0,
        expected_exception=DatabaseError
    )
)

# Register default retry managers
global_recovery_manager.register_retry_manager(
    "api_calls",
    RetryConfig(
        max_attempts=3,
        base_delay=1.0,
        max_delay=30.0,
        strategy=RetryStrategy.EXPONENTIAL
    )
)

global_recovery_manager.register_retry_manager(
    "file_operations",
    RetryConfig(
        max_attempts=2,
        base_delay=0.5,
        max_delay=10.0,
        strategy=RetryStrategy.FIXED
    )
)

# Decorators for easy integration
def with_retry(operation_name: str, retry_config: Optional[RetryConfig] = None,
              context: Optional[ErrorContext] = None):
    """Decorator for retry functionality"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            if retry_config:
                retry_manager = RetryManager(retry_config)
                return retry_manager.retry(func, *args, **kwargs)
            else:
                return global_recovery_manager.execute_with_recovery(
                    lambda: func(*args, **kwargs),
                    operation_name,
                    context,
                    use_circuit_breaker=False,
                    use_retry=True
                )
        return wrapper
    return decorator

def with_circuit_breaker(operation_name: str, 
                        circuit_breaker_config: Optional[CircuitBreakerConfig] = None,
                        context: Optional[ErrorContext] = None):
    """Decorator for circuit breaker functionality"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            if circuit_breaker_config:
                circuit_breaker = CircuitBreaker(circuit_breaker_config)
                return circuit_breaker.call(func, *args, **kwargs)
            else:
                return global_recovery_manager.execute_with_recovery(
                    lambda: func(*args, **kwargs),
                    operation_name,
                    context,
                    use_circuit_breaker=True,
                    use_retry=False
                )
        return wrapper
    return decorator

def with_recovery(operation_name: str, recovery_strategy: Optional[str] = None,
                 context: Optional[ErrorContext] = None):
    """Decorator for comprehensive error recovery"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            return global_recovery_manager.execute_with_recovery(
                lambda: func(*args, **kwargs),
                operation_name,
                context,
                use_circuit_breaker=True,
                use_retry=True,
                recovery_strategy=recovery_strategy
            )
        return wrapper
    return decorator

# Utility functions
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

def create_file_context(operation: str, file_path: Optional[str] = None) -> ErrorContext:
    """Create error context for file operations"""
    return ErrorContext(
        operation=operation,
        component="file_operations",
        additional_data={"file_path": file_path} if file_path else None
    )
