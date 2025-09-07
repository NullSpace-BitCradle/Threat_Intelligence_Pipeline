#!/usr/bin/env python3
"""
Rate limiting utilities for Threat Intelligence Pipeline
Provides decorators and classes for API rate limiting
"""
import time
import threading
from typing import Dict, Optional, Callable, Any
from functools import wraps
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class RateLimitConfig:
    """Configuration for rate limiting"""
    calls_per_second: float
    burst_size: Optional[int] = None
    window_size: float = 1.0  # seconds

class TokenBucket:
    """Token bucket rate limiter implementation"""
    
    def __init__(self, rate: float, capacity: Optional[int] = None):
        self.rate = rate  # tokens per second
        self.capacity = capacity or int(rate * 2)  # bucket capacity
        self.tokens = float(self.capacity)
        self.last_update = time.time()
        self._lock = threading.Lock()
    
    def acquire(self, tokens: int = 1) -> bool:
        """Try to acquire tokens from the bucket"""
        with self._lock:
            now = time.time()
            # Add tokens based on elapsed time
            elapsed = now - self.last_update
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_update = now
            
            if self.tokens >= float(tokens):
                self.tokens -= float(tokens)
                return True
            return False
    
    def wait_for_tokens(self, tokens: int = 1) -> float:
        """Wait for tokens to become available and return wait time"""
        with self._lock:
            now = time.time()
            elapsed = now - self.last_update
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_update = now
            
            if self.tokens >= float(tokens):
                self.tokens -= float(tokens)
                return 0.0
            
            # Calculate wait time
            needed = float(tokens) - self.tokens
            wait_time = needed / self.rate
            self.tokens = 0.0  # Reserve the tokens
            return wait_time

class SlidingWindowRateLimiter:
    """Sliding window rate limiter implementation"""
    
    def __init__(self, calls_per_second: float, window_size: float = 1.0):
        self.calls_per_second = calls_per_second
        self.window_size = window_size
        self.calls: list = []
        self._lock = threading.Lock()
    
    def acquire(self) -> bool:
        """Try to make a call within rate limit"""
        with self._lock:
            now = time.time()
            # Remove old calls outside the window
            cutoff = now - self.window_size
            self.calls = [call_time for call_time in self.calls if call_time > cutoff]
            
            # Check if we can make another call
            if len(self.calls) < self.calls_per_second * self.window_size:
                self.calls.append(now)
                return True
            return False
    
    def wait_time(self) -> float:
        """Calculate wait time until next call is allowed"""
        with self._lock:
            if not self.calls:
                return 0.0
            
            # Find the oldest call in the window
            now = time.time()
            cutoff = now - self.window_size
            valid_calls = [call_time for call_time in self.calls if call_time > cutoff]
            
            if len(valid_calls) < self.calls_per_second * self.window_size:
                return 0.0
            
            # Calculate when the oldest call will expire
            oldest_call = min(valid_calls)
            return (oldest_call + self.window_size) - now

class RateLimiterManager:
    """Centralized rate limiter management"""
    
    def __init__(self):
        self.limiters: Dict[str, Any] = {}
        self._lock = threading.Lock()
    
    def get_limiter(self, name: str, config: RateLimitConfig) -> Any:
        """Get or create a rate limiter"""
        with self._lock:
            if name not in self.limiters:
                if config.burst_size:
                    self.limiters[name] = TokenBucket(
                        config.calls_per_second, 
                        config.burst_size
                    )
                else:
                    self.limiters[name] = SlidingWindowRateLimiter(
                        config.calls_per_second,
                        config.window_size
                    )
            return self.limiters[name]
    
    def clear_limiter(self, name: str):
        """Clear a specific rate limiter"""
        with self._lock:
            self.limiters.pop(name, None)

# Global rate limiter manager
rate_limiter_manager = RateLimiterManager()

def rate_limit(name: str, calls_per_second: float, burst_size: Optional[int] = None):
    """
    Decorator for rate limiting function calls
    
    Args:
        name: Unique name for the rate limiter
        calls_per_second: Maximum calls per second
        burst_size: Optional burst capacity (uses token bucket if specified)
    
    Example:
        @rate_limit("nvd_api", 10.0, burst_size=20)
        def call_nvd_api():
            # API call here
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            config = RateLimitConfig(calls_per_second, burst_size)
            limiter = rate_limiter_manager.get_limiter(name, config)
            
            # Try to acquire permission
            if hasattr(limiter, 'acquire'):
                if not limiter.acquire():
                    # Wait for permission
                    if hasattr(limiter, 'wait_time'):
                        wait_time = limiter.wait_time()
                        if wait_time > 0:
                            logger.info(f"Rate limit reached for {name}, waiting {wait_time:.2f}s")
                            time.sleep(wait_time)
                    elif hasattr(limiter, 'wait_for_tokens'):
                        wait_time = limiter.wait_for_tokens()
                        if wait_time > 0:
                            logger.info(f"Rate limit reached for {name}, waiting {wait_time:.2f}s")
                            time.sleep(wait_time)
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator

def adaptive_rate_limit(name: str, base_calls_per_second: float, 
                       max_calls_per_second: float = None,
                       backoff_factor: float = 0.5):
    """
    Adaptive rate limiter that adjusts based on API responses
    
    Args:
        name: Unique name for the rate limiter
        base_calls_per_second: Base rate limit
        max_calls_per_second: Maximum rate limit
        backoff_factor: Factor to reduce rate on errors
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get current rate limit
            current_rate = getattr(wrapper, '_current_rate', base_calls_per_second)
            
            # Apply rate limiting
            config = RateLimitConfig(current_rate)
            limiter = rate_limiter_manager.get_limiter(f"{name}_adaptive", config)
            
            if not limiter.acquire():
                wait_time = limiter.wait_time() if hasattr(limiter, 'wait_time') else 0.1
                time.sleep(wait_time)
            
            try:
                result = func(*args, **kwargs)
                # Success - can increase rate slightly
                wrapper._current_rate = min(
                    max_calls_per_second or base_calls_per_second * 2,
                    current_rate * 1.1
                )
                return result
            except Exception as e:
                # Error - reduce rate
                wrapper._current_rate = max(
                    base_calls_per_second * 0.1,
                    current_rate * backoff_factor
                )
                logger.warning(f"Rate limiting {name} due to error: {e}")
                raise
        
        # Store current rate as an attribute
        setattr(wrapper, '_current_rate', base_calls_per_second)
        return wrapper
    return decorator

def get_rate_limiter_stats() -> Dict[str, Any]:
    """Get statistics for all rate limiters"""
    stats = {}
    for name, limiter in rate_limiter_manager.limiters.items():
        if hasattr(limiter, 'tokens'):
            stats[name] = {
                'type': 'token_bucket',
                'tokens': limiter.tokens,
                'capacity': limiter.capacity,
                'rate': limiter.rate
            }
        elif hasattr(limiter, 'calls'):
            stats[name] = {
                'type': 'sliding_window',
                'calls_in_window': len(limiter.calls),
                'calls_per_second': limiter.calls_per_second,
                'window_size': limiter.window_size
            }
    return stats

def clear_all_rate_limiters():
    """Clear all rate limiters (useful for testing)"""
    rate_limiter_manager.limiters.clear()
