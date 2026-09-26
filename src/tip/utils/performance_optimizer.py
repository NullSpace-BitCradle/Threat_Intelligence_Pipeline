"""
Performance timing and caching utilities for Threat Intelligence Pipeline
"""
import time
import logging
import threading
from collections import deque
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, Deque, Dict, Optional
from tip.utils.config import get_config

logger = logging.getLogger(__name__)
config = get_config()

# PerformanceMonitor keeps only the most recent timings so a long run (one
# timer per decorated call) cannot grow memory without bound.
MAX_RECORDED_METRICS = 1000

@dataclass
class PerformanceMetrics:
    """Performance metrics container"""
    start_time: float
    end_time: float
    items_processed: int
    memory_usage: Optional[float] = None
    cache_hits: int = 0
    cache_misses: int = 0
    
    def __post_init__(self):
        """Calculate derived fields after initialization"""
        self.duration = self.end_time - self.start_time
        self.items_per_second = self.items_processed / self.duration if self.duration > 0 else 0

class PerformanceMonitor:
    """Performance monitoring and metrics collection"""
    
    def __init__(self):
        self.metrics: Deque[PerformanceMetrics] = deque(maxlen=MAX_RECORDED_METRICS)
        self.active_operations: Dict[str, float] = {}
        self._lock = threading.Lock()
    
    def start_operation(self, operation_name: str) -> str:
        """Start timing an operation"""
        with self._lock:
            operation_id = f"{operation_name}_{int(time.time() * 1000)}"
            self.active_operations[operation_id] = time.time()
            return operation_id
    
    def end_operation(self, operation_id: str, items_processed: int = 0, 
                     memory_usage: Optional[float] = None,
                     cache_hits: int = 0, cache_misses: int = 0) -> Optional[PerformanceMetrics]:
        """End timing an operation and record metrics"""
        with self._lock:
            if operation_id not in self.active_operations:
                logger.warning(f"Operation {operation_id} not found in active operations")
                return None
            
            start_time = self.active_operations.pop(operation_id)
            end_time = time.time()
            
            metrics = PerformanceMetrics(
                start_time=start_time,
                end_time=end_time,
                items_processed=items_processed,
                memory_usage=memory_usage,
                cache_hits=cache_hits,
                cache_misses=cache_misses
            )
            
            self.metrics.append(metrics)
            return metrics
    
    def get_summary(self) -> Dict[str, Any]:
        """Get performance summary"""
        if not self.metrics:
            return {"message": "No metrics recorded"}
        
        total_duration = sum(m.duration for m in self.metrics)
        total_items = sum(m.items_processed for m in self.metrics)
        avg_items_per_second = sum(m.items_per_second for m in self.metrics) / len(self.metrics)
        
        return {
            "total_operations": len(self.metrics),
            "total_duration": total_duration,
            "total_items_processed": total_items,
            "average_items_per_second": avg_items_per_second,
            "operations": [
                {
                    "duration": m.duration,
                    "items_processed": m.items_processed,
                    "items_per_second": m.items_per_second,
                    "cache_hits": m.cache_hits,
                    "cache_misses": m.cache_misses
                }
                for m in self.metrics
            ]
        }

# Global performance monitor
performance_monitor = PerformanceMonitor()

def performance_timer(operation_name: Optional[str] = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator to time function execution"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            op_name = operation_name or func.__name__
            operation_id = performance_monitor.start_operation(op_name)
            
            try:
                result = func(*args, **kwargs)
                items_processed = len(result) if isinstance(result, (list, dict)) else 1
                performance_monitor.end_operation(operation_id, items_processed)
                return result
            except Exception as e:
                performance_monitor.end_operation(operation_id, 0)
                raise e
        
        return wrapper
    return decorator

class AdvancedCache:
    """Advanced caching system with TTL and size limits"""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 3600):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._lock = threading.RLock()
        self._access_times: Dict[str, float] = {}
    
    def _is_expired(self, key: str) -> bool:
        """Check if cache entry is expired"""
        if key not in self.cache:
            return True
        
        entry = self.cache[key]
        ttl = entry.get('ttl', self.default_ttl)
        created_at = entry.get('created_at', 0)
        
        return bool(time.time() - created_at > ttl)
    
    def _evict_lru(self):
        """Evict least recently used entries"""
        if len(self.cache) < self.max_size:
            return
        
        # Sort by access time and remove oldest
        sorted_keys = sorted(self._access_times.items(), key=lambda x: x[1])
        keys_to_remove = sorted_keys[:len(self.cache) - self.max_size + 1]
        
        for key, _ in keys_to_remove:
            self.cache.pop(key, None)
            self._access_times.pop(key, None)
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        with self._lock:
            if key in self.cache and not self._is_expired(key):
                self._access_times[key] = time.time()
                return self.cache[key]['value']
            
            # Remove expired entry
            if key in self.cache:
                del self.cache[key]
                self._access_times.pop(key, None)
            
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache"""
        with self._lock:
            if len(self.cache) >= self.max_size:
                self._evict_lru()
            
            self.cache[key] = {
                'value': value,
                'created_at': time.time(),
                'ttl': ttl or self.default_ttl
            }
            self._access_times[key] = time.time()
    
    def clear(self):
        """Clear all cache entries"""
        with self._lock:
            self.cache.clear()
            self._access_times.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            return {
                'size': len(self.cache),
                'max_size': self.max_size,
                'hit_rate': getattr(self, '_hit_rate', 0),
                'keys': list(self.cache.keys())
            }

# Global cache instance
global_cache = AdvancedCache(
    max_size=config.get('processing.cache_size', 1000),
    default_ttl=config.get('processing.cache_ttl', 3600)
)

def get_performance_summary() -> Dict[str, Any]:
    """Get comprehensive performance summary"""
    return {
        'monitor': performance_monitor.get_summary(),
        'cache': global_cache.get_stats()
    }

def get_global_cache() -> AdvancedCache:
    """Get the global cache instance"""
    return global_cache
