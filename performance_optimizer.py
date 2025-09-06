"""
Performance optimization utilities for Threat Intelligence Pipeline
"""
import time
import requests  # type: ignore
try:
    import asyncio
    import aiohttp  # type: ignore
    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging
from typing import Dict, Any, List, Optional, Callable, Union
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from functools import wraps, lru_cache
import threading
from dataclasses import dataclass
from queue import Queue, Empty
import json
from config import get_config

logger = logging.getLogger(__name__)
config = get_config()

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
        self.metrics: List[PerformanceMetrics] = []
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

def performance_timer(operation_name: Optional[str] = None):
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

class OptimizedSession:
    """Optimized HTTP session with connection pooling and retry logic"""
    
    def __init__(self, max_retries: int = 3, backoff_factor: float = 0.3,
                 pool_connections: int = 10, pool_maxsize: int = 20):
        self.session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        
        # Configure adapter with connection pooling
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize
        )
        
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set default headers
        self.session.headers.update({
            'User-Agent': 'ThreatIntelligencePipeline/1.0',
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip, deflate'
        })
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """Optimized GET request"""
        return self.session.get(url, **kwargs)
    
    def close(self):
        """Close the session"""
        self.session.close()

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
        
        return time.time() - created_at > ttl
    
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

class OptimizedThreadPool:
    """Optimized thread pool with dynamic sizing and queue management"""
    
    def __init__(self, max_workers: Optional[int] = None, queue_size: int = 1000):
        self.max_workers = max_workers or config.get('processing.max_threads', 10)
        self.queue_size = queue_size
        self.executor = None
        self.task_queue: Queue = Queue(maxsize=queue_size)
        self._lock = threading.Lock()
    
    def __enter__(self):
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.executor:
            self.executor.shutdown(wait=True)
    
    def submit(self, fn: Callable, *args, **kwargs):
        """Submit task to thread pool"""
        if not self.executor:
            raise RuntimeError("Thread pool not initialized. Use as context manager.")
        
        return self.executor.submit(fn, *args, **kwargs)
    
    def map(self, fn: Callable, iterable, chunksize: int = 1):
        """Map function over iterable using thread pool"""
        if not self.executor:
            raise RuntimeError("Thread pool not initialized. Use as context manager.")
        
        return self.executor.map(fn, iterable, chunksize=chunksize)

class BatchProcessor:
    """Efficient batch processing with configurable batch sizes"""
    
    def __init__(self, batch_size: Optional[int] = None, max_workers: Optional[int] = None):
        self.batch_size = batch_size or config.get('processing.batch_size', 1000)
        self.max_workers = max_workers or config.get('processing.max_threads', 10)
    
    def process_batches(self, items: List[Any], process_func: Callable, 
                       use_threading: bool = True) -> List[Any]:
        """Process items in batches"""
        if not items:
            return []
        
        # Create batches
        batches = [items[i:i + self.batch_size] for i in range(0, len(items), self.batch_size)]
        
        if use_threading and len(batches) > 1:
            # Process batches concurrently
            with OptimizedThreadPool(max_workers=self.max_workers) as pool:
                futures = [pool.submit(process_func, batch) for batch in batches]
                results = []
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        results.extend(result if isinstance(result, list) else [result])
                    except Exception as e:
                        logger.error(f"Batch processing error: {e}")
                        continue
                return results
        else:
            # Process batches sequentially
            results = []
            for batch in batches:
                try:
                    result = process_func(batch)
                    results.extend(result if isinstance(result, list) else [result])
                except Exception as e:
                    logger.error(f"Batch processing error: {e}")
                    continue
            return results

class AsyncAPIClient:
    """Asynchronous API client for high-performance requests"""
    
    def __init__(self, max_connections: int = 100, max_keepalive: int = 30):
        if not ASYNC_AVAILABLE:
            raise ImportError("aiohttp is required for AsyncAPIClient. Install with: pip install aiohttp")
        
        self.max_connections = max_connections
        self.max_keepalive = max_keepalive
        self.session = None
        self._connector = None
    
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(
            limit=self.max_connections,
            limit_per_host=30,
            keepalive_timeout=self.max_keepalive,
            enable_cleanup_closed=True
        )
        
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'ThreatIntelligencePipeline/1.0',
                'Accept': 'application/json'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()  # type: ignore
    
    async def get(self, url: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Asynchronous GET request"""
        async with self.session.get(url, params=params) as response:  # type: ignore
            if response.status == 200:
                return await response.json()  # type: ignore
            else:
                raise aiohttp.ClientError(f"HTTP {response.status}: {await response.text()}")  # type: ignore
    
    async def get_multiple(self, urls: List[str], params_list: Optional[List[Dict]] = None) -> List[Dict[str, Any]]:
        """Get multiple URLs concurrently"""
        if params_list is None:
            params_list = [None] * len(urls)
        
        tasks = []
        for url, params in zip(urls, params_list):
            task = self.get(url, params)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        # Filter out exceptions and return only successful results
        return [r for r in results if isinstance(r, dict)]

class PerformanceProfiler:
    """Performance profiler for identifying bottlenecks"""
    
    def __init__(self):
        self.profiles: Dict[str, List[float]] = {}
        self._lock = threading.Lock()
    
    def profile_function(self, func_name: str):
        """Decorator to profile function execution time"""
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    result = func(*args, **kwargs)
                    return result
                finally:
                    execution_time = time.time() - start_time
                    with self._lock:
                        if func_name not in self.profiles:
                            self.profiles[func_name] = []
                        self.profiles[func_name].append(execution_time)
            
            return wrapper
        return decorator
    
    def get_profile_summary(self) -> Dict[str, Dict[str, float]]:
        """Get profiling summary"""
        with self._lock:
            summary = {}
            for func_name, times in self.profiles.items():
                if times:
                    summary[func_name] = {
                        'count': len(times),
                        'total_time': sum(times),
                        'avg_time': sum(times) / len(times),
                        'min_time': min(times),
                        'max_time': max(times)
                    }
            return summary

# Global profiler instance
profiler = PerformanceProfiler()

def optimize_data_structures(data: Union[List, Dict]) -> Union[List, Dict]:
    """Optimize data structures for better performance"""
    if isinstance(data, list):
        # Use set for faster lookups if items are unique
        if len(data) == len(set(data)):
            return list(set(data))  # Remove duplicates and convert back to list
        return data
    elif isinstance(data, dict):
        # Optimize dictionary by removing None values and empty collections
        return {k: v for k, v in data.items() 
                if v is not None and v != [] and v != {}}
    return data

def get_performance_summary() -> Dict[str, Any]:
    """Get comprehensive performance summary"""
    return {
        'monitor': performance_monitor.get_summary(),
        'profiler': profiler.get_profile_summary(),
        'cache': global_cache.get_stats()
    }

# Utility functions for easy integration
def create_optimized_session() -> OptimizedSession:
    """Create an optimized HTTP session"""
    return OptimizedSession()

def get_global_cache() -> AdvancedCache:
    """Get the global cache instance"""
    return global_cache

def get_performance_monitor() -> PerformanceMonitor:
    """Get the global performance monitor"""
    return performance_monitor
