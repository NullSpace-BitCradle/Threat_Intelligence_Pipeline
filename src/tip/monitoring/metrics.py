#!/usr/bin/env python3
"""
Metrics collection utilities for Threat Intelligence Pipeline
Provides Prometheus-compatible metrics for monitoring
"""
import time
import threading
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from collections import defaultdict, deque
import logging

logger = logging.getLogger(__name__)

@dataclass
class MetricValue:
    """Container for metric values"""
    value: float
    timestamp: float
    labels: Dict[str, str]

class Counter:
    """Counter metric - only increases"""
    
    def __init__(self, name: str, description: str = "", labels: List[str] = None):
        self.name = name
        self.description = description
        self.labels = labels or []
        self._values: Dict[str, float] = defaultdict(float)
        self._lock = threading.Lock()
    
    def inc(self, amount: float = 1.0, **label_values):
        """Increment counter by amount"""
        with self._lock:
            key = self._make_key(label_values)
            self._values[key] += amount
    
    def get(self, **label_values) -> float:
        """Get current counter value"""
        with self._lock:
            key = self._make_key(label_values)
            return self._values[key]
    
    def _make_key(self, label_values: Dict[str, str]) -> str:
        """Create key from label values"""
        if not self.labels:
            return ""
        
        # Ensure all required labels are provided
        for label in self.labels:
            if label not in label_values:
                raise ValueError(f"Missing required label: {label}")
        
        # Create sorted key
        return "|".join(f"{k}={v}" for k, v in sorted(label_values.items()))

class Gauge:
    """Gauge metric - can increase or decrease"""
    
    def __init__(self, name: str, description: str = "", labels: List[str] = None):
        self.name = name
        self.description = description
        self.labels = labels or []
        self._values: Dict[str, float] = defaultdict(float)
        self._lock = threading.Lock()
    
    def set(self, value: float, **label_values):
        """Set gauge value"""
        with self._lock:
            key = self._make_key(label_values)
            self._values[key] = value
    
    def inc(self, amount: float = 1.0, **label_values):
        """Increment gauge by amount"""
        with self._lock:
            key = self._make_key(label_values)
            self._values[key] += amount
    
    def dec(self, amount: float = 1.0, **label_values):
        """Decrement gauge by amount"""
        with self._lock:
            key = self._make_key(label_values)
            self._values[key] -= amount
    
    def get(self, **label_values) -> float:
        """Get current gauge value"""
        with self._lock:
            key = self._make_key(label_values)
            return self._values[key]
    
    def _make_key(self, label_values: Dict[str, str]) -> str:
        """Create key from label values"""
        if not self.labels:
            return ""
        
        for label in self.labels:
            if label not in label_values:
                raise ValueError(f"Missing required label: {label}")
        
        return "|".join(f"{k}={v}" for k, v in sorted(label_values.items()))

class Histogram:
    """Histogram metric for measuring distributions"""
    
    def __init__(self, name: str, description: str = "", 
                 buckets: List[float] = None, labels: List[str] = None):
        self.name = name
        self.description = description
        self.labels = labels or []
        self.buckets = buckets or [0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0, float('inf')]
        self._values: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._lock = threading.Lock()
    
    def observe(self, value: float, **label_values):
        """Observe a value in the histogram"""
        with self._lock:
            key = self._make_key(label_values)
            
            # Increment count
            self._values[key]['_count'] += 1
            
            # Add to sum
            self._values[key]['_sum'] += value
            
            # Update buckets
            for bucket in self.buckets:
                if value <= bucket:
                    bucket_key = f"bucket_{bucket}"
                    self._values[key][bucket_key] += 1
    
    def get(self, **label_values) -> Dict[str, float]:
        """Get histogram values"""
        with self._lock:
            key = self._make_key(label_values)
            return dict(self._values[key])
    
    def _make_key(self, label_values: Dict[str, str]) -> str:
        """Create key from label values"""
        if not self.labels:
            return ""
        
        for label in self.labels:
            if label not in label_values:
                raise ValueError(f"Missing required label: {label}")
        
        return "|".join(f"{k}={v}" for k, v in sorted(label_values.items()))

class Summary:
    """Summary metric for measuring quantiles"""
    
    def __init__(self, name: str, description: str = "", 
                 quantiles: List[float] = None, labels: List[str] = None):
        self.name = name
        self.description = description
        self.labels = labels or []
        self.quantiles = quantiles or [0.5, 0.9, 0.95, 0.99]
        self._values: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()
    
    def observe(self, value: float, **label_values):
        """Observe a value in the summary"""
        with self._lock:
            key = self._make_key(label_values)
            self._values[key].append(value)
            
            # Keep only recent values to prevent memory issues
            if len(self._values[key]) > 10000:
                self._values[key] = self._values[key][-5000:]
    
    def get(self, **label_values) -> Dict[str, float]:
        """Get summary values including quantiles"""
        with self._lock:
            key = self._make_key(label_values)
            values = self._values[key]
            
            if not values:
                return {'count': 0, 'sum': 0}
            
            values_sorted = sorted(values)
            count = len(values)
            total = sum(values)
            
            result = {
                'count': count,
                'sum': total,
                'avg': total / count if count > 0 else 0
            }
            
            # Calculate quantiles
            for q in self.quantiles:
                if count > 0:
                    index = int((q * count) - 1)
                    index = max(0, min(index, count - 1))
                    result[f'quantile_{q}'] = float(values_sorted[index])
            
            return result
    
    def _make_key(self, label_values: Dict[str, str]) -> str:
        """Create key from label values"""
        if not self.labels:
            return ""
        
        for label in self.labels:
            if label not in label_values:
                raise ValueError(f"Missing required label: {label}")
        
        return "|".join(f"{k}={v}" for k, v in sorted(label_values.items()))

class MetricsRegistry:
    """Centralized metrics registry"""
    
    def __init__(self):
        self._metrics: Dict[str, Any] = {}
        self._lock = threading.Lock()
    
    def register_counter(self, name: str, description: str = "", labels: List[str] = None) -> Counter:
        """Register a counter metric"""
        with self._lock:
            if name in self._metrics:
                return self._metrics[name]
            
            counter = Counter(name, description, labels)
            self._metrics[name] = counter
            return counter
    
    def register_gauge(self, name: str, description: str = "", labels: List[str] = None) -> Gauge:
        """Register a gauge metric"""
        with self._lock:
            if name in self._metrics:
                return self._metrics[name]
            
            gauge = Gauge(name, description, labels)
            self._metrics[name] = gauge
            return gauge
    
    def register_histogram(self, name: str, description: str = "", 
                          buckets: List[float] = None, labels: List[str] = None) -> Histogram:
        """Register a histogram metric"""
        with self._lock:
            if name in self._metrics:
                return self._metrics[name]
            
            histogram = Histogram(name, description, buckets, labels)
            self._metrics[name] = histogram
            return histogram
    
    def register_summary(self, name: str, description: str = "", 
                        quantiles: List[float] = None, labels: List[str] = None) -> Summary:
        """Register a summary metric"""
        with self._lock:
            if name in self._metrics:
                return self._metrics[name]
            
            summary = Summary(name, description, quantiles, labels)
            self._metrics[name] = summary
            return summary
    
    def get_metric(self, name: str) -> Optional[Any]:
        """Get a metric by name"""
        with self._lock:
            return self._metrics.get(name)
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get all registered metrics"""
        with self._lock:
            return self._metrics.copy()
    
    def export_prometheus(self) -> str:
        """Export metrics in Prometheus format"""
        lines = []
        
        with self._lock:
            for name, metric in self._metrics.items():
                # Add help line
                if hasattr(metric, 'description') and metric.description:
                    lines.append(f"# HELP {name} {metric.description}")
                
                # Add type line
                metric_type = type(metric).__name__.lower()
                lines.append(f"# TYPE {name} {metric_type}")
                
                # Add metric values
                if isinstance(metric, Counter):
                    for key, value in metric._values.items():
                        if key:
                            labels = key.replace("|", ",")
                            lines.append(f"{name}{{{labels}}} {value}")
                        else:
                            lines.append(f"{name} {value}")
                
                elif isinstance(metric, Gauge):
                    for key, value in metric._values.items():
                        if key:
                            labels = key.replace("|", ",")
                            lines.append(f"{name}{{{labels}}} {value}")
                        else:
                            lines.append(f"{name} {value}")
                
                elif isinstance(metric, Histogram):
                    for key, values in metric._values.items():
                        label_str = f"{{{key.replace('|', ',')}}}" if key else ""
                        
                        for bucket_key, bucket_value in values.items():
                            if bucket_key.startswith('bucket_'):
                                bucket = bucket_key.replace('bucket_', '')
                                if bucket == 'inf':
                                    lines.append(f"{name}_bucket{{le=\"+Inf\"{label_str}}} {bucket_value}")
                                else:
                                    lines.append(f"{name}_bucket{{le=\"{bucket}\"{label_str}}} {bucket_value}")
                            elif bucket_key == '_count':
                                lines.append(f"{name}_count{label_str} {bucket_value}")
                            elif bucket_key == '_sum':
                                lines.append(f"{name}_sum{label_str} {bucket_value}")
                
                elif isinstance(metric, Summary):
                    for key, values in metric._values.items():
                        label_str = f"{{{key.replace('|', ',')}}}" if key else ""
                        # Parse key-value pairs for summary data
                        if key:
                            key_pairs = [item.split('=') for item in key.split('|')]
                            summary_data = metric.get(**{k: v for k, v in key_pairs})
                        else:
                            summary_data = metric.get()
                        
                        for q_name, q_value in summary_data.items():
                            if q_name.startswith('quantile_'):
                                quantile = q_name.replace('quantile_', '')
                                lines.append(f"{name}{{quantile=\"{quantile}\"{label_str}}} {q_value}")
                            else:
                                lines.append(f"{name}_{q_name}{label_str} {q_value}")
        
        return "\n".join(lines)

# Global metrics registry
metrics_registry = MetricsRegistry()

# Predefined metrics for the Threat Intelligence Pipeline
def get_pipeline_metrics():
    """Get predefined metrics for the pipeline"""
    
    # API metrics
    api_requests_total = metrics_registry.register_counter(
        "api_requests_total",
        "Total number of API requests",
        ["api", "method", "status"]
    )
    
    api_request_duration = metrics_registry.register_histogram(
        "api_request_duration_seconds",
        "API request duration in seconds",
        buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0],
        labels=["api", "method"]
    )
    
    # Database metrics
    database_operations_total = metrics_registry.register_counter(
        "database_operations_total",
        "Total number of database operations",
        ["operation", "table", "status"]
    )
    
    database_operation_duration = metrics_registry.register_histogram(
        "database_operation_duration_seconds",
        "Database operation duration in seconds",
        buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0],
        labels=["operation", "table"]
    )
    
    # CVE processing metrics
    cves_processed_total = metrics_registry.register_counter(
        "cves_processed_total",
        "Total number of CVEs processed",
        ["status", "year"]
    )
    
    cve_processing_duration = metrics_registry.register_histogram(
        "cve_processing_duration_seconds",
        "CVE processing duration in seconds",
        buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0],
        labels=["operation"]
    )
    
    # Error metrics
    errors_total = metrics_registry.register_counter(
        "errors_total",
        "Total number of errors",
        ["category", "severity", "component"]
    )
    
    # System metrics
    memory_usage_bytes = metrics_registry.register_gauge(
        "memory_usage_bytes",
        "Memory usage in bytes",
        ["type"]
    )
    
    cache_hits_total = metrics_registry.register_counter(
        "cache_hits_total",
        "Total number of cache hits",
        ["cache_type"]
    )
    
    cache_misses_total = metrics_registry.register_counter(
        "cache_misses_total",
        "Total number of cache misses",
        ["cache_type"]
    )
    
    # Pipeline status
    pipeline_status = metrics_registry.register_gauge(
        "pipeline_status",
        "Pipeline status (1=healthy, 0=unhealthy)",
        ["component"]
    )
    
    return {
        'api_requests_total': api_requests_total,
        'api_request_duration': api_request_duration,
        'database_operations_total': database_operations_total,
        'database_operation_duration': database_operation_duration,
        'cves_processed_total': cves_processed_total,
        'cve_processing_duration': cve_processing_duration,
        'errors_total': errors_total,
        'memory_usage_bytes': memory_usage_bytes,
        'cache_hits_total': cache_hits_total,
        'cache_misses_total': cache_misses_total,
        'pipeline_status': pipeline_status
    }

# Decorators for automatic metrics collection
def track_api_metrics(api_name: str, method: str = "GET"):
    """Decorator to track API metrics"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            status = "success"
            
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                status = "error"
                raise
            finally:
                duration = time.time() - start_time
                
                # Record metrics
                metrics = get_pipeline_metrics()
                metrics['api_requests_total'].inc(1, api=api_name, method=method, status=status)
                metrics['api_request_duration'].observe(duration, api=api_name, method=method)
        
        return wrapper
    return decorator

def track_database_metrics(operation: str, table: str = "unknown"):
    """Decorator to track database metrics"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            status = "success"
            
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                status = "error"
                raise
            finally:
                duration = time.time() - start_time
                
                # Record metrics
                metrics = get_pipeline_metrics()
                metrics['database_operations_total'].inc(1, operation=operation, table=table, status=status)
                metrics['database_operation_duration'].observe(duration, operation=operation, table=table)
        
        return wrapper
    return decorator

def track_cve_processing_metrics(operation: str):
    """Decorator to track CVE processing metrics"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            status = "success"
            
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                status = "error"
                raise
            finally:
                duration = time.time() - start_time
                
                # Record metrics
                metrics = get_pipeline_metrics()
                metrics['cve_processing_duration'].observe(duration, operation=operation)
        
        return wrapper
    return decorator

# Utility functions
def record_error(category: str, severity: str, component: str):
    """Record an error in metrics"""
    metrics = get_pipeline_metrics()
    metrics['errors_total'].inc(1, category=category, severity=severity, component=component)

def record_cache_hit(cache_type: str):
    """Record a cache hit"""
    metrics = get_pipeline_metrics()
    metrics['cache_hits_total'].inc(1, cache_type=cache_type)

def record_cache_miss(cache_type: str):
    """Record a cache miss"""
    metrics = get_pipeline_metrics()
    metrics['cache_misses_total'].inc(1, cache_type=cache_type)

def update_memory_usage(memory_type: str, bytes_used: int):
    """Update memory usage metric"""
    metrics = get_pipeline_metrics()
    metrics['memory_usage_bytes'].set(bytes_used, type=memory_type)

def update_pipeline_status(component: str, is_healthy: bool):
    """Update pipeline status metric"""
    metrics = get_pipeline_metrics()
    metrics['pipeline_status'].set(1 if is_healthy else 0, component=component)

def export_metrics() -> str:
    """Export all metrics in Prometheus format"""
    return metrics_registry.export_prometheus()

def get_metrics_summary() -> Dict[str, Any]:
    """Get a summary of all metrics"""
    summary = {}
    
    for name, metric in metrics_registry.get_all_metrics().items():
        if isinstance(metric, Counter):
            summary[name] = {
                'type': 'counter',
                'values': dict(metric._values)
            }
        elif isinstance(metric, Gauge):
            summary[name] = {
                'type': 'gauge',
                'values': dict(metric._values)
            }
        elif isinstance(metric, Histogram):
            summary[name] = {
                'type': 'histogram',
                'buckets': metric.buckets,
                'values': {k: dict(v) for k, v in metric._values.items()}
            }
        elif isinstance(metric, Summary):
            summary[name] = {
                'type': 'summary',
                'quantiles': metric.quantiles,
                'values': {k: list(v) for k, v in metric._values.items()}
            }
    
    return summary

if __name__ == "__main__":
    # Example usage
    metrics = get_pipeline_metrics()
    
    # Record some metrics
    metrics['api_requests_total'].inc(1, api="nvd", method="GET", status="success")
    metrics['cves_processed_total'].inc(5, status="success", year="2024")
    record_error("api_error", "high", "nvd_client")
    
    # Export metrics
    print("Prometheus Metrics:")
    print(export_metrics())
    
    print("\nMetrics Summary:")
    print(get_metrics_summary())
