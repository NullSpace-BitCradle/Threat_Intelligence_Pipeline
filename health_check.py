#!/usr/bin/env python3
"""
Health check utilities for Threat Intelligence Pipeline
Provides health monitoring and status reporting
"""
import os
import json
import time
import psutil
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from pathlib import Path
from dataclasses import dataclass, asdict

from config import get_config
from database_manager import DatabaseManager
from error_handler import get_error_summary

logger = logging.getLogger(__name__)

@dataclass
class HealthStatus:
    """Health status information"""
    status: str  # "healthy", "degraded", "unhealthy"
    timestamp: str
    uptime: float
    version: str
    checks: Dict[str, Any]
    metrics: Dict[str, Any]

class HealthChecker:
    """Comprehensive health checking system"""
    
    def __init__(self):
        self.config = get_config()
        self.start_time = time.time()
        self.db_manager = DatabaseManager()
        self.version = "1.0.0"  # Should be read from package info
        
    def get_health_status(self) -> HealthStatus:
        """Get comprehensive health status"""
        checks = self._run_health_checks()
        metrics = self._get_system_metrics()
        
        # Determine overall status
        overall_status = self._determine_overall_status(checks)
        
        return HealthStatus(
            status=overall_status,
            timestamp=datetime.now().isoformat(),
            uptime=time.time() - self.start_time,
            version=self.version,
            checks=checks,
            metrics=metrics
        )
    
    def _run_health_checks(self) -> Dict[str, Any]:
        """Run all health checks"""
        checks = {}
        
        # Database health
        checks["database"] = self._check_database_health()
        
        # File system health
        checks["filesystem"] = self._check_filesystem_health()
        
        # API connectivity
        checks["api_connectivity"] = self._check_api_connectivity()
        
        # Memory usage
        checks["memory"] = self._check_memory_usage()
        
        # Disk space
        checks["disk_space"] = self._check_disk_space()
        
        # Error rates
        checks["error_rates"] = self._check_error_rates()
        
        # Configuration validity
        checks["configuration"] = self._check_configuration()
        
        return checks
    
    def _check_database_health(self) -> Dict[str, Any]:
        """Check database health"""
        try:
            db_status = self.db_manager.get_database_status()
            
            # Check if all required databases exist
            required_dbs = ['capec', 'cwe', 'techniques']
            missing_dbs = [db for db in required_dbs if not db_status.get(db, {}).get('exists', False)]
            
            if missing_dbs:
                return {
                    "status": "unhealthy",
                    "message": f"Missing databases: {', '.join(missing_dbs)}",
                    "details": db_status
                }
            
            # Check database sizes
            total_entries = sum(
                db_info.get('entries', 0) 
                for db_info in db_status.values() 
                if isinstance(db_info.get('entries'), int)
            )
            
            if total_entries == 0:
                return {
                    "status": "degraded",
                    "message": "Databases exist but contain no data",
                    "details": db_status
                }
            
            return {
                "status": "healthy",
                "message": f"All databases healthy with {total_entries} total entries",
                "details": db_status
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "message": f"Database check failed: {str(e)}",
                "details": {}
            }
    
    def _check_filesystem_health(self) -> Dict[str, Any]:
        """Check file system health"""
        try:
            required_dirs = ['logs', 'database', 'resources', 'results']
            missing_dirs = []
            inaccessible_dirs = []
            
            for dir_name in required_dirs:
                dir_path = Path(dir_name)
                if not dir_path.exists():
                    missing_dirs.append(dir_name)
                elif not os.access(dir_path, os.R_OK | os.W_OK):
                    inaccessible_dirs.append(dir_name)
            
            if missing_dirs or inaccessible_dirs:
                return {
                    "status": "unhealthy",
                    "message": f"Missing: {missing_dirs}, Inaccessible: {inaccessible_dirs}",
                    "details": {
                        "missing_dirs": missing_dirs,
                        "inaccessible_dirs": inaccessible_dirs
                    }
                }
            
            return {
                "status": "healthy",
                "message": "All required directories accessible",
                "details": {"required_dirs": required_dirs}
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "message": f"Filesystem check failed: {str(e)}",
                "details": {}
            }
    
    def _check_api_connectivity(self) -> Dict[str, Any]:
        """Check API connectivity"""
        try:
            import requests
            
            # Check NVD API
            nvd_url = self.config.get('api.nvd.base_url')
            if nvd_url:
                try:
                    response = requests.get(nvd_url, timeout=5)
                    nvd_status = "healthy" if response.status_code == 200 else "degraded"
                    nvd_message = f"NVD API responded with status {response.status_code}"
                except Exception as e:
                    nvd_status = "unhealthy"
                    nvd_message = f"NVD API unreachable: {str(e)}"
            else:
                nvd_status = "unknown"
                nvd_message = "NVD API URL not configured"
            
            # Check D3FEND API
            d3fend_url = self.config.get('api.d3fend.base_url')
            if d3fend_url:
                try:
                    response = requests.get(d3fend_url, timeout=5)
                    d3fend_status = "healthy" if response.status_code == 200 else "degraded"
                    d3fend_message = f"D3FEND API responded with status {response.status_code}"
                except Exception as e:
                    d3fend_status = "unhealthy"
                    d3fend_message = f"D3FEND API unreachable: {str(e)}"
            else:
                d3fend_status = "unknown"
                d3fend_message = "D3FEND API URL not configured"
            
            # Determine overall API status
            if nvd_status == "unhealthy" or d3fend_status == "unhealthy":
                overall_status = "unhealthy"
            elif nvd_status == "degraded" or d3fend_status == "degraded":
                overall_status = "degraded"
            else:
                overall_status = "healthy"
            
            return {
                "status": overall_status,
                "message": f"NVD: {nvd_status}, D3FEND: {d3fend_status}",
                "details": {
                    "nvd": {"status": nvd_status, "message": nvd_message},
                    "d3fend": {"status": d3fend_status, "message": d3fend_message}
                }
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "message": f"API connectivity check failed: {str(e)}",
                "details": {}
            }
    
    def _check_memory_usage(self) -> Dict[str, Any]:
        """Check memory usage"""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            system_memory = psutil.virtual_memory()
            
            # Memory usage in MB
            process_memory_mb = memory_info.rss / 1024 / 1024
            system_memory_percent = system_memory.percent
            
            # Determine status based on usage
            if system_memory_percent > 90:
                status = "unhealthy"
                message = f"System memory usage critical: {system_memory_percent:.1f}%"
            elif system_memory_percent > 80:
                status = "degraded"
                message = f"System memory usage high: {system_memory_percent:.1f}%"
            else:
                status = "healthy"
                message = f"Memory usage normal: {system_memory_percent:.1f}%"
            
            return {
                "status": status,
                "message": message,
                "details": {
                    "process_memory_mb": round(process_memory_mb, 2),
                    "system_memory_percent": round(system_memory_percent, 2),
                    "available_memory_gb": round(system_memory.available / 1024 / 1024 / 1024, 2)
                }
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "message": f"Memory check failed: {str(e)}",
                "details": {}
            }
    
    def _check_disk_space(self) -> Dict[str, Any]:
        """Check disk space"""
        try:
            # Check current directory disk usage
            disk_usage = psutil.disk_usage('.')
            free_percent = (disk_usage.free / disk_usage.total) * 100
            
            # Determine status
            if free_percent < 5:
                status = "unhealthy"
                message = f"Disk space critical: {free_percent:.1f}% free"
            elif free_percent < 15:
                status = "degraded"
                message = f"Disk space low: {free_percent:.1f}% free"
            else:
                status = "healthy"
                message = f"Disk space adequate: {free_percent:.1f}% free"
            
            return {
                "status": status,
                "message": message,
                "details": {
                    "free_percent": round(free_percent, 2),
                    "free_gb": round(disk_usage.free / 1024 / 1024 / 1024, 2),
                    "total_gb": round(disk_usage.total / 1024 / 1024 / 1024, 2)
                }
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "message": f"Disk space check failed: {str(e)}",
                "details": {}
            }
    
    def _check_error_rates(self) -> Dict[str, Any]:
        """Check error rates"""
        try:
            error_summary = get_error_summary()
            total_errors = error_summary.get('total_errors', 0)
            
            # Get errors by severity
            errors_by_severity = error_summary.get('errors_by_severity', {})
            critical_errors = errors_by_severity.get('critical', 0)
            high_errors = errors_by_severity.get('high', 0)
            
            # Determine status
            if critical_errors > 0:
                status = "unhealthy"
                message = f"Critical errors detected: {critical_errors}"
            elif high_errors > 10:
                status = "degraded"
                message = f"High error count: {high_errors}"
            elif total_errors > 100:
                status = "degraded"
                message = f"Total error count high: {total_errors}"
            else:
                status = "healthy"
                message = f"Error rates normal: {total_errors} total errors"
            
            return {
                "status": status,
                "message": message,
                "details": error_summary
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "message": f"Error rate check failed: {str(e)}",
                "details": {}
            }
    
    def _check_configuration(self) -> Dict[str, Any]:
        """Check configuration validity"""
        try:
            is_valid = self.config.validate()
            
            if is_valid:
                return {
                    "status": "healthy",
                    "message": "Configuration is valid",
                    "details": {}
                }
            else:
                return {
                    "status": "unhealthy",
                    "message": "Configuration validation failed",
                    "details": {}
                }
                
        except Exception as e:
            return {
                "status": "unhealthy",
                "message": f"Configuration check failed: {str(e)}",
                "details": {}
            }
    
    def _get_system_metrics(self) -> Dict[str, Any]:
        """Get system performance metrics"""
        try:
            process = psutil.Process()
            
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory_info = process.memory_info()
            system_memory = psutil.virtual_memory()
            
            # Disk I/O
            disk_io = psutil.disk_io_counters()
            
            # Network I/O
            network_io = psutil.net_io_counters()
            
            return {
                "cpu_percent": round(cpu_percent, 2),
                "process_memory_mb": round(memory_info.rss / 1024 / 1024, 2),
                "system_memory_percent": round(system_memory.percent, 2),
                "disk_read_mb": round(disk_io.read_bytes / 1024 / 1024, 2) if disk_io else 0,
                "disk_write_mb": round(disk_io.write_bytes / 1024 / 1024, 2) if disk_io else 0,
                "network_sent_mb": round(network_io.bytes_sent / 1024 / 1024, 2) if network_io else 0,
                "network_recv_mb": round(network_io.bytes_recv / 1024 / 1024, 2) if network_io else 0
            }
            
        except Exception as e:
            logger.warning(f"Failed to get system metrics: {e}")
            return {}
    
    def _determine_overall_status(self, checks: Dict[str, Any]) -> str:
        """Determine overall health status from individual checks"""
        statuses = [check.get('status', 'unknown') for check in checks.values()]
        
        if 'unhealthy' in statuses:
            return 'unhealthy'
        elif 'degraded' in statuses:
            return 'degraded'
        else:
            return 'healthy'

def get_health_status() -> Dict[str, Any]:
    """Get health status as dictionary"""
    checker = HealthChecker()
    status = checker.get_health_status()
    return asdict(status)

def get_health_summary() -> str:
    """Get a simple health summary string"""
    status = get_health_status()
    return f"Status: {status['status']}, Uptime: {status['uptime']:.1f}s"

def is_healthy() -> bool:
    """Quick health check - returns True if healthy"""
    status = get_health_status()
    return status['status'] == 'healthy'

# Health check endpoint for web interface
def health_check_endpoint() -> Dict[str, Any]:
    """Health check endpoint for HTTP requests"""
    try:
        status = get_health_status()
        
        # Return appropriate HTTP status code
        if status['status'] == 'healthy':
            http_status = 200
        elif status['status'] == 'degraded':
            http_status = 200  # Still operational
        else:
            http_status = 503  # Service unavailable
        
        return {
            'status_code': http_status,
            'data': status
        }
        
    except Exception as e:
        logger.error(f"Health check endpoint failed: {e}")
        return {
            'status_code': 500,
            'data': {
                'status': 'unhealthy',
                'message': f'Health check failed: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }
        }

if __name__ == "__main__":
    # Command line health check
    import argparse
    
    parser = argparse.ArgumentParser(description='Health check for Threat Intelligence Pipeline')
    parser.add_argument('--format', choices=['json', 'summary'], default='summary',
                       help='Output format')
    parser.add_argument('--exit-code', action='store_true',
                       help='Exit with non-zero code if unhealthy')
    
    args = parser.parse_args()
    
    if args.format == 'json':
        print(json.dumps(get_health_status(), indent=2))
    else:
        print(get_health_summary())
    
    if args.exit_code and not is_healthy():
        exit(1)
