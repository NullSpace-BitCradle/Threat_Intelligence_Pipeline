#!/usr/bin/env python3
"""
Web interface for Threat Intelligence Pipeline
Provides HTTP endpoints for health checks, metrics, and status monitoring
"""
import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading
import logging
from pathlib import Path
from typing import Dict, Any

from tip.monitoring.health_check import get_health_status, health_check_endpoint
from tip.monitoring.metrics import export_metrics, get_metrics_summary
from tip.monitoring.request_tracker import get_request_summary
from tip.core.pipeline_orchestrator import PipelineOrchestrator
from tip.utils.config import get_config

logger = logging.getLogger(__name__)

class TIPRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Threat Intelligence Pipeline web interface"""
    
    def __init__(self, *args, **kwargs):
        self.orchestrator = PipelineOrchestrator()
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query_params = parse_qs(parsed_path.query)
        
        try:
            if path == '/':
                self._handle_root()
            elif path == '/health':
                self._handle_health()
            elif path == '/metrics':
                self._handle_metrics()
            elif path == '/status':
                self._handle_status()
            elif path == '/requests':
                self._handle_requests()
            elif path == '/config':
                self._handle_config()
            elif path == '/api/status':
                self._handle_api_status()
            elif path == '/api/process-cves':
                self._handle_process_cves()
            elif path == '/api/run':
                self._handle_run_pipeline()
            elif path == '/api/update-databases':
                self._handle_update_databases()
            elif path.startswith('/resources/'):
                self._handle_static_file(path)
            elif path.startswith('/database/'):
                self._handle_static_file(path)
            elif path.startswith('/css/') or path.startswith('/js/'):
                self._handle_docs_file(path)
            elif path.startswith('/mitre/'):
                self._handle_mitre_file(path)
            else:
                self._handle_404()
        
        except Exception as e:
            logger.error(f"Error handling request {path}: {e}")
            self._handle_500(str(e))
    
    def do_POST(self):
        """Handle POST requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        try:
            if path == '/api/run':
                self._handle_run_pipeline()
            elif path == '/api/update-databases':
                self._handle_update_databases()
            elif path == '/api/process-cves':
                self._handle_process_cves()
            else:
                self._handle_404()
        
        except Exception as e:
            logger.error(f"Error handling POST request {path}: {e}")
            self._handle_500(str(e))
    
    def _handle_root(self):
        """Handle root path - serve the main HTML page"""
        try:
            # Serve the main HTML page
            html_path = Path(__file__).parent.parent.parent.parent / "docs" / "index.html"
            if html_path.exists():
                with open(html_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                self._send_html_response(content)
            else:
                # Fallback to API documentation if HTML not found
                response = {
                    "name": "Threat Intelligence Pipeline API",
                    "version": "1.0.0",
                    "description": "REST API for Threat Intelligence Pipeline monitoring and control",
                    "endpoints": {
                        "GET /health": "Get system health status",
                        "GET /metrics": "Get Prometheus metrics",
                        "GET /status": "Get pipeline status",
                        "GET /requests": "Get request tracking information",
                        "GET /config": "Get current configuration",
                        "GET /api/status": "Get detailed API status",
                        "POST /api/run": "Run the complete pipeline",
                        "POST /api/update-databases": "Update all databases",
                        "POST /api/process-cves": "Process CVEs only"
                    }
                }
                self._send_json_response(200, response)
        except Exception as e:
            logger.error(f"Error serving HTML page: {e}")
            self._send_error_response(500, f"Error serving page: {str(e)}")
    
    def _handle_health(self):
        """Handle health check endpoint"""
        health_data = health_check_endpoint()
        self._send_json_response(health_data['status_code'], health_data['data'])
    
    def _handle_metrics(self):
        """Handle metrics endpoint"""
        format_type = self._get_query_param('format', 'prometheus')
        
        if format_type == 'json':
            metrics_data = get_metrics_summary()
            self._send_json_response(200, metrics_data)
        else:
            # Return Prometheus format
            metrics_text = export_metrics()
            self._send_text_response(200, metrics_text, 'text/plain')
    
    def _handle_status(self):
        """Handle status endpoint"""
        status = self.orchestrator.get_pipeline_status()
        self._send_json_response(200, status)
    
    def _handle_requests(self):
        """Handle requests tracking endpoint"""
        requests_data = get_request_summary()
        self._send_json_response(200, requests_data)
    
    def _handle_config(self):
        """Handle configuration endpoint"""
        config = get_config()
        config_data = {
            "api": {
                "nvd": {
                    "base_url": config.get('api.nvd.base_url'),
                    "timeout": config.get('api.nvd.timeout'),
                    "retry_limit": config.get('api.nvd.retry_limit')
                }
            },
            "processing": {
                "max_threads": config.get('processing.max_threads'),
                "batch_size": config.get('processing.batch_size')
            },
            "files": {
                "cve_output": config.get('files.cve_output'),
                "database_dir": config.get('files.database_dir')
            }
        }
        self._send_json_response(200, config_data)
    
    def _handle_api_status(self):
        """Handle detailed API status"""
        status = self.orchestrator.get_pipeline_status()
        health = get_health_status()
        metrics = get_metrics_summary()
        requests = get_request_summary()
        
        api_status = {
            "pipeline": status,
            "health": health,
            "metrics_summary": {
                "total_metrics": len(metrics),
                "metric_types": list(set(metric['type'] for metric in metrics.values()))
            },
            "requests": requests,
            "timestamp": time.time()
        }
        
        self._send_json_response(200, api_status)
    
    def _handle_run_pipeline(self):
        """Handle run pipeline request"""
        try:
            # Run pipeline in background thread
            def run_pipeline():
                try:
                    result = self.orchestrator.run_full_pipeline()
                    logger.info("Pipeline completed successfully")
                except Exception as e:
                    logger.error(f"Pipeline failed: {e}")
            
            thread = threading.Thread(target=run_pipeline)
            thread.daemon = True
            thread.start()
            
            response = {
                "message": "Pipeline started",
                "status": "running"
            }
            self._send_json_response(202, response)
        
        except Exception as e:
            self._send_json_response(500, {"error": str(e)})
    
    def _handle_update_databases(self):
        """Handle update databases request"""
        try:
            def update_databases():
                try:
                    result = self.orchestrator.run_database_updates_only()
                    logger.info("Database update completed")
                except Exception as e:
                    logger.error(f"Database update failed: {e}")
            
            thread = threading.Thread(target=update_databases)
            thread.daemon = True
            thread.start()
            
            response = {
                "message": "Database update started",
                "status": "running"
            }
            self._send_json_response(202, response)
        
        except Exception as e:
            self._send_json_response(500, {"error": str(e)})
    
    def _handle_process_cves(self):
        """Handle process CVEs request"""
        try:
            def process_cves():
                try:
                    result = self.orchestrator.run_cve_processing_only()
                    logger.info("CVE processing completed")
                except Exception as e:
                    logger.error(f"CVE processing failed: {e}")
            
            thread = threading.Thread(target=process_cves)
            thread.daemon = True
            thread.start()
            
            response = {
                "message": "CVE processing started",
                "status": "running"
            }
            self._send_json_response(202, response)
        
        except Exception as e:
            self._send_json_response(500, {"error": str(e)})
    
    def _handle_404(self):
        """Handle 404 Not Found"""
        response = {
            "error": "Not Found",
            "message": f"The requested endpoint {self.path} was not found",
            "available_endpoints": [
                "GET /health",
                "GET /metrics",
                "GET /status",
                "GET /requests",
                "GET /config",
                "GET /api/status",
                "POST /api/run",
                "POST /api/update-databases",
                "POST /api/process-cves"
            ]
        }
        self._send_json_response(404, response)
    
    def _handle_500(self, error_message: str):
        """Handle 500 Internal Server Error"""
        response = {
            "error": "Internal Server Error",
            "message": error_message
        }
        self._send_json_response(500, response)
    
    def _send_json_response(self, status_code: int, data: Dict[str, Any]):
        """Send JSON response"""
        response_body = json.dumps(data, indent=2)
        self._send_response(status_code, response_body, 'application/json')
    
    def _send_text_response(self, status_code: int, text: str, content_type: str = 'text/plain'):
        """Send text response"""
        self._send_response(status_code, text, content_type)
    
    def _send_html_response(self, html_content: str):
        """Send HTML response"""
        self._send_response(200, html_content, 'text/html')
    
    def _send_error_response(self, status_code: int, message: str):
        """Send error response"""
        error_response = {
            "error": message,
            "status_code": status_code
        }
        self._send_json_response(status_code, error_response)
    
    def _send_response(self, status_code: int, body: str, content_type: str):
        """Send HTTP response"""
        self.send_response(status_code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body.encode('utf-8'))))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(body.encode('utf-8'))
    
    def _get_query_param(self, param_name: str, default: str = None) -> str:
        """Get query parameter value"""
        parsed_path = urlparse(self.path)
        query_params = parse_qs(parsed_path.query)
        if query_params.get(param_name):
            return query_params.get(param_name, [default])[0]
        return default or ""
    
    def log_message(self, format, *args):
        """Override to use our logger"""
        logger.info(f"{self.address_string()} - {format % args}")
    
    def _handle_process_cves(self):
        """Handle CVE processing endpoint"""
        try:
            # This would need to be implemented to process CVEs
            # For now, return a placeholder response
            response = {
                "message": "CVE processing endpoint",
                "status": "not_implemented",
                "note": "This endpoint needs to be implemented to process CVEs from the web interface"
            }
            self._send_json_response(200, response)
        except Exception as e:
            logger.error(f"Error processing CVEs: {e}")
            self._send_json_response(500, {"error": str(e)})
    
    def _handle_run_pipeline(self):
        """Handle pipeline run endpoint"""
        try:
            # This would need to be implemented to run the pipeline
            # For now, return a placeholder response
            response = {
                "message": "Pipeline run endpoint",
                "status": "not_implemented",
                "note": "This endpoint needs to be implemented to run the pipeline from the web interface"
            }
            self._send_json_response(200, response)
        except Exception as e:
            logger.error(f"Error running pipeline: {e}")
            self._send_json_response(500, {"error": str(e)})
    
    def _handle_update_databases(self):
        """Handle database update endpoint"""
        try:
            # This would need to be implemented to update databases
            # For now, return a placeholder response
            response = {
                "message": "Database update endpoint",
                "status": "not_implemented",
                "note": "This endpoint needs to be implemented to update databases from the web interface"
            }
            self._send_json_response(200, response)
        except Exception as e:
            logger.error(f"Error updating databases: {e}")
            self._send_json_response(500, {"error": str(e)})
    
    def _handle_static_file(self, path: str):
        """Handle static file requests"""
        try:
            # Remove leading slash and construct file path
            file_path = path.lstrip('/')
            full_path = Path(__file__).parent.parent.parent.parent / file_path
            
            # Security check - ensure the file is within our project directory
            project_root = Path(__file__).parent.parent.parent.parent
            if not full_path.resolve().is_relative_to(project_root.resolve()):
                self._send_error_response(403, "Access denied")
                return
            
            if not full_path.exists():
                self._send_error_response(404, f"File not found: {path}")
                return
            
            # Determine content type based on file extension
            content_type = 'application/octet-stream'
            if file_path.endswith('.json'):
                content_type = 'application/json'
            elif file_path.endswith('.jsonl'):
                content_type = 'application/jsonl'
            elif file_path.endswith('.html'):
                content_type = 'text/html'
            elif file_path.endswith('.css'):
                content_type = 'text/css'
            elif file_path.endswith('.js'):
                content_type = 'application/javascript'
            
            # Read and serve the file
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self._send_response(200, content, content_type)
            
        except Exception as e:
            logger.error(f"Error serving static file {path}: {e}")
            self._send_error_response(500, f"Error serving file: {str(e)}")
    
    def _handle_docs_file(self, path: str):
        """Handle docs file requests (CSS, JS, etc.)"""
        try:
            file_path = path.lstrip('/')
            full_path = Path(__file__).parent.parent.parent.parent / "docs" / file_path
            
            # Security check
            project_root = Path(__file__).parent.parent.parent.parent / "docs"
            if not full_path.resolve().is_relative_to(project_root.resolve()):
                self._send_error_response(403, "Access denied")
                return
            
            if not full_path.exists():
                self._send_error_response(404, f"File not found: {path}")
                return
            
            # Determine content type
            content_type = 'application/octet-stream'
            if file_path.endswith('.css'):
                content_type = 'text/css'
            elif file_path.endswith('.js'):
                content_type = 'application/javascript'
            elif file_path.endswith('.html'):
                content_type = 'text/html'
            elif file_path.endswith('.json'):
                content_type = 'application/json'
            
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self._send_response(200, content, content_type)
            
        except Exception as e:
            logger.error(f"Error serving docs file {path}: {e}")
            self._send_error_response(500, f"Error serving file: {str(e)}")
    
    def _handle_mitre_file(self, path: str):
        """Handle MITRE ATT&CK file requests"""
        try:
            file_path = path.lstrip('/')
            full_path = Path(__file__).parent.parent.parent.parent / "docs" / file_path
            
            # Security check
            project_root = Path(__file__).parent.parent.parent.parent / "docs" / "mitre"
            if not full_path.resolve().is_relative_to(project_root.resolve()):
                self._send_error_response(403, "Access denied")
                return
            
            if not full_path.exists():
                self._send_error_response(404, f"File not found: {path}")
                return
            
            # Determine content type
            content_type = 'application/octet-stream'
            if file_path.endswith('.html'):
                content_type = 'text/html'
            elif file_path.endswith('.css'):
                content_type = 'text/css'
            elif file_path.endswith('.js'):
                content_type = 'application/javascript'
            elif file_path.endswith('.json'):
                content_type = 'application/json'
            elif file_path.endswith('.woff') or file_path.endswith('.woff2'):
                content_type = 'font/woff2'
            elif file_path.endswith('.ttf'):
                content_type = 'font/ttf'
            elif file_path.endswith('.svg'):
                content_type = 'image/svg+xml'
            elif file_path.endswith('.png'):
                content_type = 'image/png'
            
            # Read file as binary for binary files, text for text files
            if content_type.startswith('text/') or content_type == 'application/json' or content_type == 'application/javascript':
                with open(full_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            else:
                with open(full_path, 'rb') as f:
                    content = f.read()
            
            self._send_response(200, content, content_type)
            
        except Exception as e:
            logger.error(f"Error serving MITRE file {path}: {e}")
            self._send_error_response(500, f"Error serving file: {str(e)}")

def start_web_interface(host: str = 'localhost', port: int = 8080):
    """Start the web interface server"""
    server_address = (host, port)
    httpd = HTTPServer(server_address, TIPRequestHandler)
    
    logger.info(f"Starting Threat Intelligence Pipeline web interface on http://{host}:{port}")
    logger.info("Available endpoints:")
    logger.info("  GET  /health - Health check")
    logger.info("  GET  /metrics - Prometheus metrics")
    logger.info("  GET  /status - Pipeline status")
    logger.info("  GET  /requests - Request tracking")
    logger.info("  GET  /config - Configuration")
    logger.info("  GET  /api/status - Detailed API status")
    logger.info("  POST /api/run - Run complete pipeline")
    logger.info("  POST /api/update-databases - Update databases")
    logger.info("  POST /api/process-cves - Process CVEs")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down web interface...")
        httpd.shutdown()

def main():
    """Main entry point for web interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Threat Intelligence Pipeline Web Interface')
    parser.add_argument('--host', default='localhost', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind to')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    start_web_interface(args.host, args.port)

if __name__ == "__main__":
    main()
