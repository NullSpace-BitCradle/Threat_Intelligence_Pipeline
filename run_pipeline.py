#!/usr/bin/env python3
"""
Threat Intelligence Pipeline (TIP) - Main Entry Point
Single command to run the entire threat intelligence pipeline
"""
import sys
import argparse
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from tip.core.pipeline_orchestrator import PipelineOrchestrator
from tip.core.database_manager import DatabaseManager
from tip.core.cve_processor import CVEProcessor
from tip.utils.error_handler import get_logger, log_info, log_critical
from tip.monitoring.health_check import get_health_status, is_healthy
from tip.monitoring.metrics import get_pipeline_metrics
from tip.monitoring.request_tracker import get_request_summary

def main():
    """Main entry point for Threat Intelligence Pipeline"""
    parser = argparse.ArgumentParser(
        description='Threat Intelligence Pipeline (TIP) - CVE to CAPEC to ATT&CK Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  tip                          # Run complete pipeline (fetches all CVEs from 1999)
  tip --force                 # Force update even if not needed
  tip --cve-only              # Process CVEs only (with resume capability)
  tip --cve-only --clear-progress  # Start CVE retrieval from beginning
  tip --db-only               # Update databases only
  tip --status                # Show pipeline status
  tip --verbose               # Enable verbose logging
  tip --health-check          # Run health check
  tip --metrics               # Show metrics
  tip --web-interface         # Start web interface
  tip --web-interface --web-port 9000  # Start web interface on port 9000
        """
    )
    
    parser.add_argument('--force', action='store_true',
                       help='Force update even if not needed')
    parser.add_argument('--db-only', action='store_true',
                       help='Run only database updates')
    parser.add_argument('--cve-only', action='store_true',
                       help='Run only CVE processing')
    parser.add_argument('--clear-progress', action='store_true',
                       help='Clear progress file and start CVE retrieval from beginning')
    parser.add_argument('--status', action='store_true',
                       help='Show pipeline status')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--web-interface', action='store_true',
                       help='Start web interface instead of running pipeline')
    parser.add_argument('--web-host', default='localhost',
                       help='Host for web interface (default: localhost)')
    parser.add_argument('--web-port', type=int, default=8080,
                       help='Port for web interface (default: 8080)')
    parser.add_argument('--health-check', action='store_true',
                       help='Run health check and exit')
    parser.add_argument('--metrics', action='store_true',
                       help='Show metrics and exit')
    
    args = parser.parse_args()
    
    try:
        # Handle special commands first
        if args.health_check:
            health_status = get_health_status()
            print("Health Check Results:")
            print("=" * 40)
            print(f"Status: {health_status['status']}")
            print(f"Uptime: {health_status['uptime']:.1f} seconds")
            print(f"Version: {health_status['version']}")
            
            if health_status['status'] != 'healthy':
                print("\nIssues found:")
                for check_name, check_data in health_status['checks'].items():
                    if check_data['status'] != 'healthy':
                        print(f"  - {check_name}: {check_data['message']}")
            
            return 0 if health_status['status'] == 'healthy' else 1
        
        if args.metrics:
            metrics = get_pipeline_metrics()
            print("Pipeline Metrics:")
            print("=" * 40)
            for metric_name, metric in metrics.items():
                print(f"{metric_name}: {metric}")
            return 0
        
        if args.web_interface:
            from tip.monitoring.web_interface import start_web_interface
            start_web_interface(args.web_host, args.web_port)
            return 0
        
        # Create orchestrator
        orchestrator = PipelineOrchestrator()
        
        if args.status:
            status = orchestrator.get_pipeline_status()
            print("Threat Intelligence Pipeline Status:")
            print("=" * 40)
            
            # Database status
            print("\nDatabase Status:")
            db_status = status['database_status']
            for db_name, db_info in db_status.items():
                if db_info.get('exists'):
                    entries = db_info.get('entries', 'Unknown')
                    last_modified = db_info.get('last_modified', 'Unknown')
                    print(f"  [OK] {db_name.upper()}: {entries} entries (updated: {last_modified})")
                else:
                    print(f"  [X] {db_name.upper()}: Not found")
            
            # Last update
            last_update = status.get('last_update')
            if last_update:
                print(f"\nLast Update: {last_update}")
            else:
                print(f"\nLast Update: Never")
            
            # Pipeline ready
            ready = status.get('pipeline_ready', False)
            print(f"\nPipeline Ready: {'Yes' if ready else 'No'}")
            
            return 0
        
        # Clear progress if requested
        if args.clear_progress:
            progress_file = Path("cve_progress.json")
            if progress_file.exists():
                progress_file.unlink()
                log_info("Progress file cleared - will start CVE retrieval from beginning")
            else:
                log_info("No progress file found - already starting from beginning")
        
        # Run pipeline
        if args.db_only:
            log_info("Running database updates only...")
            summary = orchestrator.run_database_updates_only()
        elif args.cve_only:
            log_info("Running CVE processing only...")
            summary = orchestrator.run_cve_processing_only()
        else:
            log_info("Running complete Threat Intelligence Pipeline...")
            summary = orchestrator.run_full_pipeline(force_update=args.force)
        
        # Print results
        print("\n" + "="*60)
        print("THREAT INTELLIGENCE PIPELINE COMPLETED SUCCESSFULLY")
        print("="*60)
        
        session = summary['pipeline_session']
        print(f"Total Duration: {session['total_duration']:.2f} seconds")
        print(f"Successful Steps: {session['successful_steps']}")
        print(f"Failed Steps: {session['failed_steps']}")
        print(f"Total Steps: {session['total_steps']}")
        
        if session['failed_steps'] > 0:
            print(f"\nSome steps failed:")
            for name, result in summary['results'].items():
                if result.get('status') == 'failed':
                    print(f"   - {name}: {result.get('error', 'Unknown error')}")
        
        print(f"\nDetailed summary: results/update_summary.json")
        print("="*60)
        
        return 0 if session['failed_steps'] == 0 else 1
        
    except KeyboardInterrupt:
        print("\n\nPipeline interrupted by user")
        return 130
    except Exception as e:
        log_critical(f"Threat Intelligence Pipeline failed: {e}")
        print(f"\nThreat Intelligence Pipeline failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
