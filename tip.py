#!/usr/bin/env python3
"""
Threat Intelligence Pipeline (TIP) - Main Entry Point
Single command to run the entire threat intelligence pipeline
"""
import sys
import argparse
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from pipeline_orchestrator import PipelineOrchestrator
from database_manager import DatabaseManager
from cve_processor import CVEProcessor
from error_handler import get_logger, log_info, log_critical

def main():
    """Main entry point for Threat Intelligence Pipeline"""
    parser = argparse.ArgumentParser(
        description='Threat Intelligence Pipeline (TIP) - CVE to CAPEC to ATT&CK Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  tip                          # Run complete pipeline
  tip --force                 # Force update even if not needed
  tip --db-only               # Update databases only
  tip --cve-only              # Process CVEs only
  tip --status                # Show pipeline status
  tip --verbose               # Enable verbose logging
        """
    )
    
    parser.add_argument('--force', action='store_true',
                       help='Force update even if not needed')
    parser.add_argument('--db-only', action='store_true',
                       help='Run only database updates')
    parser.add_argument('--cve-only', action='store_true',
                       help='Run only CVE processing')
    parser.add_argument('--status', action='store_true',
                       help='Show pipeline status')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    try:
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
