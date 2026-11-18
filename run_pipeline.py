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

from tip.core.pipeline_orchestrator import PipelineOrchestrator, exit_code_for
from tip.utils.error_handler import log_info, log_critical

def main() -> int:
    """Main entry point for Threat Intelligence Pipeline"""
    parser = argparse.ArgumentParser(
        description='Threat Intelligence Pipeline (TIP) - CVE to CAPEC to ATT&CK Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  tip                          # Run complete pipeline (fetches all CVEs from 1999)
  tip --force                 # Force update even if not needed
  tip --cve-only              # Process CVEs only (resumes locally from cve_progress.json)
  tip --cve-only --clear-progress  # Start CVE retrieval from beginning
  tip --db-only               # Update databases only
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
    parser.add_argument('--clear-progress', action='store_true',
                       help='Clear progress file and start CVE retrieval from beginning')
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
                if not db_info.get('exists'):
                    print(f"  [X] {db_name.upper()}: Not found")
                elif 'error' in db_info:
                    print(f"  [ERROR] {db_name.upper()}: unreadable ({db_info['error']})")
                else:
                    print(f"  [OK] {db_name.upper()}: {db_info['entries']} entries (updated: {db_info['last_modified']})")
            
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
        
        session = summary['pipeline_session']
        exit_code = exit_code_for(summary)

        # A skipped run did nothing; say so instead of reporting success.
        if session.get('skipped'):
            print("\n" + "="*60)
            print("THREAT INTELLIGENCE PIPELINE SKIPPED: NOTHING WAS RUN")
            print("="*60)
            print(f"Reason: {session['skipped']}")
            print("="*60)
            return exit_code

        # Print results
        print("\n" + "="*60)
        if exit_code == 0:
            print("THREAT INTELLIGENCE PIPELINE COMPLETED SUCCESSFULLY")
        else:
            print("THREAT INTELLIGENCE PIPELINE DID NOT COMPLETE CLEANLY")
        print("="*60)

        print(f"Total Duration: {session['total_duration']:.2f} seconds")
        print(f"Successful Steps: {session['successful_steps']}")
        print(f"Failed Steps: {session['failed_steps']}")
        print(f"Degraded Steps: {session.get('degraded_steps', 0)}")
        print(f"Partial Steps: {session.get('partial_steps', 0)}")
        print(f"Total Steps: {session['total_steps']}")

        if exit_code != 0:
            print("\nSteps that were not clean:")
            for name, result in summary['results'].items():
                status = result.get('status')
                if status in ('failed', 'degraded', 'partial'):
                    detail = result.get('error') or result.get('reason') or ''
                    if status == 'partial' and 'results' in result:
                        bad = [k for k, ok in result['results'].items() if not ok]
                        detail = f"failed: {', '.join(bad)}"
                    print(f"   - {name} [{status}]: {detail}")

        print(f"\nDetailed summary: results/update_summary.json")
        print("="*60)

        return exit_code
        
    except KeyboardInterrupt:
        print("\n\nPipeline interrupted by user")
        return 130
    except Exception as e:
        log_critical(f"Threat Intelligence Pipeline failed: {e}")
        print(f"\nThreat Intelligence Pipeline failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
