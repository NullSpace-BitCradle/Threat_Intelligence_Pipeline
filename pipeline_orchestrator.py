#!/usr/bin/env python3
"""
Simplified pipeline orchestrator
Combines database updates and CVE processing into a streamlined workflow
"""
import os
import sys
import json
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
import argparse

from config import get_config
from database_manager import DatabaseManager
from cve_processor import CVEProcessor
# CVE retrieval is now handled by CVEProcessor
from error_handler import (
    log_info, log_warning, log_error, log_critical, get_logger,
    ErrorContext, ProcessingError
)
from error_recovery import with_recovery, create_data_context
from performance_optimizer import (
    performance_timer, get_performance_monitor, get_performance_summary
)

config = get_config()
logger = get_logger('pipeline_orchestrator')

class PipelineOrchestrator:
    """Simplified pipeline orchestrator for Threat Intelligence Pipeline"""
    
    def __init__(self):
        self.start_time = datetime.now()
        self.results = {}
        self.config = config
        
        # Initialize components
        self.db_manager = DatabaseManager()
        self.cve_processor = CVEProcessor()
    
    @performance_timer("full_pipeline")
    def run_full_pipeline(self, force_update: bool = False) -> Dict[str, Any]:
        """Run the complete Threat Intelligence Pipeline"""
        
        log_info("Starting Threat Intelligence Pipeline")
        log_info(f"Configuration: force_update={force_update}")
        
        try:
            # Check if updates are needed
            if not force_update and not self._updates_needed():
                log_info("No updates needed - all databases are current")
                return self._create_summary()
            
            # Step 1: Update databases
            log_info("Step 1: Updating databases...")
            db_results = self._update_databases()
            
            # Step 2: Retrieve new CVEs
            log_info("Step 2: Retrieving new CVEs...")
            cve_results = self._retrieve_cves()
            
            # Step 3: Process CVEs through pipeline
            if cve_results.get('success', False):
                log_info("Step 3: Processing CVEs through pipeline...")
                processing_results = self._process_cves()
            else:
                log_info("No new CVEs to process")
                processing_results = {'success': True, 'message': 'No new CVEs'}
            
            # Generate final summary
            summary = self._create_summary()
            log_info("Pipeline completed successfully")
            
            return summary
            
        except Exception as e:
            log_critical(f"Pipeline failed: {e}")
            raise
    
    def _updates_needed(self) -> bool:
        """Check if updates are needed based on last update time"""
        try:
            last_update_file = Path(self.config.get('files.last_update', 'lastUpdate.txt'))
            if not last_update_file.exists():
                log_info("Last update file not found - updates needed")
                return True
            
            with open(last_update_file, 'r') as f:
                last_update_str = f.read().strip()
            
            try:
                last_update = datetime.fromisoformat(last_update_str)
                hours_since_update = (datetime.now() - last_update).total_seconds() / 3600
                
                # Check if more than 24 hours have passed
                if hours_since_update > 24:
                    log_info(f"Last update was {hours_since_update:.1f} hours ago - updates needed")
                    return True
                else:
                    log_info(f"Last update was {hours_since_update:.1f} hours ago - updates not needed")
                    return False
                    
            except ValueError:
                log_warning("Invalid last update timestamp - updates needed")
                return True
                
        except Exception as e:
            log_warning(f"Error checking last update time: {e} - updates needed")
            return True
    
    @with_recovery("database_updates", recovery_strategy="data")
    def _update_databases(self) -> Dict[str, Any]:
        """Update all databases"""
        log_info("Updating databases...")
        
        try:
            start_time = time.time()
            db_results = self.db_manager.update_all_databases()
            duration = time.time() - start_time
            
            # Count successes and failures
            successful = sum(1 for success in db_results.values() if success)
            failed = len(db_results) - successful
            
            self.results['database_updates'] = {
                'status': 'success' if failed == 0 else 'partial',
                'duration': duration,
                'successful': successful,
                'failed': failed,
                'results': db_results,
                'timestamp': datetime.now().isoformat()
            }
            
            log_info(f"Database updates completed: {successful} successful, {failed} failed")
            
            if failed > 0:
                log_warning(f"Some database updates failed: {[k for k, v in db_results.items() if not v]}")
            
            return self.results['database_updates']
            
        except Exception as e:
            error_msg = f"Database updates failed: {e}"
            log_error(error_msg)
            
            self.results['database_updates'] = {
                'status': 'failed',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
            
            raise ProcessingError(error_msg, 
                                processing_stage="database_update",
                                context=create_data_context("database_update"))
    
    @with_recovery("cve_retrieval", recovery_strategy="api")
    def _retrieve_cves(self) -> Dict[str, Any]:
        """Retrieve new CVEs from NVD"""
        log_info("Retrieving new CVEs...")
        
        try:
            start_time = time.time()
            
            # CVE retrieval is now handled by the CVEProcessor
            # For now, we'll assume there are CVEs to process
            # The actual retrieval logic is in the CVEProcessor
            duration = time.time() - start_time
            
            self.results['cve_retrieval'] = {
                'status': 'success',
                'duration': duration,
                'cve_count': 0,  # Will be determined during processing
                'timestamp': datetime.now().isoformat()
            }
            
            log_info("CVE retrieval step completed")
            
            return {
                'success': True,
                'cve_count': 0,
                'data': {}
            }
            
        except Exception as e:
            error_msg = f"CVE retrieval failed: {e}"
            log_error(error_msg)
            
            self.results['cve_retrieval'] = {
                'status': 'failed',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
            
            return {
                'success': False,
                'error': str(e)
            }
    
    @with_recovery("cve_processing", recovery_strategy="data")
    def _process_cves(self) -> Dict[str, Any]:
        """Process CVEs through the pipeline"""
        log_info("Processing CVEs through pipeline...")
        
        try:
            start_time = time.time()
            
            # Process CVEs using the unified processor
            success = self.cve_processor.process_file()
            duration = time.time() - start_time
            
            self.results['cve_processing'] = {
                'status': 'success' if success else 'failed',
                'duration': duration,
                'timestamp': datetime.now().isoformat()
            }
            
            if success:
                log_info("CVE processing completed successfully")
            else:
                log_error("CVE processing failed")
            
            return {
                'success': success,
                'duration': duration
            }
            
        except Exception as e:
            error_msg = f"CVE processing failed: {e}"
            log_error(error_msg)
            
            self.results['cve_processing'] = {
                'status': 'failed',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
            
            return {
                'success': False,
                'error': str(e)
            }
    
    def _create_summary(self) -> Dict[str, Any]:
        """Create comprehensive pipeline summary"""
        total_duration = (datetime.now() - self.start_time).total_seconds()
        
        # Get performance summary
        perf_summary = get_performance_summary()
        
        # Count successes and failures
        successful_steps = sum(1 for r in self.results.values() if r.get('status') == 'success')
        failed_steps = sum(1 for r in self.results.values() if r.get('status') == 'failed')
        
        summary = {
            'pipeline_session': {
                'start_time': self.start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'total_duration': total_duration,
                'successful_steps': successful_steps,
                'failed_steps': failed_steps,
                'total_steps': len(self.results)
            },
            'results': self.results,
            'performance': perf_summary
        }
        
        # Save summary to file
        summary_file = Path('results/update_summary.json')
        summary_file.parent.mkdir(exist_ok=True)
        
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Update last update timestamp
        self._update_last_update_time()
        
        return summary
    
    def _update_last_update_time(self):
        """Update the last update timestamp"""
        try:
            last_update_file = Path(self.config.get('files.last_update', 'lastUpdate.txt'))
            with open(last_update_file, 'w') as f:
                f.write(datetime.now().isoformat())
            log_info(f"Updated last update timestamp in {last_update_file}")
        except Exception as e:
            log_warning(f"Failed to update last update timestamp: {e}")
    
    def run_database_updates_only(self) -> Dict[str, Any]:
        """Run only database updates"""
        log_info("Running database updates only...")
        self._update_databases()
        return self._create_summary()
    
    def run_cve_processing_only(self) -> Dict[str, Any]:
        """Run only CVE processing"""
        log_info("Running CVE processing only...")
        self._process_cves()
        return self._create_summary()
    
    def get_pipeline_status(self) -> Dict[str, Any]:
        """Get current pipeline status"""
        return {
            'database_status': self.db_manager.get_database_status(),
            'last_update': self._get_last_update_time(),
            'pipeline_ready': self._is_pipeline_ready()
        }
    
    def _get_last_update_time(self) -> Optional[str]:
        """Get last update time"""
        try:
            last_update_file = Path(self.config.get('files.last_update', 'lastUpdate.txt'))
            if last_update_file.exists():
                with open(last_update_file, 'r') as f:
                    return f.read().strip()
        except Exception:
            pass
        return None
    
    def _is_pipeline_ready(self) -> bool:
        """Check if pipeline is ready to run"""
        # Check if all required databases exist
        db_status = self.db_manager.get_database_status()
        required_dbs = ['capec', 'cwe', 'techniques']
        
        for db in required_dbs:
            if not db_status.get(db, {}).get('exists', False):
                return False
        
        return True

def main():
    """Main entry point for the pipeline orchestrator"""
    parser = argparse.ArgumentParser(description='Threat Intelligence Pipeline Orchestrator')
    parser.add_argument('--force-update', action='store_true',
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
    
    # Set logging level
    if args.verbose:
        logging.getLogger('cve2capec').setLevel(logging.DEBUG)
    
    # Create orchestrator
    orchestrator = PipelineOrchestrator()
    
    try:
        if args.status:
            status = orchestrator.get_pipeline_status()
            print(json.dumps(status, indent=2))
            return
        
        if args.db_only:
            summary = orchestrator.run_database_updates_only()
        elif args.cve_only:
            summary = orchestrator.run_cve_processing_only()
        else:
            summary = orchestrator.run_full_pipeline(force_update=args.force_update)
        
        # Print summary
        print("\n" + "="*60)
        print("PIPELINE SUMMARY")
        print("="*60)
        print(f"Total Duration: {summary['pipeline_session']['total_duration']:.2f}s")
        print(f"Successful Steps: {summary['pipeline_session']['successful_steps']}")
        print(f"Failed Steps: {summary['pipeline_session']['failed_steps']}")
        print(f"Total Steps: {summary['pipeline_session']['total_steps']}")
        
        if summary['pipeline_session']['failed_steps'] > 0:
            print("\nFAILED STEPS:")
            for name, result in summary['results'].items():
                if result.get('status') == 'failed':
                    print(f"  - {name}: {result.get('error', 'Unknown error')}")
        
        print(f"\nDetailed summary saved to: results/update_summary.json")
        print("="*60)
        
        # Exit with appropriate code
        if summary['pipeline_session']['failed_steps'] > 0:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except Exception as e:
        log_critical(f"Pipeline orchestrator failed: {e}")
        print(f"\n❌ Pipeline failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
