#!/usr/bin/env python3
"""
Simplified pipeline orchestrator
Combines database updates and CVE processing into a streamlined workflow
"""
import sys
import json
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
import argparse

from tip.utils.config import get_config
from tip.core.database_manager import DatabaseManager
from tip.core.cve_processor import CVEProcessor
# CVE retrieval is now handled by CVEProcessor
from tip.utils.error_handler import (
    log_info, log_warning, log_error, log_critical, get_logger,
    ProcessingError, NVDUnavailableError, create_data_context
)
from tip.utils.performance_optimizer import (
    performance_timer, get_performance_summary
)
from tip.utils.atomic_io import atomic_write_bytes, atomic_write_text, jsonl_bytes
from tip.utils.freshness import record_freshness, succeeded_sources
from tip.core import change_log

config = get_config()
logger = get_logger('pipeline_orchestrator')

class PipelineOrchestrator:
    """Simplified pipeline orchestrator for Threat Intelligence Pipeline"""
    
    def __init__(self):
        self.start_time = datetime.now()
        self.results: Dict[str, Dict[str, Any]] = {}
        self.config = config
        # Published state before this run's writes, for the change log (I8).
        self._before: Optional[Dict[str, Any]] = None
        
        # Initialize components
        self.db_manager = DatabaseManager()
        self.cve_processor = CVEProcessor()
        # One EPSS fetch per run, shared by the database step and CVE step.
        self.cve_processor.epss_processor = self.db_manager.epss_processor
    
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

            self._snapshot_before()

            # Step 1: Update databases
            log_info("Step 1: Updating databases...")
            db_results = self._update_databases()

            # Fail closed early: every shard record the crawl would rewrite
            # needs this run's EPSS, and a red run publishes nothing, so do
            # not spend hours on NVD when EPSS already failed.
            if db_results.get('results', {}).get('epss') is False:
                log_error("EPSS database step failed; NVD crawl not started")
                self.results['cve_retrieval'] = {
                    'status': 'failed',
                    'error': 'skipped: the EPSS database step failed, so the NVD crawl was not started',
                    'timestamp': datetime.now().isoformat()
                }
                return self._create_summary()

            # Step 2: Retrieve all CVEs
            log_info("Step 2: Retrieving all CVEs...")
            cve_results = self._retrieve_cves()
            
            # Step 3: Process CVEs through pipeline
            if cve_results.get('success', False):
                log_info("Step 3: Processing CVEs through pipeline...")
                processing_results = self._process_cves()
            elif cve_results.get('degraded'):
                # NVD was unavailable — do NOT claim "no new CVEs" (the exact
                # lie this hardening removes). Skip processing, preserve last-good.
                log_warning(
                    "Skipping CVE processing — NVD unavailable this run "
                    "(degraded); last-good data preserved, will resume next run"
                )
                processing_results = {
                    'success': False, 'degraded': True, 'message': 'NVD unavailable'
                }
            else:
                log_info("No new CVEs to process")
                processing_results = {'success': True, 'message': 'No new CVEs'}

            # Step 3b: Fetch campaign data. A failure keeps the last-good
            # campaigns_db.json but is a failed step: the run goes red.
            log_info("Step 3b: Fetching ATT&CK campaigns...")
            self._fetch_campaigns()

            # Step 4: Generate entity index for unified entity system. A
            # generator exception is a failed step, never a warning.
            log_info("Step 4: Generating entity index...")
            self._generate_entity_index()

            # Step 5: the curated tier may have changed with the new index;
            # republish the EPSS curated file from this run's snapshot.
            self._refresh_epss_curated()

            # Generate final summary
            summary = self._create_summary()
            log_info("Pipeline completed successfully")
            
            return summary
            
        except Exception as e:
            log_critical(f"Pipeline failed: {e}")
            raise
    
    def _fetch_campaigns(self) -> None:
        try:
            from tip.core.campaign_fetcher import fetch_campaigns
            base_dir = Path(__file__).resolve().parents[3]
            fetch_campaigns(base_dir)
            self.results['campaigns'] = {
                'status': 'success', 'timestamp': datetime.now().isoformat()
            }
            log_info("Campaign data fetched successfully")
        except Exception as e:
            log_error(f"Campaign fetch failed: {e}")
            self.results['campaigns'] = {
                'status': 'failed', 'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def _generate_entity_index(self) -> None:
        try:
            from tip.core.entity_index_generator import generate_entity_index, write_outputs
            base_dir = Path(__file__).resolve().parents[3]
            entity_index, search_index, cve_ids_index = generate_entity_index(base_dir)
            write_outputs(entity_index, search_index, base_dir, cve_ids_index)
            self.results['entity_index'] = {
                'status': 'success',
                'entity_count': entity_index['meta']['entity_count'],
                'timestamp': datetime.now().isoformat()
            }
            log_info(
                f"Entity index generated: {entity_index['meta']['entity_count']} entities, "
                f"{cve_ids_index['count']} CVE IDs in Layer 1"
            )
        except Exception as e:
            log_error(f"Entity index generation failed: {e}")
            self.results['entity_index'] = {
                'status': 'failed', 'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def _refresh_epss_curated(self) -> None:
        """Rewrite epss_curated.json against the entity index just written.

        Uses the snapshot the database step fetched; no second download. When
        there is no snapshot the epss database step already failed and the
        run is red, so there is nothing to refresh.
        """
        epss = self.db_manager.epss_processor
        if epss.snapshot is None or self.results.get('entity_index', {}).get('status') != 'success':
            return
        try:
            count = epss.write_curated(epss.snapshot)
            self.results['epss_curated'] = {
                'status': 'success', 'curated_count': count,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            log_error(f"EPSS curated refresh failed: {e}")
            self.results['epss_curated'] = {
                'status': 'failed', 'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

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
            
            summary: Dict[str, Any] = {
                'status': 'success' if failed == 0 else 'partial',
                'duration': duration,
                'successful': successful,
                'failed': failed,
                'results': db_results,
                # Steps that wrote fresh upstream data, not just succeeded;
                # freshness.json advances only on these.
                'fresh': sorted(getattr(self.db_manager, 'fresh_writes', set())),
                'timestamp': datetime.now().isoformat()
            }
            self.results['database_updates'] = summary

            log_info(f"Database updates completed: {successful} successful, {failed} failed")

            if failed > 0:
                log_warning(f"Some database updates failed: {[k for k, v in db_results.items() if not v]}")

            return summary
            
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
    
    def _retrieve_cves(self) -> Dict[str, Any]:
        """Retrieve all CVEs from NVD"""
        log_info("Retrieving all CVEs from NVD...")
        
        try:
            start_time = time.time()
            
            # Get all CVEs (no date restrictions to get complete dataset)
            log_info("Fetching all available CVEs from NVD...")
            
            # Retrieve CVEs from NVD without date parameters
            nvd_cves = self.cve_processor.retrieve_cves_from_nvd()
            
            if not nvd_cves:
                log_info("No new CVEs found")
                duration = time.time() - start_time
                
                self.results['cve_retrieval'] = {
                    'status': 'success',
                    'duration': duration,
                    'cve_count': 0,
                    'timestamp': datetime.now().isoformat()
                }
                
                return {
                    'success': True,
                    'cve_count': 0,
                    'data': {}
                }
            
            # Process NVD data into our format
            processed_cves = self.cve_processor.process_nvd_cves(nvd_cves)
            
            # Save to file for processing
            cve_file = self.config.get_output_path('cve_output')
            atomic_write_bytes(cve_file, jsonl_bytes(processed_cves.items()))

            duration = time.time() - start_time

            # A fetch resumed from a progress file only covers the tail of
            # the corpus. It is real progress but not a full refresh, so it
            # is recorded as partial and the run does not report clean.
            resumed_from = getattr(self.cve_processor, 'last_fetch_resumed_from', 0) or 0
            self.results['cve_retrieval'] = {
                'status': 'partial' if resumed_from else 'success',
                'duration': duration,
                'cve_count': len(processed_cves),
                'timestamp': datetime.now().isoformat()
            }
            if resumed_from:
                self.results['cve_retrieval']['resumed_from_index'] = resumed_from
                log_warning(
                    f"CVE fetch resumed from index {resumed_from}; "
                    "run recorded as partial, not a full refresh"
                )
            
            log_info(f"CVE retrieval completed: {len(processed_cves)} CVEs retrieved")
            
            return {
                'success': True,
                'cve_count': len(processed_cves),
                'data': processed_cves
            }
            
        except NVDUnavailableError as e:
            # NVD was unreachable/too slow past the retry budget. This is a
            # DEGRADED run, NOT "no new CVEs" — do NOT write/truncate the
            # cve_output file; leave last-good data in place. The progress file
            # (not cleaned up on failure) lets the next run resume.
            log_warning(
                "NVD unavailable — skipping CVE retrieval, last-good output "
                f"preserved ({e.partial_count} CVEs seen this run, resume at "
                f"index {e.last_index}): {e}"
            )
            self.results['cve_retrieval'] = {
                'status': 'degraded',
                'reason': 'nvd_unavailable',
                'error': str(e),
                'partial_count': e.partial_count,
                'last_index': e.last_index,
                'timestamp': datetime.now().isoformat()
            }
            return {
                'success': False,
                'degraded': True,
                'reason': 'nvd_unavailable',
                'error': str(e)
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
    
    def _process_cves(self) -> Dict[str, Any]:
        """Process CVEs through the pipeline"""
        log_info("Processing CVEs through pipeline...")
        
        try:
            start_time = time.time()
            
            # Process CVEs using the unified processor
            success = self.cve_processor.process_file()
            duration = time.time() - start_time
            
            step: Dict[str, Any] = {
                'status': 'success' if success else 'failed',
                'duration': duration,
                'timestamp': datetime.now().isoformat()
            }
            stats = getattr(self.cve_processor, 'last_enrichment', None)
            if stats:
                step['attempted'] = stats.get('attempted', 0)
                step['enrichment_failed'] = stats.get('failed', 0)
                # Capped so a mass failure cannot bloat the summary file.
                step['enrichment_failed_ids'] = list(stats.get('failed_ids', []))[:100]
            epss_error = getattr(self.cve_processor, 'last_epss_error', None)
            if epss_error:
                # Records were written without EPSS: real progress, not clean.
                step['epss_error'] = epss_error
                if success:
                    step['status'] = 'partial'
            self.results['cve_processing'] = step
            
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
        # 'partial' (some reference DBs failed, or a resumed CVE fetch) is not
        # a clean run either.
        partial_steps = sum(1 for r in self.results.values() if r.get('status') == 'partial')
        # 'degraded' (e.g. NVD unavailable) is neither success nor failure — it
        # must not silently roll up as a clean run. Counted distinctly so the
        # exit code and summary surface the brownout.
        degraded_steps = sum(1 for r in self.results.values() if r.get('status') == 'degraded')

        summary = {
            'pipeline_session': {
                'start_time': self.start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'total_duration': total_duration,
                'successful_steps': successful_steps,
                'failed_steps': failed_steps,
                'degraded_steps': degraded_steps,
                'partial_steps': partial_steps,
                'total_steps': len(self.results)
            },
            'results': self.results,
            'performance': perf_summary
        }
        
        # Not a step: the change log never turns a run red, so it lives
        # beside results, not in it.
        changes = self._record_changes()
        if changes is not None:
            summary['changes'] = changes

        # Save summary to file
        summary_file = Path('results/update_summary.json')
        summary_file.parent.mkdir(exist_ok=True)
        
        atomic_write_text(summary_file, json.dumps(summary, indent=2))

        # freshness.json advances per source on success only, even inside a
        # partial run; the data workflows publish it only when the run is clean.
        self._record_freshness()

        # lastUpdate.txt advances only on a run that did work and was fully
        # clean; a degraded, partial or failed run leaves it where it was.
        if self._run_is_clean(summary):
            self._update_last_update_time()
        elif len(self.results) > 0:
            log_warning("Run not fully successful; lastUpdate.txt left unchanged")

        return summary

    @staticmethod
    def _run_is_clean(summary: Dict[str, Any]) -> bool:
        session = summary['pipeline_session']
        return bool(
            session['total_steps'] > 0
            and session['failed_steps'] == 0
            and session.get('degraded_steps', 0) == 0
            and session.get('partial_steps', 0) == 0
        )
    
    def _record_freshness(self) -> None:
        """Record per-source success times. A failure here is logged and
        never turns the run red."""
        try:
            path = Path(self.config.get('files.freshness', 'docs/data/freshness.json'))
            advanced = record_freshness(self.results, path)
            if advanced:
                log_info(f"Freshness recorded for: {', '.join(advanced)}")
        except Exception as e:
            log_warning(f"Failed to record data freshness: {e}")

    def _change_paths(self) -> Dict[str, Path]:
        """Source files the change log diffs, and the log itself."""
        log = Path(self.config.get('files.changes', 'docs/data/changes.json.gz'))
        return {
            'kev': Path(self.config.get('database.kev.file', 'docs/data/kev_db.json')),
            'vulnrichment': Path(self.config.get('database.vulnrichment.file', 'docs/data/vulnrichment_db.json')),
            'epss': Path(self.config.get('database.epss.file', 'docs/data/epss_curated.json')),
            'entity_index': log.parent / 'entity_index.json',
            'log': log,
        }

    def _snapshot_before(self) -> None:
        """Snapshot the published state each source is about to replace
        (I8). The workflows sync to main first, so this is the last
        published state. A failure only means no events this run."""
        try:
            paths = self._change_paths()
            self._before = change_log.snapshot_sources(
                {s: paths[s] for s in change_log.SOURCES}
            )
        except Exception as e:
            log_warning(f"Change log snapshot failed; no change events this run: {e}")
            self._before = None

    def _record_changes(self) -> Optional[Dict[str, Any]]:
        """Merge this run's change events into the log. Only sources whose
        step succeeded with fresh data add events; a failure here is logged
        and never turns the run red."""
        before = getattr(self, '_before', None)
        if before is None:
            return None
        self._before = None
        try:
            paths = self._change_paths()
            summary = change_log.record_changes(
                before, paths, succeeded_sources(self.results), paths['log']
            )
            if summary.get('written'):
                log_info(
                    f"Change log: {summary['new_events']} new events from "
                    f"{', '.join(summary['diffed'])}"
                )
            return summary
        except Exception as e:
            log_warning(f"Failed to record change events: {e}")
            return {'error': str(e)}

    def _update_last_update_time(self):
        """Update the last update timestamp"""
        try:
            last_update_file = Path(self.config.get('files.last_update', 'lastUpdate.txt'))
            atomic_write_text(last_update_file, datetime.now().isoformat())
            log_info(f"Updated last update timestamp in {last_update_file}")
        except Exception as e:
            log_warning(f"Failed to update last update timestamp: {e}")
    
    def run_database_updates_only(self) -> Dict[str, Any]:
        """Run only database updates"""
        log_info("Running database updates only...")
        self._snapshot_before()
        self._update_databases()
        return self._create_summary()
    
    def run_cve_processing_only(self) -> Dict[str, Any]:
        """Run only CVE processing"""
        log_info("Running CVE processing only...")
        
        # Retrieve all CVEs first
        log_info("Retrieving all CVEs...")
        cve_results = self._retrieve_cves()
        if not cve_results.get('success', False):
            log_error("Failed to retrieve CVEs")
            return self._create_summary()
        
        self._process_cves()
        return self._create_summary()
    
    def get_pipeline_status(self) -> Dict[str, Any]:
        """Get current pipeline status"""
        pipeline_ready = self._is_pipeline_ready()

        return {
            'database_status': self.db_manager.get_database_status(),
            'last_update': self._get_last_update_time(),
            'pipeline_ready': pipeline_ready
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

def exit_code_for(summary: Dict[str, Any]) -> int:
    """Process exit code for a pipeline summary: 0 only for a clean run.

    Failed, degraded and partial steps all exit 1. This is the one rule both
    entry points (run_pipeline.py and this module) use; CI reads nothing else.
    """
    session = summary['pipeline_session']
    unclean = (
        session.get('failed_steps', 0)
        + session.get('degraded_steps', 0)
        + session.get('partial_steps', 0)
    )
    return 0 if unclean == 0 else 1


def main() -> None:
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
        degraded_steps = summary['pipeline_session'].get('degraded_steps', 0)
        print(f"Degraded Steps: {degraded_steps}")
        print(f"Total Steps: {summary['pipeline_session']['total_steps']}")

        if summary['pipeline_session']['failed_steps'] > 0:
            print("\nFAILED STEPS:")
            for name, result in summary['results'].items():
                if result.get('status') == 'failed':
                    print(f"  - {name}: {result.get('error', 'Unknown error')}")

        if degraded_steps > 0:
            print("\nDEGRADED STEPS:")
            for name, result in summary['results'].items():
                if result.get('status') == 'degraded':
                    print(f"  - {name}: {result.get('error', result.get('reason', 'degraded'))}")

        print(f"\nDetailed summary saved to: results/update_summary.json")
        print("="*60)

        # Exit with appropriate code. A degraded or partial run (e.g. NVD
        # brownout) is NOT a clean run; exit non-zero so CI does not read it
        # as success.
        sys.exit(exit_code_for(summary))
            
    except Exception as e:
        log_critical(f"Pipeline orchestrator failed: {e}")
        print(f"\n❌ Pipeline failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
