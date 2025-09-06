"""
Database optimization utilities for Threat Intelligence Pipeline
"""
import json
import os
import sqlite3
import logging
from typing import Dict, Any, List, Optional, Iterator
from pathlib import Path
import time
from config import get_config

logger = logging.getLogger(__name__)
config = get_config()

class DatabaseOptimizer:
    """Optimized database operations with indexing and caching"""
    
    def __init__(self, db_path: str = "cve_database.db"):
        self.db_path = db_path
        self.connection = None
        self._setup_database()
    
    def _setup_database(self):
        """Setup SQLite database with proper indexing"""
        self.connection = sqlite3.connect(self.db_path)
        self.connection.execute("PRAGMA journal_mode=WAL")  # Better concurrency
        self.connection.execute("PRAGMA synchronous=NORMAL")  # Faster writes
        self.connection.execute("PRAGMA cache_size=10000")  # Larger cache
        
        # Create tables with proper indexing
        self._create_tables()
        self._create_indexes()
    
    def _create_tables(self):
        """Create optimized database tables"""
        cursor = self.connection.cursor()
        
        # CVE table with proper structure
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                id TEXT PRIMARY KEY,
                year INTEGER NOT NULL,
                cwe_data TEXT,
                capec_data TEXT,
                techniques_data TEXT,
                defend_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # CWE lookup table for fast parent/child relationships
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cwe_relationships (
                cwe_id TEXT PRIMARY KEY,
                parent_cwes TEXT,
                related_capecs TEXT
            )
        """)
        
        # CAPEC lookup table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS capec_data (
                capec_id TEXT PRIMARY KEY,
                name TEXT,
                techniques TEXT
            )
        """)
        
        self.connection.commit()
    
    def _create_indexes(self):
        """Create database indexes for fast lookups"""
        cursor = self.connection.cursor()
        
        # Indexes for CVE table
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_year ON cves(year)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_updated ON cves(updated_at)")
        
        # Indexes for CWE relationships
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cwe_parents ON cwe_relationships(cwe_id)")
        
        self.connection.commit()
    
    def insert_cve_batch(self, cve_data: Dict[str, Any]) -> None:
        """Insert multiple CVEs in a single transaction"""
        cursor = self.connection.cursor()
        
        try:
            cursor.execute("BEGIN TRANSACTION")
            
            for cve_id, data in cve_data.items():
                year = int(cve_id.split('-')[1])
                
                cursor.execute("""
                    INSERT OR REPLACE INTO cves 
                    (id, year, cwe_data, capec_data, techniques_data, defend_data, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (
                    cve_id,
                    year,
                    json.dumps(data.get('CWE', [])),
                    json.dumps(data.get('CAPEC', [])),
                    json.dumps(data.get('TECHNIQUES', [])),
                    json.dumps(data.get('DEFEND', []))
                ))
            
            cursor.execute("COMMIT")
            logger.info(f"Inserted {len(cve_data)} CVEs into database")
            
        except Exception as e:
            cursor.execute("ROLLBACK")
            logger.error(f"Failed to insert CVE batch: {e}")
            raise
    
    def get_cve_by_year(self, year: int) -> Iterator[Dict[str, Any]]:
        """Get CVEs by year using streaming to avoid memory issues"""
        cursor = self.connection.cursor()
        
        cursor.execute("SELECT id, cwe_data, capec_data, techniques_data, defend_data FROM cves WHERE year = ?", (year,))
        
        for row in cursor:
            yield {
                row[0]: {
                    'CWE': json.loads(row[1]) if row[1] else [],
                    'CAPEC': json.loads(row[2]) if row[2] else [],
                    'TECHNIQUES': json.loads(row[3]) if row[3] else [],
                    'DEFEND': json.loads(row[4]) if row[4] else []
                }
            }
    
    def get_cve_count_by_year(self, year: int) -> int:
        """Get count of CVEs for a specific year"""
        cursor = self.connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM cves WHERE year = ?", (year,))
        return cursor.fetchone()[0]
    
    def update_cve_incremental(self, cve_id: str, data: Dict[str, Any]) -> None:
        """Update a single CVE record incrementally"""
        cursor = self.connection.cursor()
        year = int(cve_id.split('-')[1])
        
        cursor.execute("""
            INSERT OR REPLACE INTO cves 
            (id, year, cwe_data, capec_data, techniques_data, defend_data, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (
            cve_id,
            year,
            json.dumps(data.get('CWE', [])),
            json.dumps(data.get('CAPEC', [])),
            json.dumps(data.get('TECHNIQUES', [])),
            json.dumps(data.get('DEFEND', []))
        ))
        
        self.connection.commit()
    
    def load_cwe_relationships(self, cwe_db: Dict[str, Any]) -> None:
        """Load CWE relationships into database for fast lookups"""
        cursor = self.connection.cursor()
        
        cursor.execute("DELETE FROM cwe_relationships")  # Clear existing data
        
        for cwe_id, data in cwe_db.items():
            cursor.execute("""
                INSERT INTO cwe_relationships (cwe_id, parent_cwes, related_capecs)
                VALUES (?, ?, ?)
            """, (
                cwe_id,
                json.dumps(data.get('ChildOf', [])),
                json.dumps(data.get('RelatedAttackPatterns', []))
            ))
        
        self.connection.commit()
        logger.info(f"Loaded {len(cwe_db)} CWE relationships into database")
    
    def get_cwe_relationships(self, cwe_id: str) -> Dict[str, List[str]]:
        """Get CWE relationships from database"""
        cursor = self.connection.cursor()
        
        cursor.execute("SELECT parent_cwes, related_capecs FROM cwe_relationships WHERE cwe_id = ?", (cwe_id,))
        row = cursor.fetchone()
        
        if row:
            return {
                'ChildOf': json.loads(row[0]) if row[0] else [],
                'RelatedAttackPatterns': json.loads(row[1]) if row[1] else []
            }
        return {'ChildOf': [], 'RelatedAttackPatterns': []}
    
    def load_capec_data(self, capec_db: Dict[str, Any]) -> None:
        """Load CAPEC data into database"""
        cursor = self.connection.cursor()
        
        cursor.execute("DELETE FROM capec_data")  # Clear existing data
        
        for capec_id, data in capec_db.items():
            cursor.execute("""
                INSERT INTO capec_data (capec_id, name, techniques)
                VALUES (?, ?, ?)
            """, (
                capec_id,
                data.get('name', ''),
                data.get('techniques', '')
            ))
        
        self.connection.commit()
        logger.info(f"Loaded {len(capec_db)} CAPEC entries into database")
    
    def get_capec_data(self, capec_id: str) -> Dict[str, str]:
        """Get CAPEC data from database"""
        cursor = self.connection.cursor()
        
        cursor.execute("SELECT name, techniques FROM capec_data WHERE capec_id = ?", (capec_id,))
        row = cursor.fetchone()
        
        if row:
            return {'name': row[0], 'techniques': row[1]}
        return {'name': '', 'techniques': ''}
    
    def export_to_jsonl(self, year: int, output_file: str) -> None:
        """Export CVE data for a year to JSONL format"""
        with open(output_file, 'w', encoding='utf-8') as f:
            for cve_data in self.get_cve_by_year(year):
                f.write(json.dumps(cve_data) + "\n")
        
        logger.info(f"Exported {self.get_cve_count_by_year(year)} CVEs to {output_file}")
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        cursor = self.connection.cursor()
        
        stats = {}
        
        # Total CVEs
        cursor.execute("SELECT COUNT(*) FROM cves")
        stats['total_cves'] = cursor.fetchone()[0]
        
        # CVEs by year
        cursor.execute("SELECT year, COUNT(*) FROM cves GROUP BY year ORDER BY year")
        stats['cves_by_year'] = dict(cursor.fetchall())
        
        # Database size
        stats['db_size_mb'] = os.path.getsize(self.db_path) / (1024 * 1024)
        
        return stats
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()

class JSONLDatabaseManager:
    """Optimized JSONL database manager with streaming and caching"""
    
    def __init__(self):
        self.cache = {}
        self.cache_size_limit = config.get('processing.batch_size', 1000)
    
    def load_jsonl_streaming(self, file_path: str) -> Iterator[Dict[str, Any]]:
        """Load JSONL file using streaming to avoid memory issues"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        yield json.loads(line.strip())
                    except json.JSONDecodeError as e:
                        logger.warning(f"Invalid JSON on line {line_num} in {file_path}: {e}")
                        continue
        except FileNotFoundError:
            logger.info(f"File {file_path} not found, returning empty iterator")
            return
        except Exception as e:
            logger.error(f"Error reading {file_path}: {e}")
            raise
    
    def load_jsonl_cached(self, file_path: str) -> Dict[str, Any]:
        """Load JSONL file with caching"""
        if file_path in self.cache:
            return self.cache[file_path]
        
        data = {}
        for entry in self.load_jsonl_streaming(file_path):
            data.update(entry)
        
        # Cache if not too large
        if len(data) <= self.cache_size_limit:
            self.cache[file_path] = data
        
        return data
    
    def save_jsonl_incremental(self, file_path: str, new_data: Dict[str, Any]) -> None:
        """Save data incrementally to JSONL file"""
        # Load existing data
        existing_data = self.load_jsonl_cached(file_path)
        
        # Update with new data
        existing_data.update(new_data)
        
        # Save back to file
        with open(file_path, 'w', encoding='utf-8') as f:
            for cve_id, data in existing_data.items():
                f.write(json.dumps({cve_id: data}) + "\n")
        
        # Update cache
        if file_path in self.cache:
            self.cache[file_path] = existing_data
    
    def clear_cache(self):
        """Clear the cache"""
        self.cache.clear()

# Global database manager instances
db_optimizer = None
jsonl_manager = JSONLDatabaseManager()

def get_database_optimizer() -> DatabaseOptimizer:
    """Get global database optimizer instance"""
    global db_optimizer
    if db_optimizer is None:
        db_optimizer = DatabaseOptimizer()
    return db_optimizer

def get_jsonl_manager() -> JSONLDatabaseManager:
    """Get global JSONL manager instance"""
    return jsonl_manager
