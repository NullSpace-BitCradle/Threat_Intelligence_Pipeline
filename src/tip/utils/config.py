"""
Configuration management for Threat Intelligence Pipeline
"""
import os
import sys
import json
import logging
import logging.handlers
from typing import Dict, Any, Optional, cast
from pathlib import Path

logger = logging.getLogger(__name__)

# Marks root handlers owned by Config.setup_logging so a repeat call replaces them.
_TIP_HANDLER_ATTR = '_tip_pipeline_handler'

class Config:
    """Centralized configuration management"""
    
    def __init__(self, config_file: str = "config.json"):
        self.config_file = config_file
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default"""
        config_path = Path(self.config_file)
        
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config: Dict[str, Any] = json.load(f)
                logger.info(f"Loaded configuration from {self.config_file}")
                return config
            except Exception as e:
                logger.error(f"Failed to load config file {self.config_file}: {e}")
                logger.info("Using default configuration")
        else:
            logger.info(f"Config file {self.config_file} not found, using default configuration")
        
        return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            "api": {
                "nvd": {
                    "base_url": "https://services.nvd.nist.gov/rest/json/cves/2.0/",
                    "api_key_env": "NVD_API_KEY",
                    "timeout": 30,
                    "retry_limit": 3,
                    "retry_delay": 5,
                    "results_per_page": 2000
                },
                "d3fend": {
                    "base_url": "https://d3fend.mitre.org/api/offensive-technique/attack/",
                    "timeout": 30
                }
            },
            "database": {
                "capec": {
                    "url": "https://capec.mitre.org/data/csv/1000.csv.zip",
                    "file": "resources/capec_db.json"
                },
                "cwe": {
                    "url": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
                    "file": "resources/cwe_db.json"
                },
                "techniques": {
                    "file": "resources/techniques_db.json"
                },
                "defend": {
                    "file": "resources/defend_db.jsonl"
                }
            },
            "processing": {
                "max_threads": 10,
                "batch_size": 1000,
                "enable_concurrent_processing": True
            },
            "files": {
                "cve_output": "results/new_cves.jsonl",
                "last_update": "lastUpdate.txt",
                "database_dir": "database"
            },
            "logging": {
                "level": "INFO",
                "format": "%(asctime)s - %(levelname)s - %(message)s",
                "file": None  # Set to filename to enable file logging
            }
        }
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation
        
        Args:
            key_path: Dot-separated path to config value (e.g., 'api.nvd.timeout')
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        keys = key_path.split('.')
        value = self.config
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path: str, value: Any) -> None:
        """
        Set configuration value using dot notation
        
        Args:
            key_path: Dot-separated path to config value
            value: Value to set
        """
        keys = key_path.split('.')
        config = self.config
        
        # Navigate to the parent of the target key
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        # Set the final value
        config[keys[-1]] = value
    
    def save(self) -> None:
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4)
            logger.info(f"Configuration saved to {self.config_file}")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
    
    def get_api_key(self, api_name: str) -> Optional[str]:
        """
        Get API key from environment variable
        
        Args:
            api_name: Name of the API (e.g., 'nvd')
            
        Returns:
            API key or None if not found
        """
        env_var = self.get(f'api.{api_name}.api_key_env')
        if env_var:
            return os.environ.get(env_var)
        return None
    
    def get_database_path(self, db_name: str) -> str:
        """
        Get database file path
        
        Args:
            db_name: Name of the database (e.g., 'capec', 'cwe')
            
        Returns:
            Full path to database file
        """
        return cast(str, self.get(f'database.{db_name}.file', f'resources/{db_name}_db.json'))
    
    def get_output_path(self, file_type: str) -> str:
        """
        Get output file path
        
        Args:
            file_type: Type of output file (e.g., 'cve_output', 'last_update')
            
        Returns:
            Full path to output file
        """
        return cast(str, self.get(f'files.{file_type}', f'results/{file_type}'))
    
    def setup_logging(self) -> None:
        """Install the pipeline's console and file handlers on the root logger.

        Root is the single owner of logging.file: every logger (the
        'cve2capec' tree and plain module loggers) propagates here, so each
        record is written once. Safe to call repeatedly: handlers installed by
        an earlier call are replaced, never stacked.
        """
        root = logging.getLogger()
        for handler in [h for h in root.handlers if getattr(h, _TIP_HANDLER_ATTR, False)]:
            root.removeHandler(handler)
            handler.close()

        root.setLevel(getattr(logging, self.get('logging.level', 'INFO').upper()))

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        setattr(console_handler, _TIP_HANDLER_ATTR, True)
        root.addHandler(console_handler)

        log_file = self.get('logging.file')
        if log_file:
            os.makedirs(os.path.dirname(log_file) or '.', exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=self.get('logging.max_file_size', 10 * 1024 * 1024),
                backupCount=self.get('logging.backup_count', 5),
                encoding='utf-8',
            )
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
            ))
            setattr(file_handler, _TIP_HANDLER_ATTR, True)
            root.addHandler(file_handler)

# Global configuration instance
config = Config()

def get_config() -> Config:
    """Get global configuration instance"""
    return config
