"""
Configuration management for Threat Intelligence Pipeline
"""
import os
import json
import logging
from typing import Dict, Any, Optional
from pathlib import Path
from config_validator import validate_config, ConfigValidator

logger = logging.getLogger(__name__)

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
                    config = json.load(f)
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
                    "url": "http://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
                    "file": "resources/cwe_db.json"
                },
                "techniques": {
                    "enterprise": {
                        "url": "https://attack.mitre.org/docs/enterprise-attack-v17.1/enterprise-attack-v17.1-techniques.xlsx",
                        "column": 9
                    },
                    "mobile": {
                        "url": "https://attack.mitre.org/docs/mobile-attack-v17.1/mobile-attack-v17.1-techniques.xlsx",
                        "column": 10
                    },
                    "ics": {
                        "url": "https://attack.mitre.org/docs/ics-attack-v17.1/ics-attack-v17.1-techniques.xlsx",
                        "column": 9
                    },
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
    
    def validate(self) -> bool:
        """
        Validate configuration using JSON schema validation
        
        Returns:
            True if configuration is valid
        """
        # Use the comprehensive validator
        validator = ConfigValidator()
        is_valid = validator.validate_config(self.config)
        
        if not is_valid:
            logger.error("Configuration validation failed:")
            for error in validator.get_errors():
                logger.error(f"  - {error}")
        
        # Log warnings
        for warning in validator.get_warnings():
            logger.warning(f"Configuration warning: {warning}")
        
        return is_valid
    
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
        return self.get(f'database.{db_name}.file', f'resources/{db_name}_db.json')
    
    def get_output_path(self, file_type: str) -> str:
        """
        Get output file path
        
        Args:
            file_type: Type of output file (e.g., 'cve_output', 'last_update')
            
        Returns:
            Full path to output file
        """
        return self.get(f'files.{file_type}', f'results/{file_type}')
    
    def setup_logging(self) -> None:
        """Setup logging based on configuration"""
        level = getattr(logging, self.get('logging.level', 'INFO').upper())
        format_str = self.get('logging.format', '%(asctime)s - %(levelname)s - %(message)s')
        log_file = self.get('logging.file')
        
        logging.basicConfig(
            level=level,
            format=format_str,
            filename=log_file if log_file else None,
            filemode='a' if log_file else 'w'
        )

# Global configuration instance
config = Config()

def get_config() -> Config:
    """Get global configuration instance"""
    return config
