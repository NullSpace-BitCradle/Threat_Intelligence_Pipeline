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

# config.json at the repo root, found from this file rather than the working
# directory, so the pipeline reads the same config wherever it is started.
DEFAULT_CONFIG_FILE = Path(__file__).resolve().parents[3] / "config.json"


class Config:
    """Centralized configuration management"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = str(config_file or DEFAULT_CONFIG_FILE)
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load the configuration file. A missing or unreadable file raises:
        silently running on built-in defaults sent data to other paths with
        no download URLs, and failed later with misleading errors."""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config: Dict[str, Any] = json.load(f)
        except (OSError, ValueError) as e:
            raise RuntimeError(f"Cannot load config file {self.config_file}: {e}") from e
        logger.info(f"Loaded configuration from {self.config_file}")
        return config
    
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
            # Stripped: a pasted secret can end in a newline, and requests
            # quotes a header value it rejects, key included, in the error.
            return os.environ.get(env_var, "").strip() or None
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
