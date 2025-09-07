#!/usr/bin/env python3
"""
Configuration validation utilities for Threat Intelligence Pipeline
Provides JSON schema validation for configuration files
"""
import json
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

# JSON Schema for configuration validation
CONFIG_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["api", "database", "processing", "files", "logging"],
    "properties": {
        "api": {
            "type": "object",
            "required": ["nvd"],
            "properties": {
                "nvd": {
                    "type": "object",
                    "required": ["base_url", "timeout", "retry_limit"],
                    "properties": {
                        "base_url": {"type": "string", "format": "uri"},
                        "api_key_env": {"type": "string"},
                        "timeout": {"type": "number", "minimum": 1, "maximum": 300},
                        "retry_limit": {"type": "integer", "minimum": 1, "maximum": 10},
                        "retry_delay": {"type": "number", "minimum": 0.1, "maximum": 60},
                        "results_per_page": {"type": "integer", "minimum": 1, "maximum": 2000}
                    }
                },
                "d3fend": {
                    "type": "object",
                    "properties": {
                        "base_url": {"type": "string", "format": "uri"},
                        "timeout": {"type": "number", "minimum": 1, "maximum": 300}
                    }
                }
            }
        },
        "database": {
            "type": "object",
            "required": ["capec", "cwe", "techniques"],
            "properties": {
                "capec": {
                    "type": "object",
                    "required": ["url", "file"],
                    "properties": {
                        "url": {"type": "string", "format": "uri"},
                        "file": {"type": "string", "pattern": ".*\\.json$"}
                    }
                },
                "cwe": {
                    "type": "object",
                    "required": ["url", "file"],
                    "properties": {
                        "url": {"type": "string", "format": "uri"},
                        "file": {"type": "string", "pattern": ".*\\.json$"}
                    }
                },
                "techniques": {
                    "type": "object",
                    "required": ["enterprise", "mobile", "ics", "file"],
                    "properties": {
                        "enterprise": {
                            "type": "object",
                            "required": ["url", "column"],
                            "properties": {
                                "url": {"type": "string", "format": "uri"},
                                "column": {"type": "integer", "minimum": 0, "maximum": 20}
                            }
                        },
                        "mobile": {
                            "type": "object",
                            "required": ["url", "column"],
                            "properties": {
                                "url": {"type": "string", "format": "uri"},
                                "column": {"type": "integer", "minimum": 0, "maximum": 20}
                            }
                        },
                        "ics": {
                            "type": "object",
                            "required": ["url", "column"],
                            "properties": {
                                "url": {"type": "string", "format": "uri"},
                                "column": {"type": "integer", "minimum": 0, "maximum": 20}
                            }
                        },
                        "file": {"type": "string", "pattern": ".*\\.json$"}
                    }
                },
                "defend": {
                    "type": "object",
                    "properties": {
                        "file": {"type": "string", "pattern": ".*\\.jsonl?$"}
                    }
                }
            }
        },
        "processing": {
            "type": "object",
            "required": ["max_threads", "batch_size"],
            "properties": {
                "max_threads": {"type": "integer", "minimum": 1, "maximum": 100},
                "batch_size": {"type": "integer", "minimum": 1, "maximum": 10000},
                "enable_concurrent_processing": {"type": "boolean"},
                "cache_size": {"type": "integer", "minimum": 100, "maximum": 100000},
                "cache_ttl": {"type": "integer", "minimum": 60, "maximum": 86400},
                "use_async_processing": {"type": "boolean"},
                "max_connections": {"type": "integer", "minimum": 1, "maximum": 1000},
                "connection_pool_size": {"type": "integer", "minimum": 1, "maximum": 100}
            }
        },
        "database_optimization": {
            "type": "object",
            "properties": {
                "use_sqlite": {"type": "boolean"},
                "cache_size": {"type": "integer", "minimum": 100, "maximum": 100000},
                "enable_streaming": {"type": "boolean"},
                "batch_insert_size": {"type": "integer", "minimum": 10, "maximum": 10000},
                "enable_indexing": {"type": "boolean"}
            }
        },
        "files": {
            "type": "object",
            "required": ["cve_output", "last_update", "database_dir"],
            "properties": {
                "cve_output": {"type": "string", "pattern": ".*\\.jsonl?$"},
                "last_update": {"type": "string", "pattern": ".*\\.txt$"},
                "database_dir": {"type": "string"}
            }
        },
        "logging": {
            "type": "object",
            "required": ["level"],
            "properties": {
                "level": {"type": "string", "enum": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]},
                "format": {"type": "string"},
                "file": {"type": "string", "pattern": ".*\\.log$"},
                "json_file": {"type": "string", "pattern": ".*\\.json$"},
                "max_file_size": {"type": "integer", "minimum": 1024, "maximum": 1073741824},
                "backup_count": {"type": "integer", "minimum": 1, "maximum": 50}
            }
        },
        "error_handling": {
            "type": "object",
            "properties": {
                "enable_circuit_breaker": {"type": "boolean"},
                "enable_retry": {"type": "boolean"},
                "enable_recovery": {"type": "boolean"},
                "alert_thresholds": {
                    "type": "object",
                    "properties": {
                        "critical": {"type": "integer", "minimum": 1, "maximum": 100},
                        "high": {"type": "integer", "minimum": 1, "maximum": 1000},
                        "medium": {"type": "integer", "minimum": 1, "maximum": 10000},
                        "low": {"type": "integer", "minimum": 1, "maximum": 100000}
                    }
                },
                "retry_configs": {
                    "type": "object",
                    "patternProperties": {
                        ".*": {
                            "type": "object",
                            "properties": {
                                "max_attempts": {"type": "integer", "minimum": 1, "maximum": 10},
                                "base_delay": {"type": "number", "minimum": 0.1, "maximum": 60},
                                "max_delay": {"type": "number", "minimum": 0.1, "maximum": 300},
                                "strategy": {"type": "string", "enum": ["fixed", "exponential", "linear", "random"]}
                            }
                        }
                    }
                },
                "circuit_breaker_configs": {
                    "type": "object",
                    "patternProperties": {
                        ".*": {
                            "type": "object",
                            "properties": {
                                "failure_threshold": {"type": "integer", "minimum": 1, "maximum": 100},
                                "recovery_timeout": {"type": "number", "minimum": 1, "maximum": 3600}
                            }
                        }
                    }
                }
            }
        }
    },
    "additionalProperties": False
}

class ConfigValidator:
    """Configuration validator with JSON schema support"""
    
    def __init__(self, schema: Dict[str, Any] = None):
        self.schema = schema or CONFIG_SCHEMA
        self.errors: List[str] = []
        self.warnings: List[str] = []
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate configuration against schema
        
        Args:
            config: Configuration dictionary to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        self.errors.clear()
        self.warnings.clear()
        
        # Basic validation
        if not self._validate_required_fields(config):
            return False
        
        # Type validation
        if not self._validate_types(config):
            return False
        
        # Range validation
        if not self._validate_ranges(config):
            return False
        
        # Format validation
        if not self._validate_formats(config):
            return False
        
        # Custom validation rules
        if not self._validate_custom_rules(config):
            return False
        
        return len(self.errors) == 0
    
    def _validate_required_fields(self, config: Dict[str, Any]) -> bool:
        """Validate required fields are present"""
        required_fields = ["api", "database", "processing", "files", "logging"]
        
        for field in required_fields:
            if field not in config:
                self.errors.append(f"Missing required field: {field}")
                return False
        
        # Validate nested required fields
        api_required = ["nvd"]
        for field in api_required:
            if field not in config.get("api", {}):
                self.errors.append(f"Missing required API field: {field}")
                return False
        
        database_required = ["capec", "cwe", "techniques"]
        for field in database_required:
            if field not in config.get("database", {}):
                self.errors.append(f"Missing required database field: {field}")
                return False
        
        return True
    
    def _validate_types(self, config: Dict[str, Any]) -> bool:
        """Validate data types"""
        valid = True
        
        # Validate API configuration
        api_config = config.get("api", {})
        if "nvd" in api_config:
            nvd_config = api_config["nvd"]
            if not isinstance(nvd_config.get("timeout"), (int, float)):
                self.errors.append("API NVD timeout must be a number")
                valid = False
            if not isinstance(nvd_config.get("retry_limit"), int):
                self.errors.append("API NVD retry_limit must be an integer")
                valid = False
        
        # Validate processing configuration
        processing_config = config.get("processing", {})
        if not isinstance(processing_config.get("max_threads"), int):
            self.errors.append("Processing max_threads must be an integer")
            valid = False
        if not isinstance(processing_config.get("batch_size"), int):
            self.errors.append("Processing batch_size must be an integer")
            valid = False
        
        return valid
    
    def _validate_ranges(self, config: Dict[str, Any]) -> bool:
        """Validate value ranges"""
        valid = True
        
        # Validate API timeouts
        api_config = config.get("api", {})
        if "nvd" in api_config:
            nvd_config = api_config["nvd"]
            timeout = nvd_config.get("timeout")
            if timeout is not None and (timeout < 1 or timeout > 300):
                self.errors.append("API NVD timeout must be between 1 and 300 seconds")
                valid = False
        
        # Validate processing limits
        processing_config = config.get("processing", {})
        max_threads = processing_config.get("max_threads")
        if max_threads is not None and (max_threads < 1 or max_threads > 100):
            self.errors.append("Processing max_threads must be between 1 and 100")
            valid = False
        
        batch_size = processing_config.get("batch_size")
        if batch_size is not None and (batch_size < 1 or batch_size > 10000):
            self.errors.append("Processing batch_size must be between 1 and 10000")
            valid = False
        
        return valid
    
    def _validate_formats(self, config: Dict[str, Any]) -> bool:
        """Validate string formats"""
        valid = True
        
        # Validate URLs
        api_config = config.get("api", {})
        if "nvd" in api_config:
            base_url = api_config["nvd"].get("base_url", "")
            if base_url and not base_url.startswith(("http://", "https://")):
                self.errors.append("API NVD base_url must be a valid HTTP/HTTPS URL")
                valid = False
        
        # Validate file extensions
        files_config = config.get("files", {})
        cve_output = files_config.get("cve_output", "")
        if cve_output and not cve_output.endswith((".json", ".jsonl")):
            self.errors.append("Files cve_output must have .json or .jsonl extension")
            valid = False
        
        return valid
    
    def _validate_custom_rules(self, config: Dict[str, Any]) -> bool:
        """Validate custom business rules"""
        valid = True
        
        # Check for reasonable configuration combinations
        processing_config = config.get("processing", {})
        max_threads = processing_config.get("max_threads", 0)
        batch_size = processing_config.get("batch_size", 0)
        
        if max_threads > batch_size:
            self.warnings.append("max_threads is greater than batch_size, which may be inefficient")
        
        # Check API rate limits
        api_config = config.get("api", {})
        if "nvd" in api_config:
            retry_limit = api_config["nvd"].get("retry_limit", 0)
            retry_delay = api_config["nvd"].get("retry_delay", 0)
            
            if retry_limit * retry_delay > 60:
                self.warnings.append("Total retry time may exceed 60 seconds")
        
        return valid
    
    def get_errors(self) -> List[str]:
        """Get validation errors"""
        return self.errors.copy()
    
    def get_warnings(self) -> List[str]:
        """Get validation warnings"""
        return self.warnings.copy()
    
    def get_validation_report(self) -> Dict[str, Any]:
        """Get comprehensive validation report"""
        return {
            "valid": len(self.errors) == 0,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "errors": self.errors,
            "warnings": self.warnings
        }

def validate_config_file(config_path: str) -> Dict[str, Any]:
    """
    Validate a configuration file
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Validation report dictionary
    """
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        validator = ConfigValidator()
        is_valid = validator.validate_config(config)
        
        report = validator.get_validation_report()
        report["config_path"] = config_path
        
        return report
        
    except FileNotFoundError:
        return {
            "valid": False,
            "error_count": 1,
            "warning_count": 0,
            "errors": [f"Configuration file not found: {config_path}"],
            "warnings": [],
            "config_path": config_path
        }
    except json.JSONDecodeError as e:
        return {
            "valid": False,
            "error_count": 1,
            "warning_count": 0,
            "errors": [f"Invalid JSON in configuration file: {e}"],
            "warnings": [],
            "config_path": config_path
        }
    except Exception as e:
        return {
            "valid": False,
            "error_count": 1,
            "warning_count": 0,
            "errors": [f"Error validating configuration: {e}"],
            "warnings": [],
            "config_path": config_path
        }

def create_default_config_with_validation() -> Dict[str, Any]:
    """Create a default configuration and validate it"""
    from config import Config
    
    # Create default config using existing Config class
    config = Config()
    default_config = config._get_default_config()
    
    # Validate it
    validator = ConfigValidator()
    is_valid = validator.validate_config(default_config)
    
    if not is_valid:
        logger.error("Default configuration is invalid!")
        for error in validator.get_errors():
            logger.error(f"  - {error}")
    
    return {
        "config": default_config,
        "valid": is_valid,
        "errors": validator.get_errors(),
        "warnings": validator.get_warnings()
    }

# Convenience function for easy integration
def validate_config(config: Dict[str, Any]) -> bool:
    """Quick validation of configuration dictionary"""
    validator = ConfigValidator()
    return validator.validate_config(config)
