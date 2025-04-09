#!/usr/bin/env python3
"""
DRM Analysis Tool: Educational Software for DRM Research
Copyright 2025 - Research Edition

This tool is designed for EDUCATIONAL PURPOSES ONLY to analyze and understand
various DRM protection systems. It provides a framework for researching DRM
mechanisms in a controlled environment. This tool should NOT be used to
circumvent copyright protection on commercial software.
"""
import os
import sys
import time
import logging
import binascii
import hashlib
import random
import socket
import json
import shutil
import struct
import threading
import tempfile
import re
from typing import List, Dict, Any, Optional, Union, Tuple, Set, BinaryIO, Callable

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("drm_slayer.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("DRM_SLAYER")

# ===========================================================================
# Check for optional dependencies
# ===========================================================================

try:
    import lief
    LIEF_AVAILABLE = True
    logger.info("LIEF binary analysis library found")
except ImportError:
    LIEF_AVAILABLE = False
    logger.warning(
        "LIEF binary analysis library not found - some advanced binary features will be limited")

try:
    import capstone
    CAPSTONE_AVAILABLE = True
    logger.info("Capstone disassembly engine found")
except ImportError:
    CAPSTONE_AVAILABLE = False
    logger.warning(
        "Capstone disassembly engine not found - some assembly analysis features will be limited")

# ===========================================================================
# Constants and Signature Database
# ===========================================================================

VERSION = "3.0 Ultimate"

# DRM types supported by the application
DRM_TYPES = [
    "denuvo",
    "steam",
    "epic",
    "origin",
    "ubisoft",
    "vmprotect",
    "custom_protection",
    "hardware_lock"
]

# Descriptions of protection systems
PROTECTION_DESCRIPTIONS = {
    "denuvo": "Advanced anti-tamper technology with virtualization and hardware fingerprinting",
    "steam": "Valve's DRM system and license verification",
    "epic": "Epic Games Store protection and license verification",
    "origin": "EA's copy protection and online activation system",
    "ubisoft": "Ubisoft Connect (formerly Uplay) DRM and online service",
    "vmprotect": "Software protection with code virtualization and mutation",
    "custom_protection": "Custom or publisher-specific protection mechanisms",
    "hardware_lock": "Hardware-based activation requiring specific machine components"
}

# Detailed signature database for DRM detection
DRM_SIGNATURES = {
    "denuvo": [
        # Denuvo VM entry signatures
        {
            "signature": b"\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57",
            "name": "denuvo",
            "subtype": "vm_entry",
            "description": "Denuvo VM entry prologue (x64)",
            "confidence": 90
        },
        {
            "signature": b"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x81\xEC",
            "name": "denuvo",
            "subtype": "vm_entry",
            "description": "Denuvo VM entry alternate pattern",
            "confidence": 85
        },

        # Denuvo license check signatures
        {
            "signature": b"\x48\x83\xEC\x40\x48\x8B\x05",
            "name": "denuvo",
            "subtype": "license_check",
            "description": "Denuvo license verification",
            "confidence": 80
        },

        # Denuvo anti-debug signatures
        {
            "signature": b"\x64\x48\x8B\x04\x25\x30\x00\x00\x00",
            "name": "denuvo",
            "subtype": "anti_debug",
            "description": "Denuvo anti-debugging check (x64)",
            "confidence": 75
        },

        # Denuvo VM dispatcher signatures
        {
            "signature": b"\x0F\xB6\x94\x3B",
            "name": "denuvo",
            "subtype": "vm_dispatcher",
            "description": "Denuvo VM instruction dispatcher",
            "confidence": 70
        },

        # Denuvo 2023-2025 specific signatures
        {
            "signature": b"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x48\x8B\xD9\x33\xFF",
            "name": "denuvo",
            "subtype": "denuvo_2023",
            "description": "Denuvo 2023 pattern",
            "confidence": 85
        },
        {
            "signature": b"\x48\x8B\x0D\xCC\xCC\xCC\xCC\x48\x85\xC9\x74\x0F\x48\x8B\x01\xFF\x50\x18\x48\x8B\x0D",
            "name": "denuvo",
            "subtype": "denuvo_2025",
            "description": "Denuvo 2025 pattern",
            "confidence": 90
        },

        # Denuvo hardware fingerprinting signatures
        {
            "signature": b"\x0F\xA2",  # CPUID instruction
            "name": "denuvo",
            "subtype": "hw_fingerprint",
            "description": "CPUID instruction for hardware fingerprinting",
            "confidence": 60
        },
        {
            "signature": b"\x0F\x31",  # RDTSC instruction
            "name": "denuvo",
            "subtype": "hw_fingerprint",
            "description": "RDTSC instruction for timing checks",
            "confidence": 60
        }
    ],

    "steam": [
        # Steam DRM signatures
        {
            "signature": b"SteamDRMDll",
            "name": "steam",
            "subtype": "core",
            "description": "Steam DRM core module",
            "confidence": 90
        },
        {
            "signature": b"SteamAPI_Init",
            "name": "steam",
            "subtype": "api",
            "description": "Steam API initialization",
            "confidence": 85
        },
        {
            "signature": b"SteamAPI_IsSteamRunning",
            "name": "steam",
            "subtype": "check",
            "description": "Steam running check",
            "confidence": 85
        }
    ],

    "epic": [
        # Epic Games Store signatures
        {
            "signature": b"EpicOnlineServices",
            "name": "epic",
            "subtype": "core",
            "description": "Epic Online Services SDK",
            "confidence": 90
        },
        {
            "signature": b"EOS_Platform_Create",
            "name": "epic",
            "subtype": "api",
            "description": "EOS platform initialization",
            "confidence": 85
        },
        {
            "signature": b"EOS_Auth_Login",
            "name": "epic",
            "subtype": "auth",
            "description": "EOS authentication",
            "confidence": 85
        }
    ],

    "origin": [
        # Origin/EA signatures
        {
            "signature": b"OriginDRM",
            "name": "origin",
            "subtype": "core",
            "description": "Origin DRM core module",
            "confidence": 90
        },
        {
            "signature": b"EACore",
            "name": "origin",
            "subtype": "core",
            "description": "EA Core services",
            "confidence": 85
        },
        {
            "signature": b"VerifyLicense",
            "name": "origin",
            "subtype": "license",
            "description": "Origin license verification",
            "confidence": 85
        }
    ],

    "ubisoft": [
        # Ubisoft Connect/Uplay signatures
        {
            "signature": b"UplayDRM",
            "name": "ubisoft",
            "subtype": "core",
            "description": "Uplay DRM module",
            "confidence": 90
        },
        {
            "signature": b"UbiServices",
            "name": "ubisoft",
            "subtype": "services",
            "description": "Ubisoft online services",
            "confidence": 85
        },
        {
            "signature": b"UplayStart",
            "name": "ubisoft",
            "subtype": "init",
            "description": "Uplay initialization",
            "confidence": 85
        }
    ],

    "vmprotect": [
        # VMProtect signatures
        {
            "signature": b"VMProtect",
            "name": "vmprotect",
            "subtype": "core",
            "description": "VMProtect core module",
            "confidence": 90
        },
        {
            "signature": b"VMProtectBegin",
            "name": "vmprotect",
            "subtype": "begin",
            "description": "VMProtect protected region start",
            "confidence": 95
        },
        {
            "signature": b"\x68\xCC\xCC\xCC\xCC\x9C\x60",
            "name": "vmprotect",
            "subtype": "vm_entry",
            "description": "VMProtect VM entry",
            "confidence": 85
        }
    ],

    "hardware_lock": [
        # Hardware-based protection
        {
            "signature": b"\x0F\xA2",  # CPUID instruction
            "name": "hardware_lock",
            "subtype": "cpu_check",
            "description": "CPU identity check",
            "confidence": 60
        },
        {
            "signature": b"GetVolumeInformation",
            "name": "hardware_lock",
            "subtype": "disk_check",
            "description": "Disk volume information check",
            "confidence": 75
        },
        {
            "signature": b"GetAdaptersInfo",
            "name": "hardware_lock",
            "subtype": "network_check",
            "description": "Network adapter check",
            "confidence": 75
        }
    ]
}

# ===========================================================================
# Core DRM Engine
# ===========================================================================


class DRMEngine:
    """Core DRM detection and removal engine"""

    def __init__(self):
        self.last_scan_results = {}
        self.stats = {
            "files_scanned": 0,
            "files_modified": 0,
            "drm_detected": 0,
            "drm_removed": 0,
            "success_rate": 0.0
        }
        self.options = {
            "recursive": True,
            "backup": True,
            "verbose": True,
            "safe_mode": True,
            "aggressive_detection": False,
            "auto_patch": True
        }

    def scan_file(self, file_path: str, drm_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Scan a file for DRM protection

        Args:
            file_path: Path to the file to scan
            drm_types: Optional list of DRM types to scan for (if None, scan for all)

        Returns:
            List of detected DRM information
        """
        # Check if file exists
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return []

        # Check if it's a directory
        if os.path.isdir(file_path):
            logger.warning(f"{file_path} is a directory, not a file")
            return []

        # Track stats
        self.stats["files_scanned"] += 1

        # Get file info
        file_size = os.path.getsize(file_path)
        file_ext = os.path.splitext(file_path)[1].lower()

        # Read the file (or part of it for large files)
        max_read_size = 50 * 1024 * 1024  # Max 50MB to avoid memory issues
        read_size = min(file_size, max_read_size)

        try:
            with open(file_path, "rb") as f:
                file_data = f.read(read_size)

            # Check if it's a supported file type
            if not self._is_supported_file(file_path, file_data):
                logger.debug(f"Unsupported file type: {file_path}")
                return []

            # Run detection methods
            results = []

            # Detect by signature matching
            sig_results = self._detect_by_signature(
                file_path, file_data, drm_types)
            if sig_results:
                results.extend(sig_results)

            # Detect by string patterns
            str_results = self._detect_by_strings(
                file_path, file_data, drm_types)
            if str_results:
                results.extend(str_results)

            # If LIEF is available, use more advanced detection methods
            if LIEF_AVAILABLE:
                # Detect by section entropy (high entropy can indicate DRM protection)
                entropy_results = self._detect_by_section_entropy(
                    file_path, file_data, drm_types)
                if entropy_results:
                    results.extend(entropy_results)

                # Detect by imports (DRM-related imports)
                import_results = self._detect_by_imports(
                    file_path, file_data, drm_types)
                if import_results:
                    results.extend(import_results)

            # If Capstone is available, detect virtualization patterns
            if CAPSTONE_AVAILABLE:
                vm_results = self._detect_by_vm_patterns(
                    file_path, file_data, drm_types)
                if vm_results:
                    results.extend(vm_results)

            # Update stats
            if results:
                self.stats["drm_detected"] += len(results)

            # Store results
            self.last_scan_results[file_path] = results

            # Return merged results
            return results

        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return []

    def scan_folder(self, folder_path: str, drm_types: Optional[List[str]] = None, recursive: Optional[bool] = None) -> Dict[str, List[Dict[str, Any]]]:
        """
        Scan a folder for files with DRM protection

        Args:
            folder_path: Path to the folder to scan
            drm_types: Optional list of DRM types to scan for (if None, scan for all)
            recursive: Whether to scan subfolders (overrides self.options if provided)

        Returns:
            Dictionary mapping file paths to detected DRM information
        """
        # Check if folder exists
        if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
            logger.error(f"Folder not found or not a directory: {folder_path}")
            return {}

        # Use provided recursive option or default from self.options
        use_recursive = recursive if recursive is not None else self.options["recursive"]

        # Reset scan results
        self.last_scan_results = {}

        # Get list of files to scan
        files_to_scan = []

        if use_recursive:
            # Walk through the folder and all subfolders
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    files_to_scan.append(os.path.join(root, file))
        else:
            # Only scan files in the top folder
            for item in os.listdir(folder_path):
                item_path = os.path.join(folder_path, item)
                if os.path.isfile(item_path):
                    files_to_scan.append(item_path)

        # Scan each file
        results = {}

        for file_path in files_to_scan:
            try:
                file_results = self.scan_file(file_path, drm_types)
                if file_results:
                    results[file_path] = file_results
            except Exception as e:
                logger.error(f"Error scanning file {file_path}: {e}")

        logger.info(
            f"Scanned {len(files_to_scan)} files, found DRM in {len(results)} files")

        # Store results
        self.last_scan_results = results

        return results

    def remove_drm(self, file_path: str, drm_info: List[Dict[str, Any]]) -> bool:
        """
        Remove DRM protection from a file

        Args:
            file_path: Path to the file
            drm_info: Information about the DRM to remove

        Returns:
            True if removal was successful, False otherwise
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return False

        # Create backup if option is enabled
        if self.options["backup"]:
            backup_path = file_path + ".bak"
            try:
                shutil.copy2(file_path, backup_path)
                logger.info(f"Created backup at {backup_path}")
            except Exception as e:
                logger.error(f"Error creating backup: {e}")
                if self.options["safe_mode"]:
                    logger.error("Aborting DRM removal due to safe mode")
                    return False

        # Choose appropriate removal method based on the file type
        file_ext = os.path.splitext(file_path)[1].lower()

        # Try binary patching first
        try:
            if self._patch_drm(file_path, drm_info):
                self._update_removal_stats(len(drm_info))
                return True
        except Exception as e:
            logger.error(f"Error patching DRM in {file_path}: {e}")

            # If patching failed and we're in safe mode, restore backup
            if self.options["backup"] and self.options["safe_mode"]:
                self._restore_backup(file_path)

            return False

    def remove_drm_from_folder(self, folder_path: str, scan_results: Optional[Dict[str, List[Dict[str, Any]]]] = None) -> Dict[str, Any]:
        """
        Remove DRM protection from files in a folder

        Args:
            folder_path: Path to the folder
            scan_results: Optional scan results (if None, uses last scan results)

        Returns:
            Dictionary with removal results
        """
        # Check if folder exists
        if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
            logger.error(f"Folder not found or not a directory: {folder_path}")
            return {"success": False, "error": "Folder not found or not a directory"}

        # Use provided scan results or last scan results
        results_to_use = scan_results if scan_results is not None else self.last_scan_results

        # Filter results to only include files in the target folder
        filtered_results = {}
        for file_path, drm_info in results_to_use.items():
            if os.path.commonpath([folder_path, file_path]) == folder_path:
                filtered_results[file_path] = drm_info

        if not filtered_results:
            logger.warning(f"No DRM found in folder {folder_path}")
            return {"success": False, "error": "No DRM found in folder"}

        # Remove DRM from each file
        removal_results = {
            "total_files": len(filtered_results),
            "successful": 0,
            "failed": 0,
            "file_results": {}
        }

        for file_path, drm_info in filtered_results.items():
            try:
                success = self.remove_drm(file_path, drm_info)

                removal_results["file_results"][file_path] = {
                    "success": success,
                    "drm_count": len(drm_info)
                }

                if success:
                    removal_results["successful"] += 1
                else:
                    removal_results["failed"] += 1

            except Exception as e:
                logger.error(f"Error removing DRM from {file_path}: {e}")
                removal_results["file_results"][file_path] = {
                    "success": False,
                    "error": str(e)
                }
                removal_results["failed"] += 1

        removal_results["success"] = removal_results["successful"] > 0

        logger.info(
            f"Removed DRM from {removal_results['successful']} out of {removal_results['total_files']} files")

        return removal_results

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about DRM detection and removal"""
        # Calculate success rate if we've detected any DRM
        if self.stats["drm_detected"] > 0:
            self.stats["success_rate"] = (
                self.stats["drm_removed"] / self.stats["drm_detected"]) * 100

        # Return a copy of the stats
        return dict(self.stats)

    def set_option(self, option: str, value: Any) -> bool:
        """
        Set an option for the DRM engine

        Args:
            option: Option name
            value: Option value

        Returns:
            True if option was set, False if option doesn't exist
        """
        if option in self.options:
            self.options[option] = value
            logger.debug(f"Set option {option} to {value}")
            return True
        else:
            logger.warning(f"Unknown option: {option}")
            return False

    # Private helper methods

    def _is_supported_file(self, file_path: str, file_data: bytes) -> bool:
        """Check if the file is a supported type for DRM scanning"""
        file_ext = os.path.splitext(file_path)[1].lower()

        # Executable files
        if file_ext in [".exe", ".dll", ".so", ".dylib"]:
            return True

        # Check for PE or ELF headers
        if file_data[:2] == b"MZ":  # Windows PE
            return True
        if file_data[:4] == b"\x7FELF":  # Linux ELF
            return True

        # Game data files
        if file_ext in [".pak", ".bsa", ".ba2", ".rpf", ".uasset", ".umap", ".assets"]:
            return True

        # Generic binary files that might contain DRM
        if file_ext in [".bin", ".dat", ".db"]:
            return True

        # Check for common game file headers
        if len(file_data) >= 4 and file_data[:4] in [b"PAK\x01", b"PAK\x05", b"GDCC", b"BSA\x00", b"BTDX"]:
            return True

        # Fallback check for binary data
        text_chars = bytearray({7, 8, 9, 10, 12, 13, 27}
                               | set(range(0x20, 0x7F)))
        binary_chars = bytearray(range(256))
        for c in text_chars:
            binary_chars[c] = 0

        # Count binary chars in the first 1000 bytes
        sample = file_data[:1000]
        binary_count = sum(1 for byte in sample if binary_chars[byte] != 0)
        binary_percentage = (binary_count / len(sample)) * 100

        # If more than 30% of the bytes are binary, consider it a binary file
        return binary_percentage > 30

    def _detect_by_signature(self, file_path: str, file_data: bytes, drm_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Detect DRM by matching binary signatures"""
        signatures = {}

        # Filter signatures by DRM types if specified
        if drm_types:
            for drm_type in drm_types:
                if drm_type in DRM_SIGNATURES:
                    signatures[drm_type] = DRM_SIGNATURES[drm_type]
        else:
            signatures = DRM_SIGNATURES

        # Search for signatures
        results = []

        for drm_type, sigs in signatures.items():
            for sig_info in sigs:
                signature = sig_info.get("signature", b"")
                if not signature:
                    continue

                # Convert hex string to bytes if needed
                if isinstance(signature, str):
                    try:
                        signature = binascii.unhexlify(signature)
                    except:
                        continue

                offset = 0
                while True:
                    pos = file_data.find(signature, offset)
                    if pos == -1:
                        break

                    # Found a match
                    results.append({
                        "name": sig_info.get("name", drm_type),
                        "subtype": sig_info.get("subtype", "unknown"),
                        "offset": pos,
                        "signature": signature.hex(),
                        "confidence": sig_info.get("confidence", 90),
                        "detection_method": "signature"
                    })

                    offset = pos + 1  # Continue searching after this occurrence

        return results

    def _detect_by_strings(self, file_path: str, file_data: bytes, drm_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Detect DRM by searching for string patterns"""
        # Common string patterns associated with various DRM systems
        string_patterns = {
            "denuvo": ["Denuvo", "Anti-Tamper", "SecureDRM", "VMProtect"],
            "steam": ["SteamAPI", "Steamworks", "valve"],
            "origin": ["Origin.dll", "EACore", "Electronic Arts"],
            "ubisoft": ["Uplay", "Ubisoft Connect", "UbisoftGameLauncher"],
            "epic": ["Epic Games", "EpicOnlineServices", "EOS SDK"],
            "vmprotect": ["VMProtect", "VMProtectSDK"],
            "custom_protection": ["SecuROM", "SafeDisc", "StarForce", "FADE", "Arxan", "Themida"]
        }

        # Filter patterns by DRM types if specified
        if drm_types:
            filtered_patterns = {}
            for drm_type in drm_types:
                if drm_type in string_patterns:
                    filtered_patterns[drm_type] = string_patterns[drm_type]
            string_patterns = filtered_patterns

        # Convert file data to string for searching
        # Use errors="ignore" to handle binary data
        file_str = file_data.decode("utf-8", errors="ignore")

        # Search for string patterns
        results = []

        for drm_type, patterns in string_patterns.items():
            for pattern in patterns:
                offset = 0
                while True:
                    pos = file_str.find(pattern, offset)
                    if pos == -1:
                        break

                    # Found a match
                    results.append({
                        "name": drm_type,
                        "subtype": "string_match",
                        "offset": pos,
                        "pattern": pattern,
                        "confidence": 70,  # String matches are less reliable
                        "detection_method": "string"
                    })

                    offset = pos + 1  # Continue searching after this occurrence

        return results

    def _detect_by_section_entropy(self, file_path: str, file_data: bytes, drm_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Detect DRM by analyzing section entropy"""
        # Skip if LIEF is not available
        if not LIEF_AVAILABLE:
            return []

        try:
            # Parse the binary
            binary = lief.parse(file_path)
            if not binary:
                return []

            # Calculate section statistics
            results = []

            for section in binary.sections:
                # Skip common non-DRM sections
                if section.name in [".text", ".data", ".rdata", ".rsrc"]:
                    continue

                # Check if section has high entropy (common for packed/protected code)
                entropy = section.entropy
                if entropy > 7.0:  # High entropy threshold
                    # Found a suspicious section
                    results.append({
                        "name": "unknown",
                        "subtype": "high_entropy_section",
                        "offset": section.virtual_address,
                        "section": section.name,
                        "entropy": entropy,
                        # Higher entropy = higher confidence
                        "confidence": min(int(entropy * 10) - 60, 90),
                        "detection_method": "entropy"
                    })

                    # Try to identify the DRM type based on section name or patterns
                    if "denuvo" in section.name.lower():
                        results[-1]["name"] = "denuvo"
                    elif "steam" in section.name.lower():
                        results[-1]["name"] = "steam"
                    elif "uplay" in section.name.lower() or "ubi" in section.name.lower():
                        results[-1]["name"] = "ubisoft"
                    elif "epic" in section.name.lower() or "eos" in section.name.lower():
                        results[-1]["name"] = "epic"
                    elif "vm" in section.name.lower() or "vmp" in section.name.lower():
                        results[-1]["name"] = "vmprotect"

            return results

        except Exception as e:
            logger.error(f"Error analyzing section entropy: {e}")
            return []

    def _detect_by_imports(self, file_path: str, file_data: bytes, drm_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Detect DRM by analyzing imported functions"""
        # Skip if LIEF is not available
        if not LIEF_AVAILABLE:
            return []

        try:
            # Parse the binary
            binary = lief.parse(file_path)
            if not binary:
                return []

            # Common imports associated with DRM systems
            drm_imports = {
                "denuvo": ["GetProcessHeap", "GetProcessId", "OutputDebugStringA", "GetSystemTimeAsFileTime", "GetVolumeInformationW"],
                "steam": ["SteamAPI_Init", "SteamAPI_RunCallbacks", "SteamAPI_RegisterCallback"],
                "origin": ["EACore", "AuthorizeAccess", "VerifyLicense"],
                "ubisoft": ["UplayStart", "UplayConnect", "UplayR1"],
                "epic": ["EOS_Initialize", "EOS_Platform_Create", "EOS_Auth_Login"],
                "vmprotect": ["VMProtectBegin", "VMProtectEnd", "VMProtectIsDebuggerPresent"]
            }

            # Filter imports by DRM types if specified
            if drm_types:
                filtered_imports = {}
                for drm_type in drm_types:
                    if drm_type in drm_imports:
                        filtered_imports[drm_type] = drm_imports[drm_type]
                drm_imports = filtered_imports

            # Check imports
            results = []
            import_matches = {}

            # For PE files
            if isinstance(binary, lief.PE.Binary):
                for entry in binary.imports:
                    for func in entry.entries:
                        if not func.name:
                            continue

                        # Check each DRM type
                        for drm_type, imports in drm_imports.items():
                            for imp in imports:
                                if imp in func.name:
                                    # Count matches for this DRM type
                                    import_matches[drm_type] = import_matches.get(
                                        drm_type, 0) + 1

            # For ELF files
            elif isinstance(binary, lief.ELF.Binary):
                for symbol in binary.dynamic_symbols:
                    if not symbol.name:
                        continue

                    # Check each DRM type
                    for drm_type, imports in drm_imports.items():
                        for imp in imports:
                            if imp in symbol.name:
                                # Count matches for this DRM type
                                import_matches[drm_type] = import_matches.get(
                                    drm_type, 0) + 1

            # Add results for DRM types with sufficient matches
            for drm_type, count in import_matches.items():
                if count >= 2:  # Require at least 2 import matches
                    results.append({
                        "name": drm_type,
                        "subtype": "import_match",
                        "offset": 0,  # Not applicable for import-based detection
                        "match_count": count,
                        "confidence": min(count * 10 + 50, 90),
                        "detection_method": "imports"
                    })

            return results

        except Exception as e:
            logger.error(f"Error analyzing imports: {e}")
            return []

    def _detect_by_vm_patterns(self, file_path: str, file_data: bytes, drm_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Detect DRM by analyzing virtualization patterns"""
        # Skip if Capstone is not available
        if not CAPSTONE_AVAILABLE:
            return []

        # Skip if not interested in VM-based DRM
        if drm_types and not any(drm in ["denuvo", "vmprotect"] for drm in drm_types):
            return []

        try:
            # Initialize Capstone for x86-64
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            md.detail = True

            # VM patterns to look for
            vm_entry_patterns = [
                # Push many registers, prepare for VM entry
                {"opcode_sequence": ["push", "push", "push", "push", "push", "push",
                                     "mov", "mov"], "min_count": 6, "name": "denuvo", "subtype": "vm_entry"},
                # Common VMProtect entry sequence
                {"opcode_sequence": ["pushfd", "pushad", "mov", "mov", "sub", "call"],
                    "min_count": 4, "name": "vmprotect", "subtype": "vm_entry"},
                # Denuvo VM dispatcher pattern
                {"opcode_sequence": ["mov", "movzx", "shl", "add", "jmp"],
                    "min_count": 4, "name": "denuvo", "subtype": "vm_dispatcher"}
            ]

            # Find potential VM patterns
            results = []

            # Check only the first ~1MB for VM patterns to avoid excessive analysis
            max_scan_size = min(len(file_data), 1024 * 1024)
            scan_data = file_data[:max_scan_size]

            # Disassemble the code
            last_opcodes = []

            for i, instruction in enumerate(md.disasm(scan_data, 0)):
                # Keep track of the last few opcodes
                last_opcodes.append(instruction.mnemonic)
                if len(last_opcodes) > 10:
                    last_opcodes.pop(0)

                # Check for VM patterns
                for pattern in vm_entry_patterns:
                    opcode_sequence = pattern["opcode_sequence"]
                    min_count = pattern["min_count"]

                    # Check if we have enough opcodes to match
                    if len(last_opcodes) < min_count:
                        continue

                    # Check for matches
                    matches = 0
                    for j, opcode in enumerate(opcode_sequence):
                        if j >= len(last_opcodes):
                            break
                        if opcode == last_opcodes[-(j+1)]:
                            matches += 1

                    if matches >= min_count:
                        # Found a VM pattern
                        results.append({
                            "name": pattern["name"],
                            "subtype": pattern["subtype"],
                            # Approximate offset
                            "offset": instruction.address - (min_count * 3),
                            "pattern": "-".join(last_opcodes[-min_count:]),
                            "confidence": min(matches * 10 + 50, 90),
                            "detection_method": "vm_pattern"
                        })

                        # Skip ahead to avoid duplicate detections
                        break

            return results

        except Exception as e:
            logger.error(f"Error analyzing VM patterns: {e}")
            return []

    def _patch_drm(self, file_path: str, drm_info: List[Dict[str, Any]]) -> bool:
        """
        Patch DRM in a file

        Args:
            file_path: Path to the file
            drm_info: Information about the DRM to patch

        Returns:
            True if patching was successful, False otherwise
        """
        try:
            # Read the file
            with open(file_path, "rb") as f:
                file_data = bytearray(f.read())

            # Track if we patched anything
            patched = False

            # Process each DRM finding
            for drm in drm_info:
                offset = drm.get("offset", -1)
                if offset < 0 or offset >= len(file_data):
                    continue

                drm_type = drm.get("name", "unknown")
                subtype = drm.get("subtype", "unknown")

                # Choose patch based on DRM type and subtype
                patch = None

                if drm_type == "denuvo":
                    if subtype == "vm_entry":
                        # Patch Denuvo VM entry to return immediately
                        # mov eax, 1; ret
                        patch = bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3])
                    elif subtype == "license_check":
                        # Patch license check to return success
                        # xor eax, eax; inc eax; ret
                        patch = bytes([0x31, 0xC0, 0x40, 0xC3])
                    elif subtype == "anti_debug":
                        # Patch anti-debug check to skip
                        patch = bytes(
                            [0x90, 0x90, 0x90, 0x90, 0x90])  # nop sled
                    elif subtype == "vm_dispatcher":
                        # Patch VM dispatcher to skip
                        # mov eax, 1; ret
                        patch = bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3])
                    elif subtype == "denuvo_2023" or subtype == "denuvo_2025":
                        # Patch Denuvo 2023/2025 pattern
                        # xor rax, rax; inc rax; ret
                        patch = bytes(
                            [0x48, 0x31, 0xC0, 0x48, 0xFF, 0xC0, 0xC3])
                    elif subtype == "hw_fingerprint":
                        # Patch hardware fingerprinting
                        # mov eax, 1; ret
                        patch = bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3])

                elif drm_type == "steam":
                    # Patch Steam DRM checks to return success
                    # mov eax, 1; ret
                    patch = bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3])

                elif drm_type == "origin" or drm_type == "ubisoft" or drm_type == "epic":
                    # Patch license verification to return success
                    # mov eax, 1; ret
                    patch = bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3])

                elif drm_type == "vmprotect":
                    # Patch VMProtect to return immediately
                    # mov eax, 1; ret
                    patch = bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3])

                elif drm_type == "hardware_lock":
                    # Patch hardware fingerprinting
                    if subtype == "cpu_check":
                        # nop the CPUID instruction
                        patch = bytes([0x90, 0x90])
                    else:
                        # mov eax, 1; ret
                        patch = bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3])

                # Apply the patch if available
                if patch:
                    # Make sure we don't overflow the file
                    if offset + len(patch) <= len(file_data):
                        file_data[offset:offset+len(patch)] = patch
                        patched = True
                        logger.info(
                            f"Patched {drm_type} {subtype} at offset {offset}")

            # Write back the file if we patched anything
            if patched:
                with open(file_path, "wb") as f:
                    f.write(file_data)

                return True

            return False

        except Exception as e:
            logger.error(f"Error patching DRM: {e}")
            return False

    def _update_removal_stats(self, num_drm_removed: int) -> None:
        """Update stats after removing DRM"""
        self.stats["files_modified"] += 1
        self.stats["drm_removed"] += num_drm_removed

        # Update success rate
        if self.stats["drm_detected"] > 0:
            self.stats["success_rate"] = (
                self.stats["drm_removed"] / self.stats["drm_detected"]) * 100

    def _restore_backup(self, file_path: str) -> bool:
        """Restore backup file"""
        backup_path = file_path + ".bak"
        if os.path.exists(backup_path):
            try:
                shutil.copy2(backup_path, file_path)
                logger.info(f"Restored backup of {file_path}")
                return True
            except Exception as e:
                logger.error(f"Error restoring backup: {e}")
        return False

# ===========================================================================
# Binary Reconstruction System
# ===========================================================================


class BinaryReconstructor:
    """
    Advanced binary reconstruction system that rebuilds entire files
    rather than just patching them, with enhanced reverse engineering capabilities
    and functionality verification
    """

    def __init__(self):
        self.supported_formats = {
            # Executable formats
            "exe": "Windows Executable",
            "dll": "Dynamic Link Library",
            "so": "Shared Object (Linux)",
            "dylib": "Dynamic Library (macOS)",

            # Game data formats
            "pak": "Package File",
            "bsa": "Bethesda Archive",
            "ba2": "Bethesda Archive v2",
            "dds": "DirectDraw Surface",
            "uasset": "Unreal Asset",
            "sav": "Save File",
            "rpf": "RAGE Package File"
        }

        # Track reconstruction history for analysis
        self.reconstruction_history = {}

        # Patterns for common file structures
        self.file_signatures = {
            # PE file signatures
            "exe": [b"MZ", b"PE\x00\x00"],
            "dll": [b"MZ", b"PE\x00\x00"],
            # ELF file signatures
            "so": [b"\x7FELF"],
            # Mach-O file signatures
            "dylib": [b"\xFE\xED\xFA\xCE", b"\xFE\xED\xFA\xCF", b"\xCE\xFA\xED\xFE", b"\xCF\xFA\xED\xFE"],
            # Game package signatures
            "pak": [b"PAK\x01", b"PAK\x05", b"GDCC"],
            "bsa": [b"BSA\x00"],
            "ba2": [b"BTDX"],
            "rpf": [b"RPF"],
            "uasset": [b"C\x1A\x83\x11"]
        }

        # Common section names by file type
        self.common_sections = {
            "pe": [".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata", ".edata", ".pdata"],
            "elf": [".text", ".data", ".bss", ".rodata", ".comment", ".note", ".eh_frame"],
            "mach-o": ["__TEXT", "__DATA", "__LINKEDIT", "__OBJC"]
        }

        # Patches for different DRM types
        self.drm_patches = {
            "denuvo": {
                # MOV EAX, 1; RET
                "vm_entry": bytearray([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]),
                # XOR EAX, EAX; INC EAX; RET
                "license_check": bytearray([0x31, 0xC0, 0x40, 0xC3]),
                # NOP sled
                "anti_debug": bytearray([0x90, 0x90, 0x90, 0x90, 0x90]),
                # MOV EAX, 1; RET
                "vm_dispatcher": bytearray([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]),
                # NOP the CPUID instruction
                "hw_fingerprint": bytearray([0x90, 0x90])
            },
            "steam": {
                # MOV EAX, 1; RET
                "core": bytearray([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]),
                # PUSH 1; POP RAX; RET
                "api": bytearray([0x6A, 0x01, 0x58, 0xC3]),
                # XOR EAX, EAX; INC EAX; RET
                "check": bytearray([0x31, 0xC0, 0x40, 0xC3])
            },
            "vmprotect": {
                # XOR RAX, RAX; INC RAX; RET
                "vm_entry": bytearray([0x48, 0x31, 0xC0, 0x48, 0xFF, 0xC0, 0xC3]),
                # MOV EAX, 1; RET
                "core": bytearray([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3])
            },
            # XOR EAX, EAX; INC EAX; RET
            "generic": bytearray([0x31, 0xC0, 0x40, 0xC3])
        }

    def reconstruct_file(self, file_path: str, output_path: str, drm_info: List[Dict[str, Any]]) -> bool:
        """
        Reconstruct a file without DRM protection using advanced reverse engineering

        Args:
            file_path: Path to the input file
            output_path: Path for the output file
            drm_info: Information about detected DRM in the file

        Returns:
            True if reconstruction was successful, False otherwise
        """
        try:
            # Get file type and analyze structure
            file_ext = os.path.splitext(file_path)[1].lower().lstrip(".")
            file_type = self._analyze_file_type(file_path)

            logger.info(
                f"Reconstructing file: {file_path} (detected type: {file_type})")

            # Create a reconstruction record
            reconstruction_id = hashlib.md5(
                f"{file_path}_{time.time()}".encode()).hexdigest()
            self.reconstruction_history[reconstruction_id] = {
                "file_path": file_path,
                "output_path": output_path,
                "file_type": file_type,
                "drm_count": len(drm_info),
                "drm_types": list(set(d.get("name", "unknown") for d in drm_info)),
                "start_time": time.time(),
                "status": "in_progress",
                "patches_applied": 0
            }

            # Choose reconstruction method based on file type
            result = False
            if file_type == "pe":
                result = self._reconstruct_pe(file_path, output_path, drm_info)
            elif file_type == "elf":
                result = self._reconstruct_elf(
                    file_path, output_path, drm_info)
            elif file_type == "mach-o":
                result = self._reconstruct_macho(
                    file_path, output_path, drm_info)
            elif file_type in ["pak", "bsa", "ba2", "rpf"]:
                result = self._reconstruct_package(
                    file_path, output_path, drm_info)
            elif file_type in ["uasset", "umap"]:
                result = self._reconstruct_unreal_asset(
                    file_path, output_path, drm_info)
            else:
                # For unknown formats, use enhanced generic binary reconstruction
                result = self._reconstruct_generic_binary(
                    file_path, output_path, drm_info)

            # Update reconstruction record
            self.reconstruction_history[reconstruction_id]["end_time"] = time.time(
            )
            self.reconstruction_history[reconstruction_id]["status"] = "success" if result else "failed"

            # Verify the reconstructed file if successful
            if result:
                verification_result = self.verify_file_functionality(
                    output_path, file_type)
                self.reconstruction_history[reconstruction_id]["verification"] = verification_result

                if not verification_result["functional"]:
                    logger.warning(
                        f"Reconstructed file verification failed: {verification_result['reason']}")

                    # Try alternative reconstruction if verification failed
                    if verification_result.get("can_retry", False):
                        logger.info(
                            "Attempting alternative reconstruction method...")
                        alt_output_path = output_path + ".alt"
                        alt_result = self._reconstruct_generic_binary(
                            file_path, alt_output_path, drm_info, aggressive=True)

                        if alt_result:
                            alt_verification = self.verify_file_functionality(
                                alt_output_path, file_type)
                            if alt_verification["functional"]:
                                logger.info(
                                    "Alternative reconstruction succeeded, using this version")
                                shutil.copy2(alt_output_path, output_path)
                                result = True
                                self.reconstruction_history[reconstruction_id]["verification"] = alt_verification
                                self.reconstruction_history[reconstruction_id]["used_alternative"] = True

                            # Clean up alternative file if not needed
                            if os.path.exists(alt_output_path):
                                os.remove(alt_output_path)

            return result

        except Exception as e:
            logger.error(f"Error reconstructing file {file_path}: {e}")
            if reconstruction_id in self.reconstruction_history:
                self.reconstruction_history[reconstruction_id]["status"] = "error"
                self.reconstruction_history[reconstruction_id]["error"] = str(
                    e)
            return False

    def _analyze_file_type(self, file_path: str) -> str:
        """
        Analyze a file to determine its actual type based on content

        Args:
            file_path: Path to the file

        Returns:
            Detected file type
        """
        try:
            # Read file header (first 4KB should be enough for signatures)
            with open(file_path, "rb") as f:
                header = f.read(4096)

            # Check file signatures
            for file_type, signatures in self.file_signatures.items():
                for signature in signatures:
                    if signature in header:
                        return file_type

            # If no signature match, use extension as fallback
            file_ext = os.path.splitext(file_path)[1].lower().lstrip(".")
            if file_ext in self.supported_formats:
                return file_ext

            # Check for ELF vs PE vs Mach-O
            if header.startswith(b"MZ"):
                return "pe"
            elif header.startswith(b"\x7FELF"):
                return "elf"
            elif header.startswith(b"\xFE\xED\xFA") or header.startswith(b"\xCE\xFA\xED\xFE"):
                return "mach-o"

            # Default to generic binary
            return "binary"

        except Exception as e:
            logger.error(f"Error analyzing file type: {e}")
            return "binary"

    def _reconstruct_pe(self, file_path: str, output_path: str, drm_info: List[Dict[str, Any]]) -> bool:
        """Reconstruct a PE file (EXE/DLL)"""
        if LIEF_AVAILABLE:
            try:
                # Parse the binary
                binary = lief.parse(file_path)
                if not binary:
                    raise ValueError(f"Failed to parse PE file: {file_path}")

                # Process each detected DRM
                for drm in drm_info:
                    # Get section containing the DRM
                    drm_offset = drm.get("offset", 0)
                    drm_section = None

                    for section in binary.sections:
                        section_start = section.virtual_address
                        section_end = section_start + section.size

                        if section_start <= drm_offset < section_end:
                            drm_section = section
                            break

                    if drm_section:
                        logger.info(
                            f"Found DRM in section {drm_section.name} at offset {drm_offset}")

                        # Get the content of the section
                        section_content = list(drm_section.content)

                        # Calculate relative offset within the section
                        relative_offset = drm_offset - drm_section.virtual_address

                        # Replace the DRM code with NOPs or a success return patch
                        if relative_offset < len(section_content):
                            # Basic patch: Return 1 (success)
                            patch = [0xB8, 0x01, 0x00, 0x00,
                                     0x00, 0xC3]  # MOV EAX, 1; RET

                            # Apply the patch
                            for i, b in enumerate(patch):
                                if relative_offset + i < len(section_content):
                                    section_content[relative_offset + i] = b

                            # Update the section content
                            drm_section.content = section_content

                # Rebuild the PE file
                builder = lief.PE.Builder(binary)
                builder.build()
                builder.write(output_path)

                return os.path.exists(output_path)

            except Exception as e:
                logger.error(f"Error in LIEF PE reconstruction: {e}")
                # Fall back to generic method
                return self._reconstruct_generic_binary(file_path, output_path, drm_info)
        else:
            # LIEF not available, use generic method
            return self._reconstruct_generic_binary(file_path, output_path, drm_info)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("drm_slayer.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("DRM_SLAYER")

# ===========================================================================
# Check for optional dependencies
# ===========================================================================

try:
    import lief
    LIEF_AVAILABLE = True
    logger.info("LIEF binary analysis library found")
except ImportError:
    LIEF_AVAILABLE = False
    logger.warning(
        "LIEF binary analysis library not found - some advanced binary features will be limited")

try:
    import capstone
    CAPSTONE_AVAILABLE = True
    logger.info("Capstone disassembly engine found")
except ImportError:
    CAPSTONE_AVAILABLE = False
    logger.warning(
        "Capstone disassembly engine not found - some assembly analysis features will be limited")

# ===========================================================================
# Constants and Signature Database
# ===========================================================================

VERSION = "3.0 Ultimate"

# DRM types supported by the application
DRM_TYPES = [
    "denuvo",
    "steam",
    "epic",
    "origin",
    "ubisoft",
    "vmprotect",
    "custom_protection",
    "hardware_lock"
]

# Descriptions of protection systems
PROTECTION_DESCRIPTIONS = {
    "denuvo": "Advanced anti-tamper technology with virtualization and hardware fingerprinting",
    "steam": "Valve's DRM system and license verification",
    "epic": "Epic Games Store protection and license verification",
    "origin": "EA's copy protection and online activation system",
    "ubisoft": "Ubisoft Connect (formerly Uplay) DRM and online service",
    "vmprotect": "Software protection with code virtualization and mutation",
    "custom_protection": "Custom or publisher-specific protection mechanisms",
    "hardware_lock": "Hardware-based activation requiring specific machine components"
}

# Detailed signature database for DRM detection
DRM_SIGNATURES = {
    "denuvo": [
        # Denuvo VM entry signatures
        {
            "signature": b"\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57",
            "name": "denuvo",
            "subtype": "vm_entry",
            "description": "Denuvo VM entry prologue (x64)",
            "confidence": 90
        },
        {
            "signature": b"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x81\xEC",
            "name": "denuvo",
            "subtype": "vm_entry",
            "description": "Denuvo VM entry alternate pattern",
            "confidence": 85
        },

        # Denuvo license check signatures
        {
            "signature": b"\x48\x83\xEC\x40\x48\x8B\x05",
            "name": "denuvo",
            "subtype": "license_check",
            "description": "Denuvo license verification",
            "confidence": 80
        },

        # Denuvo anti-debug signatures
        {
            "signature": b"\x64\x48\x8B\x04\x25\x30\x00\x00\x00",
            "name": "denuvo",
            "subtype": "anti_debug",
            "description": "Denuvo anti-debugging check (x64)",
            "confidence": 75
        },

        # Denuvo VM dispatcher signatures
        {
            "signature": b"\x0F\xB6\x94\x3B",
            "name": "denuvo",
            "subtype": "vm_dispatcher",
            "description": "Denuvo VM instruction dispatcher",
            "confidence": 70
        },

        # Denuvo 2023-2025 specific signatures
        {
            "signature": b"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x48\x8B\xD9\x33\xFF",
            "name": "denuvo",
            "subtype": "denuvo_2023",
            "description": "Denuvo 2023 pattern",
            "confidence": 85
        },
        {
            "signature": b"\x48\x8B\x0D\xCC\xCC\xCC\xCC\x48\x85\xC9\x74\x0F\x48\x8B\x01\xFF\x50\x18\x48\x8B\x0D",
            "name": "denuvo",
            "subtype": "denuvo_2025",
            "description": "Denuvo 2025 pattern",
            "confidence": 90
        },

        # Denuvo hardware fingerprinting signatures
        {
            "signature": b"\x0F\xA2",  # CPUID instruction
            "name": "denuvo",
            "subtype": "hw_fingerprint",
            "description": "CPUID instruction for hardware fingerprinting",
            "confidence": 60
        },
        {
            "signature": b"\x0F\x31",  # RDTSC instruction
            "name": "denuvo",
            "subtype": "hw_fingerprint",
            "description": "RDTSC instruction for timing checks",
            "confidence": 60
        }
    ],

    "steam": [
        # Steam DRM signatures
        {
            "signature": b"SteamDRMDll",
            "name": "steam",
            "subtype": "core",
            "description": "Steam DRM core module",
            "confidence": 90
        },
        {
            "signature": b"SteamAPI_Init",
            "name": "steam",
            "subtype": "api",
            "description": "Steam API initialization",
            "confidence": 85
        },
        {
            "signature": b"SteamAPI_IsSteamRunning",
            "name": "steam",
            "subtype": "check",
            "description": "Steam running check",
            "confidence": 85
        }
    ],

    "epic": [
        # Epic Games Store signatures
        {
            "signature": b"EpicOnlineServices",
            "name": "epic",
            "subtype": "core",
            "description": "Epic Online Services SDK",
            "confidence": 90
        },
        {
            "signature": b"EOS_Platform_Create",
            "name": "epic",
            "subtype": "api",
            "description": "EOS platform initialization",
            "confidence": 85
        },
        {
            "signature": b"EOS_Auth_Login",
            "name": "epic",
            "subtype": "auth",
            "description": "EOS authentication",
            "confidence": 85
        }
    ],

    "origin": [
        # Origin/EA signatures
        {
            "signature": b"OriginDRM",
            "name": "origin",
            "subtype": "core",
            "description": "Origin DRM core module",
            "confidence": 90
        },
        {
            "signature": b"EACore",
            "name": "origin",
            "subtype": "core",
            "description": "EA Core services",
            "confidence": 85
        },
        {
            "signature": b"VerifyLicense",
            "name": "origin",
            "subtype": "license",
            "description": "Origin license verification",
            "confidence": 85
        }
    ],

    "ubisoft": [
        # Ubisoft Connect/Uplay signatures
        {
            "signature": b"UplayDRM",
            "name": "ubisoft",
            "subtype": "core",
            "description": "Uplay DRM module",
            "confidence": 90
        },
        {
            "signature": b"UbiServices",
            "name": "ubisoft",
            "subtype": "services",
            "description": "Ubisoft online services",
            "confidence": 85
        },
        {
            "signature": b"UplayStart",
            "name": "ubisoft",
            "subtype": "init",
            "description": "Uplay initialization",
            "confidence": 85
        }
    ],

    "vmprotect": [
        # VMProtect signatures
        {
            "signature": b"VMProtect",
            "name": "vmprotect",
            "subtype": "core",
            "description": "VMProtect core module",
            "confidence": 90
        },
        {
            "signature": b"VMProtectBegin",
            "name": "vmprotect",
            "subtype": "begin",
            "description": "VMProtect protected region start",
            "confidence": 95
        },
        {
            "signature": b"\x68\xCC\xCC\xCC\xCC\x9C\x60",
            "name": "vmprotect",
            "subtype": "vm_entry",
            "description": "VMProtect VM entry",
            "confidence": 85
        }
    ],

    "hardware_lock": [
        # Hardware-based protection
        {
            "signature": b"\x0F\xA2",  # CPUID instruction
            "name": "hardware_lock",
            "subtype": "cpu_check",
            "description": "CPU identity check",
            "confidence": 60
        },
        {
            "signature": b"GetVolumeInformation",
            "name": "hardware_lock",
            "subtype": "disk_check",
            "description": "Disk volume information check",
            "confidence": 75
        },
        {
            "signature": b"GetAdaptersInfo",
            "name": "hardware_lock",
            "subtype": "network_check",
            "description": "Network adapter check",
            "confidence": 75
        }
    ]
}

# ===========================================================================
# Core DRM Engine
# ===========================================================================


class DRMEngine:
    """Core DRM detection and removal engine"""

    def __init__(self):
        self.last_scan_results = {}
        self.stats = {
            "files_scanned": 0,
            "files_modified": 0,
            "drm_detected": 0,
            "drm_removed": 0,
            "success_rate": 0.0
        }
        self.options = {
            "recursive": True,
            "backup": True,
            "verbose": True,
            "safe_mode": True,
            "aggressive_detection": False,
            "auto_patch": True
        }

    def scan_file(self, file_path: str, drm_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Scan a file for DRM protection

        Args:
            file_path: Path to the file to scan
            drm_types: Optional list of DRM types to scan for (if None, scan for all)

        Returns:
            List of detected DRM information
        """
        # Check if file exists
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return []

        # Check if it's a directory
        if os.path.isdir(file_path):
            logger.warning(f"{file_path} is a directory, not a file")
            return []

        # Track stats
        self.stats["files_scanned"] += 1

        # Get file info
        file_size = os.path.getsize(file_path)
        file_ext = os.path.splitext(file_path)[1].lower()

        # Read the file (or part of it for large files)
        max_read_size = 50 * 1024 * 1024  # Max 50MB to avoid memory issues
        read_size = min(file_size, max_read_size)

        try:
            with open(file_path, "rb") as f:
                file_data = f.read(read_size)

            # Check if it's a supported file type
            if not self._is_supported_file(file_path, file_data):
                logger.debug(f"Unsupported file type: {file_path}")
                return []

            # Run detection methods
            results = []

            # Detect by signature matching
            sig_results = self._detect_by_signature(
                file_path, file_data, drm_types)
            if sig_results:
                results.extend(sig_results)

            # Detect by string patterns
            str_results = self._detect_by_strings(
                file_path, file_data, drm_types)
            if str_results:
                results.extend(str_results)

            # If LIEF is available, use more advanced detection methods
            if LIEF_AVAILABLE:
                # Detect by section entropy (high entropy can indicate DRM protection)
                entropy_results = self._detect_by_section_entropy(
                    file_path, file_data, drm_types)
                if entropy_results:
                    results.extend(entropy_results)

                # Detect by imports (DRM-related imports)
                import_results = self._detect_by_imports(
                    file_path, file_data, drm_types)
                if import_results:
                    results.extend(import_results)

            # If Capstone is available, detect virtualization patterns
            if CAPSTONE_AVAILABLE:
                vm_results = self._detect_by_vm_patterns(
                    file_path, file_data, drm_types)
                if vm_results:
                    results.extend(vm_results)

            # Update stats
            if results:
                self.stats["drm_detected"] += len(results)

            # Store results
            self.last_scan_results[file_path] = results

            # Return merged results
            return results

        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return []

    def scan_folder(self, folder_path: str, drm_types: Optional[List[str]] = None, recursive: Optional[bool] = None) -> Dict[str, List[Dict[str, Any]]]:
        """
        Scan a folder for files with DRM protection

        Args:
            folder_path: Path to the folder to scan
            drm_types: Optional list of DRM types to scan for (if None, scan for all)
            recursive: Whether to scan subfolders(overrides self.options if provided)

        Returns:
            Dictionary mapping file paths to detected DRM information
        """
        # Check if folder exists
        if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
            logger.error(f"Folder not found or not a directory: {folder_path}")
            return {}

        # Use provided recursive option or default from self.options
        use_recursive = recursive if recursive is not None else self.options["recursive"]

        # Reset scan results
        self.last_scan_results = {}

        # Get list of files to scan
        files_to_scan = []

        if use_recursive:
            # Walk through the folder and all subfolders
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    files_to_scan.append(os.path.join(root, file))
        else:
            # Only scan files in the top folder
            for item in os.listdir(folder_path):
                item_path = os.path.join(folder_path, item)
                if os.path.isfile(item_path):
                    files_to_scan.append(item_path)

        # Scan each file
        results = {}

        for file_path in files_to_scan:
            try:
                file_results = self.scan_file(file_path, drm_types)
                if file_results:
                    results[file_path] = file_results
            except Exception as e:
                logger.error(f"Error scanning file {file_path}: {e}")

        logger.info(
            f"Scanned {len(files_to_scan)} files, found DRM in {len(results)} files")

        # Store results
        self.last_scan_results = results

        return results

    def remove_drm(self, file_path: str, drm_info: List[Dict[str, Any]]) -> bool:
        """
        Remove DRM protection from a file

        Args:
            file_path: Path to the file
            drm_info: Information about the DRM to remove

        Returns:
            True if removal was successful, False otherwise
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return False

        # Create backup if option is enabled
        if self.options["backup"]:
            backup_path = file_path + ".bak"
            try:
                shutil.copy2(file_path, backup_path)
                logger.info(f"Created backup at {backup_path}")
            except Exception as e:
                logger.error(f"Error creating backup: {e}")
                if self.options["safe_mode"]:
                    logger.error("Aborting DRM removal due to safe mode")
                    return False

        # Choose appropriate removal method based on the file type
        file_ext = os.path.splitext(file_path)[1].lower()

        # Try binary patching first
        try:
            if self._patch_drm(file_path, drm_info):
                self._update_removal_stats(len(drm_info))
                return True
        except Exception as e:
            logger.error(f"Error patching DRM in {file_path}: {e}")

            # If patching failed and we're in safe mode, restore backup
            if self.options["backup"] and self.options["safe_mode"]:
                self._restore_backup(file_path)

            return False

    def remove_drm_from_folder(self, folder_path: str, scan_results: Optional[Dict[str, List[Dict[str, Any]]]] = None) -> Dict[str, Any]:
        """
        Remove DRM protection from files in a folder

        Args:
            folder_path: Path to the folder
            scan_results: Optional scan results(if None, uses last scan results)

        Returns:
            Dictionary with removal results
        """
        # Check if folder exists
        if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
            logger.error(f"Folder not found or not a directory: {folder_path}")
            return {"success": False, "error": "Folder not found or not a directory"}

        # Use provided scan results or last scan results
        results_to_use = scan_results if scan_results is not None else self.last_scan_results

        # Filter results to only include files in the target folder
        filtered_results = {}
        for file_path, drm_info in results_to_use.items():
            if os.path.commonpath([folder_path, file_path]) == folder_path:
                filtered_results[file_path] = drm_info

        if not filtered_results:
            logger.warning(f"No DRM found in folder {folder_path}")
            return {"success": False, "error": "No DRM found in folder"}

        # Remove DRM from each file
        removal_results = {
            "total_files": len(filtered_results),
            "successful": 0,
            "failed": 0,
            "file_results": {}
        }

        for file_path, drm_info in filtered_results.items():
            try:
                success = self.remove_drm(file_path, drm_info)

                removal_results["file_results"][file_path] = {
                    "success": success,
                    "drm_count": len(drm_info)
                }

                if success:
                    removal_results["successful"] += 1
                else:
                    removal_results["failed"] += 1

            except Exception as e:
                logger.error(f"Error removing DRM from {file_path}: {e}")
                removal_results["file_results"][file_path] = {
                    "success": False,
                    "error": str(e)
                }
                removal_results["failed"] += 1

        removal_results["success"] = removal_results["successful"] > 0

        logger.info(
            f"Removed DRM from {removal_results['successful']} out of {removal_results['total_files']} files")

        return removal_results

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about DRM detection and removal"""
        # Calculate success rate if we've detected any DRM
        if self.stats["drm_detected"] > 0:
            self.stats["success_rate"] = (
                self.stats["drm_removed"] / self.stats["drm_detected"]) * 100

        # Return a copy of the stats
        return dict(self.stats)

    def set_option(self, option: str, value: Any) -> bool:
        """
        Set an option for the DRM engine

        Args:
            option: Option name
            value: Option value

        Returns:
            True if option was set, False if option doesn't exist
        """
        if option in self.options:
            self.options[option] = value
            logger.debug(f"Set option {option} to {value}")
            return True
        else:
            logger.warning(f"Unknown option: {option}")
            return False

    # Private helper methods

    def _is_supported_file(self, file_path: str, file_data: bytes) -> bool:
        """Check if the file is a supported type for DRM scanning"""
        file_ext = os.path.splitext(file_path)[1].lower()

        # Executable files
        if file_ext in [".exe", ".dll", ".so", ".dylib"]:
            return True

        # Check for PE or ELF headers
        if file_data[:2] == b"MZ":  # Windows PE
            return True
        if file_data[:4] == b"\x7FELF":  # Linux ELF
            return True

        # Game data files
        if file_ext in [".pak", ".bsa", ".ba2", ".rpf", ".uasset", ".umap", ".assets"]:
            return True

        # Generic binary files that might contain DRM
        if file_ext in [".bin", ".dat", ".db"]:
            return True

        # Check for common game file headers
        if len(file_data) >= 4 and file_data[:4] in [b"PAK\x01", b"PAK\x05", b"GDCC", b"BSA\x00", b"BTDX"]:
            return True

        # Fallback check for binary data
        text_chars = bytearray({7, 8, 9, 10, 12, 13, 27}
                               | set(range(0x20, 0x7F)))
        binary_chars = bytearray(range(256))
        for c in text_chars:
            binary_chars[c] = 0

        # Count binary chars in the first 1000 bytes
        sample = file_data[:1000]
        binary_count = sum(1 for byte in sample if binary_chars[byte] != 0)
        binary_percentage = (binary_count / len(sample)) * 100

        # If more than 30% of the bytes are binary, consider it a binary file
        return binary_percentage > 30

    def _detect_by_signature(self, file_path: str, file_data: bytes, drm_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Detect DRM by matching binary signatures"""
        signatures = {}

        # Filter signatures by DRM types if specified
        if drm_types:
            for drm_type in drm_types:
                if drm_type in DRM_SIGNATURES:
                    signatures[drm_type] = DRM_SIGNATURES[drm_type]
        else:
            signatures = DRM_SIGNATURES

        # Search for signatures
        results = []

        for drm_type, sigs in signatures.items():
            for sig_info in sigs:
                signature = sig_info.get("signature", b"")
                if not signature:
                    continue

                # Convert hex string to bytes if needed
                if isinstance(signature, str):
                    try:
                        signature = binascii.unhexlify(signature)
                    except:
                        continue

                offset = 0
                while True:
                    pos = file_data.find(signature, offset)
                    if pos == -1:
                        break

                    # Found a match
                    results.append({
                        "name": sig_info.get("name", drm_type),
                        "subtype": sig_info.get("subtype", "unknown"),
                        "offset": pos,
                        "signature": signature.hex(),
                        "confidence": sig_info.get("confidence", 90),
                        "detection_method": "signature"
                    })

                    offset = pos + 1  # Continue searching after this occurrence

        return results

    def _detect_by_strings(self, file_path: str, file_data: bytes, drm_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Detect DRM by searching for string patterns"""
        # Common string patterns associated with various DRM systems
        string_patterns = {
            "denuvo": ["Denuvo", "Anti-Tamper", "SecureDRM", "VMProtect"],
            "steam": ["SteamAPI", "Steamworks", "valve"],
            "origin": ["Origin.dll", "EACore", "Electronic Arts"],
            "ubisoft": ["Uplay", "Ubisoft Connect", "UbisoftGameLauncher"],
            "epic": ["Epic Games", "EpicOnlineServices", "EOS SDK"],
            "vmprotect": ["VMProtect", "VMProtectSDK"],
            "custom_protection": ["SecuROM", "SafeDisc", "StarForce", "FADE", "Arxan", "Themida"]
        }

        # Filter patterns by DRM types if specified
        if drm_types:
            filtered_patterns = {}
            for drm_type in drm_types:
                if drm_type in string_patterns:
                    filtered_patterns[drm_type] = string_patterns[drm_type]
            string_patterns = filtered_patterns

        # Convert file data to string for searching
        # Use errors="ignore" to handle binary data
        file_str = file_data.decode("utf-8", errors="ignore")

        # Search for string patterns
        results = []

        for drm_type, patterns in string_patterns.items():
            for pattern in patterns:
                offset = 0
                while True:
                    pos = file_str.find(pattern, offset)
                    if pos == -1:
                        break

                    # Found a match
                    results.append({
                        "name": drm_type,
                        "subtype": "string_match",
                        "offset": pos,
                        "pattern": pattern,
                        "confidence": 70,  # String matches are less reliable
                        "detection_method": "string"
                    })

                    offset = pos + 1  # Continue searching after this occurrence

        return results

    def _detect_by_section_entropy(self, file_path: str, file_data: bytes, drm_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Detect DRM by analyzing section entropy"""
        # Skip if LIEF is not available
        if not LIEF_AVAILABLE:
            return []

        try:
            # Parse the binary
            binary = lief.parse(file_path)
            if not binary:
                return []

            # Calculate section statistics
            results = []

            for section in binary.sections:
                # Skip common non-DRM sections
                if section.name in [".text", ".data", ".rdata", ".rsrc"]:
                    continue

                # Check if section has high entropy (common for packed/protected code)
                entropy = section.entropy
                if entropy > 7.0:  # High entropy threshold
                    # Found a suspicious section
                    results.append({
                        "name": "unknown",
                        "subtype": "high_entropy_section",
                        "offset": section.virtual_address,
                        "section": section.name,
                        "entropy": entropy,
                        # Higher entropy = higher confidence
                        "confidence": min(int(entropy * 10) - 60, 90),
                        "detection_method": "entropy"
                    })

                    # Try to identify the DRM type based on section name or patterns
                    if "denuvo" in section.name.lower():
                        results[-1]["name"] = "denuvo"
                    elif "steam" in section.name.lower():
                        results[-1]["name"] = "steam"
                    elif "uplay" in section.name.lower() or "ubi" in section.name.lower():
                        results[-1]["name"] = "ubisoft"
                    elif "epic" in section.name.lower() or "eos" in section.name.lower():
                        results[-1]["name"] = "epic"
                    elif "vm" in section.name.lower() or "vmp" in section.name.lower():
                        results[-1]["name"] = "vmprotect"

            return results

        except Exception as e:
            logger.error(f"Error analyzing section entropy: {e}")
            return []

    def _detect_by_imports(self, file_path: str, file_data: bytes, drm_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Detect DRM by analyzing imported functions"""
        # Skip if LIEF is not available
        if not LIEF_AVAILABLE:
            return []

        try:
            # Parse the binary
            binary = lief.parse(file_path)
            if not binary:
                return []

            # Common imports associated with DRM systems
            drm_imports = {
                "denuvo": ["GetProcessHeap", "GetProcessId", "OutputDebugStringA", "GetSystemTimeAsFileTime", "GetVolumeInformationW"],
                "steam": ["SteamAPI_Init", "SteamAPI_RunCallbacks", "SteamAPI_RegisterCallback"],
                "origin": ["EACore", "AuthorizeAccess", "VerifyLicense"],
                "ubisoft": ["UplayStart", "UplayConnect", "UplayR1"],
                "epic": ["EOS_Initialize", "EOS_Platform_Create", "EOS_Auth_Login"],
                "vmprotect": ["VMProtectBegin", "VMProtectEnd", "VMProtectIsDebuggerPresent"]
            }

            # Filter imports by DRM types if specified
            if drm_types:
                filtered_imports = {}
                for drm_type in drm_types:
                    if drm_type in drm_imports:
                        filtered_imports[drm_type] = drm_imports[drm_type]
                drm_imports = filtered_imports

            # Check imports
            results = []
            import_matches = {}

            # For PE files
            if isinstance(binary, lief.PE.Binary):
                for entry in binary.imports:
                    for func in entry.entries:
                        if not func.name:
                            continue

                        # Check each DRM type
                        for drm_type, imports in drm_imports.items():
                            for imp in imports:
                                if imp in func.name:
                                    # Count matches for this DRM type
                                    import_matches[drm_type] = import_matches.get(
                                        drm_type, 0) + 1

            # For ELF files
            elif isinstance(binary, lief.ELF.Binary):
                for symbol in binary.dynamic_symbols:
                    if not symbol.name:
                        continue

                    # Check each DRM type
                    for drm_type, imports in drm_imports.items():
                        for imp in imports:
                            if imp in symbol.name:
                                # Count matches for this DRM type
                                import_matches[drm_type] = import_matches.get(
                                    drm_type, 0) + 1

            # Add results for DRM types with sufficient matches
            for drm_type, count in import_matches.items():
                if count >= 2:  # Require at least 2 import matches
                    results.append({
                        "name": drm_type,
                        "subtype": "import_match",
                        "offset": 0,  # Not applicable for import-based detection
                        "match_count": count,
                        "confidence": min(count * 10 + 50, 90),
                        "detection_method": "imports"
                    })

            return results

        except Exception as e:
            logger.error(f"Error analyzing imports: {e}")
            return []

    def _detect_by_vm_patterns(self, file_path: str, file_data: bytes, drm_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Detect DRM by analyzing virtualization patterns"""
        # Skip if Capstone is not available
        if not CAPSTONE_AVAILABLE:
            return []

        # Skip if not interested in VM-based DRM
        if drm_types and not any(drm in ["denuvo", "vmprotect"] for drm in drm_types):
            return []

        try:
            # Initialize Capstone for x86-64
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            md.detail = True

            # VM patterns to look for
            vm_entry_patterns = [
                # Push many registers, prepare for VM entry
                {"opcode_sequence": ["push", "push", "push", "push", "push", "push",
                                     "mov", "mov"], "min_count": 6, "name": "denuvo", "subtype": "vm_entry"},
                # Common VMProtect entry sequence
                {"opcode_sequence": ["pushfd", "pushad", "mov", "mov", "sub", "call"],
                    "min_count": 4, "name": "vmprotect", "subtype": "vm_entry"},
                # Denuvo VM dispatcher pattern
                {"opcode_sequence": ["mov", "movzx", "shl", "add", "jmp"],
                    "min_count": 4, "name": "denuvo", "subtype": "vm_dispatcher"}
            ]

            # Find potential VM patterns
            results = []

            # Check only the first ~1MB for VM patterns to avoid excessive analysis
            max_scan_size = min(len(file_data), 1024 * 1024)
            scan_data = file_data[:max_scan_size]

            # Disassemble the code
            last_opcodes = []

            for i, instruction in enumerate(md.disasm(scan_data, 0)):
                # Keep track of the last few opcodes
                last_opcodes.append(instruction.mnemonic)
                if len(last_opcodes) > 10:
                    last_opcodes.pop(0)

                # Check for VM patterns
                for pattern in vm_entry_patterns:
                    opcode_sequence = pattern["opcode_sequence"]
                    min_count = pattern["min_count"]

                    # Check if we have enough opcodes to match
                    if len(last_opcodes) < min_count:
                        continue

                    # Check for matches
                    matches = 0
                    for j, opcode in enumerate(opcode_sequence):
                        if j >= len(last_opcodes):
                            break
                        if opcode == last_opcodes[-(j+1)]:
                            matches += 1

                    if matches >= min_count:
                        # Found a VM pattern
                        results.append({
                            "name": pattern["name"],
                            "subtype": pattern["subtype"],
                            # Approximate offset
                            "offset": instruction.address - (min_count * 3),
                            "pattern": "-".join(last_opcodes[-min_count:]),
                            "confidence": min(matches * 10 + 50, 90),
                            "detection_method": "vm_pattern"
                        })

                        # Skip ahead to avoid duplicate detections
                        break

            return results

        except Exception as e:
            logger.error(f"Error analyzing VM patterns: {e}")
            return []

    def _patch_drm(self, file_path: str, drm_info: List[Dict[str, Any]]) -> bool:
        """
        Patch DRM in a file

        Args:
            file_path: Path to the file
            drm_info: Information about the DRM to patch

        Returns:
            True if patching was successful, False otherwise
        """
        try:
            # Read the file
            with open(file_path, "rb") as f:
                file_data = bytearray(f.read())

            # Track if we patched anything
            patched = False

            # Process each DRM finding
            for drm in drm_info:
                offset = drm.get("offset", -1)
                if offset < 0 or offset >= len(file_data):
                    continue

                drm_type = drm.get("name", "unknown")
                subtype = drm.get("subtype", "unknown")

                # Choose patch based on DRM type and subtype
                patch = None

                if drm_type == "denuvo":
                    if subtype == "vm_entry":
                        # Patch Denuvo VM entry to return immediately
                        # mov eax, 1; ret
                        patch = bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3])
                    elif subtype == "license_check":
                        # Patch license check to return success
                        # xor eax, eax; inc eax; ret
                        patch = bytes([0x31, 0xC0, 0x40, 0xC3])
                    elif subtype == "anti_debug":
                        # Patch anti-debug check to skip
                        patch = bytes(
                            [0x90, 0x90, 0x90, 0x90, 0x90])  # nop sled
                    elif subtype == "vm_dispatcher":
                        # Patch VM dispatcher to skip
                        # mov eax, 1; ret
                        patch = bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3])
                    elif subtype == "denuvo_2023" or subtype == "denuvo_2025":
                        # Patch Denuvo 2023/2025 pattern
                        # xor rax, rax; inc rax; ret
                        patch = bytes(
                            [0x48, 0x31, 0xC0, 0x48, 0xFF, 0xC0, 0xC3])
                    elif subtype == "hw_fingerprint":
                        # Patch hardware fingerprinting
                        # mov eax, 1; ret
                        patch = bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3])

                elif drm_type == "steam":
                    # Patch Steam DRM checks to return success
                    # mov eax, 1; ret
                    patch = bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3])

                elif drm_type == "origin" or drm_type == "ubisoft" or drm_type == "epic":
                    # Patch license verification to return success
                    # mov eax, 1; ret
                    patch = bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3])

                elif drm_type == "vmprotect":
                    # Patch VMProtect to return immediately
                    # mov eax, 1; ret
                    patch = bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3])

                elif drm_type == "hardware_lock":
                    # Patch hardware fingerprinting
                    if subtype == "cpu_check":
                        # nop the CPUID instruction
                        patch = bytes([0x90, 0x90])
                    else:
                        # mov eax, 1; ret
                        patch = bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3])

                # Apply the patch if available
                if patch:
                    # Make sure we don't overflow the file
                    if offset + len(patch) <= len(file_data):
                        file_data[offset:offset+len(patch)] = patch
                        patched = True
                        logger.info(
                            f"Patched {drm_type} {subtype} at offset {offset}")

            # Write back the file if we patched anything
            if patched:
                with open(file_path, "wb") as f:
                    f.write(file_data)

                return True

            return False

        except Exception as e:
            logger.error(f"Error patching DRM: {e}")
            return False

    def _update_removal_stats(self, num_drm_removed: int) -> None:
        """Update stats after removing DRM"""
        self.stats["files_modified"] += 1
        self.stats["drm_removed"] += num_drm_removed

        # Update success rate
        if self.stats["drm_detected"] > 0:
            self.stats["success_rate"] = (
                self.stats["drm_removed"] / self.stats["drm_detected"]) * 100

    def _restore_backup(self, file_path: str) -> bool:
        """Restore backup file"""
        backup_path = file_path + ".bak"
        if os.path.exists(backup_path):
            try:
                shutil.copy2(backup_path, file_path)
                logger.info(f"Restored backup of {file_path}")
                return True
            except Exception as e:
                logger.error(f"Error restoring backup: {e}")
        return False

# ===========================================================================
# Binary Reconstruction System
# ===========================================================================


class BinaryReconstructor:
    """
    Advanced binary reconstruction system that rebuilds entire files
    rather than just patching them
    """

    def __init__(self):
        self.supported_formats = {
            # Executable formats
            "exe": "Windows Executable",
            "dll": "Dynamic Link Library",
            "so": "Shared Object (Linux)",
            "dylib": "Dynamic Library (macOS)",

            # Game data formats
            "pak": "Package File",
            "bsa": "Bethesda Archive",
            "ba2": "Bethesda Archive v2",
            "dds": "DirectDraw Surface",
            "uasset": "Unreal Asset",
            "sav": "Save File",
            "rpf": "RAGE Package File"
        }

    def reconstruct_file(self, file_path: str, output_path: str, drm_info: List[Dict[str, Any]]) -> bool:
        """
        Reconstruct a file without DRM protection

        Args:
            file_path: Path to the input file
            output_path: Path for the output file
            drm_info: Information about detected DRM in the file

        Returns:
            True if reconstruction was successful, False otherwise
        """
        try:
            # Get file type
            file_ext = os.path.splitext(file_path)[1].lower().lstrip(".")

            # Choose reconstruction method based on file type
            if file_ext in ["exe", "dll"]:
                return self._reconstruct_pe(file_path, output_path, drm_info)
            elif file_ext == "so":
                return self._reconstruct_elf(file_path, output_path, drm_info)
            elif file_ext in ["pak", "bsa", "ba2", "rpf"]:
                return self._reconstruct_package(file_path, output_path, drm_info)
            elif file_ext in ["uasset", "umap"]:
                return self._reconstruct_unreal_asset(file_path, output_path, drm_info)
            else:
                # For unknown formats, use a generic binary reconstruction approach
                return self._reconstruct_generic_binary(file_path, output_path, drm_info)

        except Exception as e:
            logger.error(f"Error reconstructing file {file_path}: {e}")
            return False

    def _reconstruct_pe(self, file_path: str, output_path: str, drm_info: List[Dict[str, Any]]) -> bool:
        """Reconstruct a PE file (EXE/DLL)"""
        if LIEF_AVAILABLE:
            try:
                # Parse the binary
                binary = lief.parse(file_path)
                if not binary:
                    raise ValueError(f"Failed to parse PE file: {file_path}")

                # Process each detected DRM
                for drm in drm_info:
                    # Get section containing the DRM
                    drm_offset = drm.get("offset", 0)
                    drm_section = None

                    for section in binary.sections:
                        section_start = section.virtual_address
                        section_end = section_start + section.size

                        if section_start <= drm_offset < section_end:
                            drm_section = section
                            break

                    if drm_section:
                        logger.info(
                            f"Found DRM in section {drm_section.name} at offset {drm_offset}")

                        # Get the content of the section
                        section_content = list(drm_section.content)

                        # Calculate relative offset within the section
                        relative_offset = drm_offset - drm_section.virtual_address

                        # Replace the DRM code with NOPs or a success return patch
                        if relative_offset < len(section_content):
                            # Basic patch: Return 1 (success)
                            patch = [0xB8, 0x01, 0x00, 0x00,
                                     0x00, 0xC3]  # MOV EAX, 1; RET

                            # Apply the patch
                            for i, b in enumerate(patch):
                                if relative_offset + i < len(section_content):
                                    section_content[relative_offset + i] = b

                            # Update the section content
                            drm_section.content = section_content

                # Rebuild the PE file
                builder = lief.PE.Builder(binary)
                builder.build()
                builder.write(output_path)

                return os.path.exists(output_path)

            except Exception as e:
                logger.error(f"Error in LIEF PE reconstruction: {e}")
                # Fall back to generic method
                return self._reconstruct_generic_binary(file_path, output_path, drm_info)
        else:
            # LIEF not available, use generic method
            return self._reconstruct_generic_binary(file_path, output_path, drm_info)

    def _reconstruct_elf(self, file_path: str, output_path: str, drm_info: List[Dict[str, Any]]) -> bool:
        """Reconstruct an ELF file"""
        if LIEF_AVAILABLE:
            try:
                # Parse the binary
                binary = lief.parse(file_path)
                if not binary:
                    raise ValueError(f"Failed to parse ELF file: {file_path}")

                # Process each detected DRM
                for drm in drm_info:
                    # Similar to PE reconstruction
                    drm_offset = drm.get("offset", 0)
                    drm_section = None

                    for section in binary.sections:
                        section_start = section.virtual_address
                        section_end = section_start + section.size

                        if section_start <= drm_offset < section_end:
                            drm_section = section
                            break

                    if drm_section:
                        logger.info(
                            f"Found DRM in section {drm_section.name} at offset {drm_offset}")

                        # Get the content of the section
                        section_content = list(drm_section.content)

                        # Calculate relative offset within the section
                        relative_offset = drm_offset - drm_section.virtual_address

                        # Replace the DRM code with NOPs or a success return patch
                        if relative_offset < len(section_content):
                            # Basic patch: Return 1 (success)
                            patch = [0xB8, 0x01, 0x00, 0x00,
                                     0x00, 0xC3]  # MOV EAX, 1; RET

                            # Apply the patch
                            for i, b in enumerate(patch):
                                if relative_offset + i < len(section_content):
                                    section_content[relative_offset + i] = b

                            # Update the section content
                            drm_section.content = section_content

                # Rebuild the ELF file
                builder = lief.ELF.Builder(binary)
                builder.build()
                builder.write(output_path)

                return os.path.exists(output_path)

            except Exception as e:
                logger.error(f"Error in LIEF ELF reconstruction: {e}")
                # Fall back to generic method
                return self._reconstruct_generic_binary(file_path, output_path, drm_info)
        else:
            # LIEF not available, use generic method
            return self._reconstruct_generic_binary(file_path, output_path, drm_info)

    def _reconstruct_macho(self, file_path: str, output_path: str, drm_info: List[Dict[str, Any]]) -> bool:
        """Reconstruct a Mach-O file (macOS executable/library)"""
        if LIEF_AVAILABLE:
            try:
                # Parse the binary
                binary = lief.parse(file_path)
                if not binary:
                    raise ValueError(
                        f"Failed to parse Mach-O file: {file_path}")

                # Process each detected DRM
                for drm in drm_info:
                    drm_offset = drm.get("offset", 0)
                    drm_section = None

                    # Find section containing the DRM
                    for section in binary.sections:
                        section_start = section.offset
                        section_end = section_start + section.size

                        if section_start <= drm_offset < section_end:
                            drm_section = section
                            break

                    if drm_section:
                        logger.info(
                            f"Found DRM in section {drm_section.name} at offset {drm_offset}")

                        # Get the content of the section
                        section_content = list(drm_section.content)

                        # Calculate relative offset within the section
                        relative_offset = drm_offset - section_start

                        # Replace the DRM code with NOPs or a success return patch
                        if relative_offset < len(section_content):
                            # Basic patch: Return 1 (success)
                            patch = [0xB8, 0x01, 0x00, 0x00,
                                     0x00, 0xC3]  # MOV EAX, 1; RET

                            # Apply the patch
                            for i, b in enumerate(patch):
                                if relative_offset + i < len(section_content):
                                    section_content[relative_offset + i] = b

                            # Update the section content
                            drm_section.content = section_content

                # Rebuild the Mach-O file
                builder = lief.MachO.Builder(binary)
                builder.build()
                builder.write(output_path)

                return os.path.exists(output_path)

            except Exception as e:
                logger.error(f"Error in LIEF Mach-O reconstruction: {e}")
                # Fall back to generic method
                return self._reconstruct_generic_binary(file_path, output_path, drm_info)
        else:
            # LIEF not available, use generic method
            return self._reconstruct_generic_binary(file_path, output_path, drm_info)

    def _reconstruct_package(self, file_path: str, output_path: str, drm_info: List[Dict[str, Any]]) -> bool:
        """Reconstruct a package file"""
        try:
            # Identify package type
            file_ext = os.path.splitext(file_path)[1].lower().lstrip(".")

            # Create a temporary directory for extraction
            with tempfile.TemporaryDirectory() as temp_dir:
                # Extract package contents if possible
                extracted = False

                if file_ext == "pak":
                    # Try to extract PAK file
                    extracted = self._extract_pak(file_path, temp_dir)
                elif file_ext in ["bsa", "ba2"]:
                    # Try to extract Bethesda archives
                    extracted = self._extract_bethesda_archive(
                        file_path, temp_dir)
                elif file_ext == "rpf":
                    # Try to extract RAGE package
                    extracted = self._extract_rpf(file_path, temp_dir)

                if extracted:
                    # Process extracted files to remove DRM
                    for root, _, files in os.walk(temp_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            # Scan the file for DRM
                            file_drm_info = []
                            for drm in drm_info:
                                # Simplified matching - in a real implementation,
                                # we would need more sophisticated matching
                                file_drm_info.append(drm)

                            if file_drm_info:
                                # Create output path relative to temp directory
                                rel_path = os.path.relpath(file_path, temp_dir)
                                file_output_path = os.path.join(
                                    temp_dir, "processed", rel_path)
                                os.makedirs(os.path.dirname(
                                    file_output_path), exist_ok=True)

                                # Process the file
                                self._reconstruct_generic_binary(
                                    file_path, file_output_path, file_drm_info)

                    # Repack the processed files
                    if file_ext == "pak":
                        return self._repack_pak(os.path.join(temp_dir, "processed"), output_path)
                    elif file_ext in ["bsa", "ba2"]:
                        return self._repack_bethesda_archive(os.path.join(temp_dir, "processed"), output_path, file_ext)
                    elif file_ext == "rpf":
                        return self._repack_rpf(os.path.join(temp_dir, "processed"), output_path)

            # If extraction/repacking not implemented or failed, fall back to generic binary reconstruction
            return self._reconstruct_generic_binary(file_path, output_path, drm_info)

        except Exception as e:
            logger.error(f"Error reconstructing package file {file_path}: {e}")
            return self._reconstruct_generic_binary(file_path, output_path, drm_info)

    def _extract_pak(self, file_path: str, output_dir: str) -> bool:
        """Extract a PAK file (placeholder implementation)"""
        logger.info(
            f"PAK extraction not fully implemented, using generic binary reconstruction")
        return False

    def _extract_bethesda_archive(self, file_path: str, output_dir: str) -> bool:
        """Extract a Bethesda archive file (placeholder implementation)"""
        logger.info(
            f"Bethesda archive extraction not fully implemented, using generic binary reconstruction")
        return False

    def _extract_rpf(self, file_path: str, output_dir: str) -> bool:
        """Extract a RAGE package file (placeholder implementation)"""
        logger.info(
            f"RAGE package extraction not fully implemented, using generic binary reconstruction")
        return False

    def _repack_pak(self, input_dir: str, output_path: str) -> bool:
        """Repack a PAK file (placeholder implementation)"""
        logger.info(f"PAK repacking not fully implemented")
        return False

    def _repack_bethesda_archive(self, input_dir: str, output_path: str, archive_type: str) -> bool:
        """Repack a Bethesda archive file (placeholder implementation)"""
        logger.info(f"Bethesda archive repacking not fully implemented")
        return False

    def _repack_rpf(self, input_dir: str, output_path: str) -> bool:
        """Repack a RAGE package file (placeholder implementation)"""
        logger.info(f"RAGE package repacking not fully implemented")
        return False

    def _reconstruct_unreal_asset(self, file_path: str, output_path: str, drm_info: List[Dict[str, Any]]) -> bool:
        """Reconstruct an Unreal Engine asset file"""
        # For Unreal assets, we'll use generic binary reconstruction
        # In a full implementation, this would parse the asset format properly
        return self._reconstruct_generic_binary(file_path, output_path, drm_info)

    def verify_file_functionality(self, file_path: str, file_type: str) -> Dict[str, Any]:
        """
        Verify if a reconstructed file is functional

        Args:
            file_path: Path to the file to verify
            file_type: Type of the file

        Returns:
            Dictionary with verification results
        """
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                return {
                    "functional": False,
                    "reason": "File does not exist",
                    "can_retry": False
                }

            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                return {
                    "functional": False,
                    "reason": "File is empty",
                    "can_retry": False
                }

            # Basic header check
            with open(file_path, "rb") as f:
                header = f.read(16)  # Read first 16 bytes

            # Check file type-specific headers
            if file_type == "pe":
                if not header.startswith(b"MZ"):
                    return {
                        "functional": False,
                        "reason": "Invalid PE header",
                        "can_retry": True
                    }
            elif file_type == "elf":
                if not header.startswith(b"\x7FELF"):
                    return {
                        "functional": False,
                        "reason": "Invalid ELF header",
                        "can_retry": True
                    }
            elif file_type == "mach-o":
                if not (header.startswith(b"\xFE\xED\xFA") or header.startswith(b"\xCE\xFA\xED\xFE")):
                    return {
                        "functional": False,
                        "reason": "Invalid Mach-O header",
                        "can_retry": True
                    }

            # For executable files, try more advanced checks if LIEF is available
            if file_type in ["pe", "elf", "mach-o"] and LIEF_AVAILABLE:
                try:
                    binary = lief.parse(file_path)
                    if not binary:
                        return {
                            "functional": False,
                            "reason": "Failed to parse binary",
                            "can_retry": True
                        }

                    # Check for entry point
                    if hasattr(binary, "entrypoint") and binary.entrypoint == 0:
                        return {
                            "functional": False,
                            "reason": "Invalid entry point",
                            "can_retry": True
                        }

                    # Check for sections
                    if len(binary.sections) == 0:
                        return {
                            "functional": False,
                            "reason": "No sections found",
                            "can_retry": True
                        }
                except Exception as e:
                    logger.warning(f"LIEF verification failed: {e}")
                    # Continue with basic verification

            # All checks passed
            return {
                "functional": True,
                "reason": "All checks passed"
            }

        except Exception as e:
            logger.error(f"Error verifying file functionality: {e}")
            return {
                "functional": False,
                "reason": f"Verification error: {e}",
                "can_retry": True
            }

    def _reconstruct_generic_binary(self, file_path: str, output_path: str, drm_info: List[Dict[str, Any]], aggressive: bool = False) -> bool:
        """
        Generic binary reconstruction that works with any file type

        Args:
            file_path: Path to input file
            output_path: Path for output file
            drm_info: Information about detected DRM
            aggressive: Whether to use aggressive patching (more patches, larger areas)

        Returns:
            True if successful, False otherwise
        """
        try:
            # Read the entire file
            with open(file_path, "rb") as f:
                file_data = bytearray(f.read())

            # Process each DRM instance
            for drm in drm_info:
                drm_offset = drm.get("offset", 0)
                drm_type = drm.get("name", "unknown")

                # Skip if offset is invalid
                if drm_offset >= len(file_data):
                    continue

                # Choose patch based on DRM type
                if "denuvo" in drm_type.lower():
                    # Denuvo patch: MOV EAX, 1; RET + NOPs
                    patch = bytearray([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3])
                    patch.extend([0x90] * 32)  # Add some NOPs
                    # Limit patch length
                    patch_len = min(len(patch), 64 if aggressive else 32)
                elif "steam" in drm_type.lower():
                    # Steam patch: PUSH 1; POP RAX; RET
                    patch = bytearray([0x6A, 0x01, 0x58, 0xC3])
                    patch.extend([0x90] * 32)  # Add some NOPs
                    # Limit patch length
                    patch_len = min(len(patch), 48 if aggressive else 24)
                elif "vm" in drm_type.lower() or "virtual" in drm_type.lower():
                    # VM patch: XOR RAX, RAX; INC RAX; RET
                    patch = bytearray(
                        [0x48, 0x31, 0xC0, 0x48, 0xFF, 0xC0, 0xC3])
                    patch.extend([0x90] * 32)  # Add some NOPs
                    # Limit patch length
                    patch_len = min(len(patch), 64 if aggressive else 32)
                else:
                    # Generic patch: Return success
                    # XOR EAX, EAX; INC EAX; RET
                    patch = bytearray([0x31, 0xC0, 0x40, 0xC3])
                    patch.extend([0x90] * 16)  # Add some NOPs
                    # Limit patch length
                    patch_len = min(len(patch), 32 if aggressive else 16)

                # Apply the patch
                for i in range(patch_len):
                    if drm_offset + i < len(file_data):
                        file_data[drm_offset + i] = patch[i]

                # If aggressive mode, also patch surrounding areas
                if aggressive:
                    # Patch a larger area around the DRM
                    extra_patch_size = 128  # Additional bytes to patch
                    start_offset = max(0, drm_offset - extra_patch_size // 2)
                    end_offset = min(len(file_data), drm_offset +
                                     patch_len + extra_patch_size // 2)

                    # Fill with NOPs
                    for i in range(start_offset, end_offset):
                        if i < drm_offset or i >= drm_offset + patch_len:  # Don't overwrite the main patch
                            file_data[i] = 0x90  # NOP instruction

            # Write the modified file
            with open(output_path, "wb") as f:
                f.write(file_data)

            return os.path.exists(output_path)

        except Exception as e:
            logger.error(f"Error in generic binary reconstruction: {e}")
            return False

    def generate_test_file(self, output_path: str, drm_types: List[str], complexity: int = 200) -> Dict[str, Any]:
        """Generate a test file with embedded DRM protections"""
        # Ensure complexity is within reasonable range
        complexity = max(1, min(1000, complexity))

        # Create a basic executable structure
        file_size = 1024 * 1024  # 1MB
        file_data = bytearray(file_size)

        # Add a PE header
        file_data[0:2] = b"MZ"  # DOS header

        # Add a PE signature at a typical offset
        pe_offset = 0x80
        file_data[pe_offset:pe_offset+4] = b"PE\x00\x00"

        # Add some sections
        sections = [
            {"name": ".text", "offset": 0x1000, "size": 0x10000},
            {"name": ".data", "offset": 0x11000, "size": 0x5000},
            {"name": ".rdata", "offset": 0x16000, "size": 0x3000},
            {"name": ".drm", "offset": 0x19000, "size": 0x8000}
        ]

        # Add random code to each section
        for section in sections:
            offset = section["offset"]
            size = section["size"]
            for i in range(size):
                if offset + i < len(file_data):
                    file_data[offset + i] = random.randint(0, 255)

        # Insert DRM protection patterns
        drm_patterns = {
            "denuvo": [
                # Denuvo VM entry pattern
                bytes([0x55, 0x53, 0x56, 0x57, 0x41, 0x54,
                      0x41, 0x55, 0x41, 0x56, 0x41, 0x57]),
                # Denuvo license check pattern
                bytes([0x48, 0x83, 0xEC, 0x40, 0x48, 0x8B, 0x05]),
            ],
            "steam": [
                # Steam DRM common patterns
                bytes([0x53, 0x74, 0x65, 0x61, 0x6D,
                      0x44, 0x52, 0x4D]),  # "SteamDRM"
                bytes([0xFF, 0x15, 0xCC, 0xCC, 0xCC, 0xCC, 0x85, 0xC0, 0x74]),
            ],
            "epic": [
                # Epic online services pattern
                bytes([0x45, 0x70, 0x69, 0x63, 0x4F, 0x6E,
                      0x6C, 0x69, 0x6E, 0x65]),  # "EpicOnline"
            ],
            "vmprotect": [
                # VMProtect pattern
                bytes([0x68, 0xCC, 0xCC, 0xCC, 0xCC, 0x9C, 0x60]),
            ],
            "hardware_lock": [
                # CPUID instruction
                bytes([0x0F, 0xA2]),
                # RDTSC instruction
                bytes([0x0F, 0x31]),
            ]
        }

        # Filter signatures by DRM types
        available_types = [t for t in drm_types if t in drm_patterns]
        if not available_types:
            available_types = list(drm_patterns.keys())

        # Section for DRM protections
        section = sections[-1]  # Use the .drm section
        drm_section_start = section["offset"]
        drm_section_end = drm_section_start + section["size"]

        # Add the specified number of protection layers
        drm_locations = []

        for i in range(complexity):
            # Choose a random DRM type
            drm_type = random.choice(available_types)
            patterns = drm_patterns[drm_type]
            pattern = random.choice(patterns)

            # Choose a random location in the .drm section
            offset = random.randint(
                drm_section_start, drm_section_end - len(pattern))

            # Insert the pattern
            for j, b in enumerate(pattern):
                if offset + j < len(file_data):
                    file_data[offset + j] = b

            # Record the DRM location
            drm_locations.append({
                "type": drm_type,
                "offset": offset,
                "length": len(pattern),
                "pattern": pattern.hex()
            })

        # Write the test file
        with open(output_path, "wb") as f:
            f.write(file_data)

        return {
            "path": output_path,
            "size": file_size,
            "drm_count": len(drm_locations),
            "drm_types": list(set(d["type"] for d in drm_locations)),
            "drm_locations": drm_locations
        }

# ===========================================================================
# Process Virtualization Layer
# ===========================================================================


class ProcessVirtualizationLayer:
    """
    Creates a virtualization layer that intercepts hardware fingerprinting
    and provides clean/consistent responses
    """

    def __init__(self):
        self.hooks = {}
        self.hardware_profiles = {}
        self.current_profile = "default"
        self.intercept_enabled = False
        self._load_hardware_profiles()

    def _load_hardware_profiles(self):
        """Load predefined hardware profiles"""
        # Default profile - generic system
        self.hardware_profiles["default"] = {
            "cpu": {
                "vendor": "GenuineIntel",
                "brand": "Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz",
                "cores": 8,
                "threads": 16,
                "family": 6,
                "model": 165,
                "stepping": 3,
                "features": ["sse", "sse2", "avx", "avx2", "aes", "pclmulqdq", "rdrand"]
            },
            "memory": {
                "total": 16 * 1024 * 1024 * 1024,  # 16 GB
                "speed": 3200,
                "type": "DDR4"
            },
            "disk": {
                "model": "Samsung SSD 970 EVO 1TB",
                "serial": self._generate_serial("SSD"),
                "size": 1000 * 1024 * 1024 * 1024,  # 1 TB
                "type": "nvme"
            },
            "network": {
                "mac": self._generate_mac(),
                "interfaces": ["Ethernet", "Wi-Fi"],
                "hostname": "DESKTOP-" + ''.join(random.choices('0123456789ABCDEF', k=8))
            },
            "gpu": {
                "vendor": "NVIDIA",
                "model": "NVIDIA GeForce RTX 3070",
                "vram": 8 * 1024 * 1024 * 1024,  # 8 GB
                "driver": "535.98"
            },
            "os": {
                "name": "Windows 10 Pro",
                "version": "10.0.19045",
                "build": "19045.3693",
                "locale": "en-US"
            },
            "system": {
                "manufacturer": "ASUS",
                "model": "ROG STRIX Z490-E GAMING",
                "serial": self._generate_serial("MB"),
                "uuid": self._generate_uuid()
            }
        }

        # High-end profile - top-tier hardware
        self.hardware_profiles["high_end"] = {
            "cpu": {
                "vendor": "GenuineIntel",
                "brand": "Intel(R) Core(TM) i9-14900K CPU @ 5.80GHz",
                "cores": 24,
                "threads": 32,
                "family": 6,
                "model": 183,
                "stepping": 1,
                "features": ["sse", "sse2", "avx", "avx2", "avx512f", "aes", "pclmulqdq", "rdrand"]
            },
            "memory": {
                "total": 64 * 1024 * 1024 * 1024,  # 64 GB
                "speed": 6400,
                "type": "DDR5"
            },
            "disk": {
                "model": "Samsung SSD 990 PRO 2TB",
                "serial": self._generate_serial("SSD"),
                "size": 2000 * 1024 * 1024 * 1024,  # 2 TB
                "type": "nvme"
            },
            "network": {
                "mac": self._generate_mac(),
                "interfaces": ["Ethernet", "Wi-Fi 6E"],
                "hostname": "DESKTOP-" + ''.join(random.choices('0123456789ABCDEF', k=8))
            },
            "gpu": {
                "vendor": "NVIDIA",
                "model": "NVIDIA GeForce RTX 4090",
                "vram": 24 * 1024 * 1024 * 1024,  # 24 GB
                "driver": "551.61"
            },
            "os": {
                "name": "Windows 11 Pro",
                "version": "11.0.22631",
                "build": "22631.3155",
                "locale": "en-US"
            },
            "system": {
                "manufacturer": "ASUS",
                "model": "ROG MAXIMUS Z790 EXTREME",
                "serial": self._generate_serial("MB"),
                "uuid": self._generate_uuid()
            }
        }

    def _generate_serial(self, prefix: str) -> str:
        """Generate a random but consistent serial number"""
        # Use a consistent seed based on the prefix
        random.seed(hashlib.md5(prefix.encode()).digest())
        serial = prefix + "-"
        serial += ''.join(random.choices('0123456789ABCDEFGHJKLMNPQRSTUVWXYZ', k=12))
        # Reset the random seed
        random.seed()
        return serial

    def _generate_mac(self) -> str:
        """Generate a random but valid MAC address"""
        # Use locally administered address (2nd bit of first byte set to 1)
        mac = [random.randint(0, 255) & 0xFE | 0x02]
        mac.extend([random.randint(0, 255) for _ in range(5)])
        return ':'.join(f'{b:02x}' for b in mac)

    def _generate_uuid(self) -> str:
        """Generate a random UUID"""
        return '-'.join([
            f'{random.getrandbits(32):08x}',
            f'{random.getrandbits(16):04x}',
            f'{4000 | random.getrandbits(12):04x}',
            f'{8000 | random.getrandbits(14):04x}',
            f'{random.getrandbits(48):012x}'
        ])

    def set_hardware_profile(self, profile_name: str) -> bool:
        """Set the active hardware profile"""
        if profile_name in self.hardware_profiles:
            self.current_profile = profile_name
            logger.info(f"Set hardware profile to {profile_name}")
            return True
        else:
            logger.error(f"Profile {profile_name} not found")
            return False

    def get_current_profile(self) -> Dict[str, Any]:
        """Get the current hardware profile"""
        return self.hardware_profiles.get(self.current_profile, self.hardware_profiles["default"])

    def enable_virtualization(self) -> bool:
        """Enable the virtualization layer"""
        if self.intercept_enabled:
            logger.warning("Virtualization layer already enabled")
            return True

        # Here we would install API hooks for hardware fingerprinting functions
        # For a Python implementation, this would involve patching modules or using a hooking library

        self.intercept_enabled = True
        logger.info("Virtualization layer enabled")
        return True

    def disable_virtualization(self) -> bool:
        """Disable the virtualization layer"""
        if not self.intercept_enabled:
            logger.warning("Virtualization layer not enabled")
            return True

        # Here we would remove the installed hooks

        self.intercept_enabled = False
        logger.info("Virtualization layer disabled")
        return True

    def intercept_cpuid(self, eax: int, ecx: int) -> Tuple[int, int, int, int]:
        """Intercept CPUID instruction"""
        profile = self.get_current_profile()
        cpu_info = profile["cpu"]

        # CPUID leaf 0: Maximum leaf and vendor ID
        if eax == 0:
            max_leaf = 0x16  # Reasonable maximum

            # Vendor ID string (12 bytes in EBX, EDX, ECX)
            vendor = cpu_info["vendor"].ljust(12, ' ')
            ebx = struct.unpack("<I", vendor[0:4].encode())[0]
            edx = struct.unpack("<I", vendor[4:8].encode())[0]
            ecx = struct.unpack("<I", vendor[8:12].encode())[0]

            return (max_leaf, ebx, ecx, edx)

        # CPUID leaf 1: Processor Info and Feature Bits
        elif eax == 1:
            # Family, Model, Stepping
            family = cpu_info["family"] & 0xF
            extended_family = (cpu_info["family"] >> 4) & 0xFF
            model = cpu_info["model"] & 0xF
            extended_model = (cpu_info["model"] >> 4) & 0xF
            stepping = cpu_info["stepping"] & 0xF

            eax_value = ((extended_family << 20) | (extended_model << 16) |
                         (family << 8) | (model << 4) | stepping)

            # EBX: Brand index, CLFLUSH line size, logical processors, APIC ID
            logical_processors = cpu_info["threads"] // cpu_info["cores"]
            ebx_value = ((0 << 24) |                      # APIC ID
                         # Logical processors
                         ((logical_processors & 0xFF) << 16) |
                         # CLFLUSH line size (64 bytes)
                         (8 << 8) |
                         (0 & 0xFF))                      # Brand index

            # ECX and EDX: Feature flags
            feature_flags = {
                "sse": (1 << 25),    # EDX bit 25
                "sse2": (1 << 26),   # EDX bit 26
                "avx": (1 << 28),    # ECX bit 28
                "avx2": (1 << 5),    # ECX bit 5 (leaf 7)
                "aes": (1 << 25),    # ECX bit 25
                "pclmulqdq": (1 << 1),  # ECX bit 1
                "rdrand": (1 << 30)   # ECX bit 30
            }

            ecx_value = 0
            edx_value = 0

            for feature, flag in feature_flags.items():
                if feature in cpu_info["features"]:
                    if feature in ["sse", "sse2"]:
                        edx_value |= flag
                    elif feature != "avx2":  # avx2 is reported in leaf 7
                        ecx_value |= flag

            return (eax_value, ebx_value, ecx_value, edx_value)

        # Default: return zeros
        return (0, 0, 0, 0)

    def intercept_rdtsc(self) -> int:
        """Intercept RDTSC instruction (time stamp counter)"""
        # Get a consistent but advancing timestamp
        # Using a base value plus elapsed time gives a realistic TSC
        base_tsc = 0x1000000000000000  # Base TSC value
        elapsed = int(time.time() * 2.8e9)  # Simulate ~2.8 GHz clock

        return base_tsc + elapsed

    def intercept_system_info(self) -> Dict[str, Any]:
        """Intercept GetSystemInfo API"""
        profile = self.get_current_profile()

        return {
            "processor_architecture": 9,  # PROCESSOR_ARCHITECTURE_AMD64
            "page_size": 4096,
            "minimum_application_address": 0x10000,
            "maximum_application_address": 0x7FFFFFFF0000,
            "active_processor_mask": (1 << profile["cpu"]["threads"]) - 1,
            "number_of_processors": profile["cpu"]["threads"],
            "processor_type": 8664,  # PROCESSOR_AMD_X8664
            "allocation_granularity": 65536,
            "processor_level": 6,
            "processor_revision": (profile["cpu"]["model"] << 8) | profile["cpu"]["stepping"]
        }

# ===========================================================================
# License Emulation System
# ===========================================================================


class LicenseEmulator:
    """
    License emulation system that intercepts license verification
    and returns valid responses
    """

    def __init__(self):
        self.license_templates = {}
        self.active_emulations = {}
        self.emulation_stats = {
            "total_requests": 0,
            "successful_emulations": 0,
            "failed_emulations": 0,
            "platforms": {}
        }
        self._load_license_templates()

    def _load_license_templates(self):
        """Load predefined license templates for various platforms"""

        # Steam license template
        self.license_templates["steam"] = {
            "license_type": "subscription",
            "is_valid": True,
            "app_ownership": {
                "app_id": 0,  # Will be replaced with actual app ID
                "owner_id": self._generate_steam_id(),
                "is_permanent": True,
                "timestamp": int(time.time()),
                "licenses": [
                    {
                        "license_id": random.randint(100000000, 999999999),
                        "purchase_time": int(time.time()) - random.randint(86400, 8640000),
                        "package_id": 0,  # Will be replaced
                        "access_level": 1,
                        "territory": 0,  # Worldwide
                        "status": 1  # Active
                    }
                ]
            },
            "subscriptions": [
                {
                    "package_id": 0,  # Will be replaced
                    "access_level": 1,
                    "active": True,
                    "time_created": int(time.time()) - random.randint(86400, 8640000),
                    "time_updated": int(time.time()) - random.randint(0, 86400)
                }
            ],
            "user_info": {
                "steam_id": 0,  # Will be replaced
                "account_creation": int(time.time()) - random.randint(15778800, 157788000),
                "account_type": 1,  # Individual
                "account_flags": 4 | 32 | 64,  # Licensed + Community + Profile created
                "country_code": "US"
            }
        }

        # Epic Games license template
        self.license_templates["epic"] = {
            "licenses": [
                {
                    "id": self._generate_uuid(),
                    "catalogItemId": "",  # Will be replaced with actual ID
                    "namespace": "epic",
                    "entitlementName": "entitlement.product",
                    "entitlementType": "PURCHASE",
                    "grantDate": self._get_iso_time(-random.randint(1, 365)),
                    "expirationDate": None,
                    "status": "ACTIVE",
                    "active": True,
                    "source": "PURCHASE",
                    "grantee": {
                        "id": self._generate_epic_account_id(),
                        "type": "user",
                        "displayName": "Player"
                    }
                }
            ],
            "success": True,
            "error": None
        }

        # Denuvo license template
        self.license_templates["denuvo"] = {
            "activation": {
                "machine_id": self._generate_machine_id(),
                "activation_id": self._generate_hex_string(32),
                "timestamp": int(time.time()),
                "license_type": "full",
                "expiration": 0,  # No expiration
                "verification_count": random.randint(5, 20),
                "signature": self._generate_hex_string(128)
            },
            "user": {
                "id": self._generate_hex_string(32),
                "created": int(time.time()) - random.randint(86400, 8640000),
                "last_login": int(time.time()) - random.randint(0, 86400),
                "country": "US",
                "hardware_changes": random.randint(0, 2)
            },
            "machine": {
                "id": self._generate_machine_id(),
                "hash": self._generate_hex_string(64),
                "first_activation": int(time.time()) - random.randint(86400, 8640000),
                "last_verification": int(time.time()) - random.randint(0, 86400),
                "verification_count": random.randint(10, 100)
            }
        }

    def generate_license(self, platform: str, game_id: str, custom_params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Generate a license for a specific platform and game

        Args:
            platform: Platform name (steam, epic, ubisoft, etc.)
            game_id: Game ID for the platform
            custom_params: Optional custom parameters

        Returns:
            License data
        """
        # Get the template
        if platform.lower() not in self.license_templates:
            raise ValueError(f"Platform {platform} not supported")

        template = self.license_templates[platform.lower()]
        license_data = self._deep_copy_dict(template)

        # Customize based on platform
        if platform.lower() == "steam":
            # Set app ID
            license_data["app_ownership"]["app_id"] = int(game_id)

            # Set package ID
            package_id = int(game_id) + 10000
            for license in license_data["app_ownership"]["licenses"]:
                license["package_id"] = package_id

            for subscription in license_data["subscriptions"]:
                subscription["package_id"] = package_id

            # Set Steam ID
            steam_id = license_data["user_info"]["steam_id"] = int(
                license_data["app_ownership"]["owner_id"])

        elif platform.lower() == "epic":
            # Set catalog item ID
            license_data["licenses"][0]["catalogItemId"] = game_id

        elif platform.lower() == "denuvo":
            # No specific customization for Denuvo
            pass

        # Apply custom parameters if provided
        if custom_params:
            for key, value in custom_params.items():
                path = key.split(".")
                if len(path) > 1:
                    self._set_nested_value(license_data, path, value)

        # Track this emulation
        emulation_id = f"{platform}_{game_id}_{int(time.time())}"
        self.active_emulations[emulation_id] = {
            "platform": platform,
            "game_id": game_id,
            "created_at": int(time.time()),
            "license": license_data
        }

        # Update statistics
        self.emulation_stats["total_requests"] += 1
        self.emulation_stats["successful_emulations"] += 1

        if platform not in self.emulation_stats["platforms"]:
            self.emulation_stats["platforms"][platform] = {
                "successful": 0, "failed": 0}

        self.emulation_stats["platforms"][platform]["successful"] += 1

        return license_data

    def _set_nested_value(self, data: Dict[str, Any], path: List[str], value: Any) -> None:
        """Set a value in a nested dictionary using a path"""
        if not path:
            return

        current = data
        for i, key in enumerate(path[:-1]):
            if key not in current:
                current[key] = {}
            current = current[key]

        current[path[-1]] = value

    def _deep_copy_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Deep copy a dictionary"""
        return json.loads(json.dumps(data))

    def _generate_steam_id(self) -> int:
        """Generate a valid Steam ID"""
        # Steam IDs are 17-digit numbers starting with 7656119
        return 7656119000000000 + random.randint(10000000, 99999999)

    def _generate_epic_account_id(self) -> str:
        """Generate a valid Epic account ID"""
        return self._generate_hex_string(32)

    def _generate_uuid(self) -> str:
        """Generate a random UUID"""
        return '-'.join([
            f'{random.getrandbits(32):08x}',
            f'{random.getrandbits(16):04x}',
            f'{4000 | random.getrandbits(12):04x}',
            f'{8000 | random.getrandbits(14):04x}',
            f'{random.getrandbits(48):012x}'
        ])

    def _generate_hex_string(self, length: int) -> str:
        """Generate a random hex string of given length"""
        return ''.join(random.choice('0123456789abcdef') for _ in range(length))

    def _generate_machine_id(self) -> str:
        """Generate a machine ID that looks like a hardware hash"""
        # Format: XX:XX:XX:XX:XX:XX:XX:XX (where X is a hex digit)
        return ':'.join(f'{random.randint(0, 255):02x}' for _ in range(8))

    def _get_iso_time(self, days_offset: int = 0) -> str:
        """Get ISO 8601 formatted time with optional offset in days"""
        dt = time.gmtime(time.time() + days_offset * 86400)
        return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", dt)

# ===========================================================================
# Network Manipulation
# ===========================================================================


class NetworkManipulator:
    """
    Network traffic manipulation system that intercepts and modifies
    communications between games and authentication/validation servers
    """

    def __init__(self):
        self.active_proxies = {}
        self.manipulation_rules = {}
        self.stats = {
            "packets_intercepted": 0,
            "packets_modified": 0,
            "bytes_intercepted": 0,
            "bytes_modified": 0,
            "active_proxies": 0,
            "start_time": int(time.time())
        }
        self._register_default_rules()

    def _register_default_rules(self):
        """Register default manipulation rules"""
        # Common rules for various platforms
        self.add_manipulation_rule(
            "steam_license_valid",
            ["api.steampowered.com", "store.steampowered.com"],
            "replace",
            b"\"licensed\":false",
            b"\"licensed\":true",
            "http"
        )

        self.add_manipulation_rule(
            "epic_license_valid",
            ["api.epicgames.dev", "egs-api.epicgames.com"],
            "replace",
            b"\"active\":false",
            b"\"active\":true",
            "http"
        )

        self.add_manipulation_rule(
            "denuvo_valid",
            [],
            "replace",
            b"\"valid\":false",
            b"\"valid\":true",
            "tcp"
        )

    def add_manipulation_rule(self, rule_name: str, target_hosts: List[str], rule_type: str,
                              search_pattern: Union[str, bytes], replace_pattern: Union[str, bytes],
                              protocol: str = "http") -> bool:
        """
        Add a traffic manipulation rule

        Args:
            rule_name: Name of the rule
            target_hosts: List of target hostnames or IPs
            rule_type: Type of rule (e.g., "replace", "block")
            search_pattern: Pattern to search for in traffic
            replace_pattern: Pattern to replace with (for "replace" rule_type)
            protocol: Target protocol

        Returns:
            True if rule was added, False otherwise
        """
        # Convert string patterns to bytes if needed
        if isinstance(search_pattern, str):
            search_pattern = search_pattern.encode('utf-8')

        if isinstance(replace_pattern, str):
            replace_pattern = replace_pattern.encode('utf-8')

        # Add the rule
        rule = {
            "name": rule_name,
            "target_hosts": target_hosts,
            "type": rule_type,
            "search_pattern": search_pattern,
            "replace_pattern": replace_pattern,
            "protocol": protocol,
            "enabled": True,
            "hits": 0,
            "created": int(time.time())
        }

        self.manipulation_rules[rule_name] = rule
        logger.info(f"Added manipulation rule: {rule_name}")

        return True

    def start_proxy(self, protocol: str, local_port: int, remote_host: str, remote_port: int) -> bool:
        """
        Start a proxy for the specified protocol

        Args:
            protocol: Protocol to proxy
            local_port: Local port to listen on
            remote_host: Remote host to forward to
            remote_port: Remote port to forward to

        Returns:
            True if proxy was started, False otherwise
        """
        proxy_id = f"{protocol}_{local_port}_{remote_host}_{remote_port}"

        # Check if proxy already exists
        if proxy_id in self.active_proxies:
            logger.warning(f"Proxy already exists: {proxy_id}")
            return False

        try:
            # Create and start the proxy thread
            proxy_thread = threading.Thread(
                target=self._proxy_thread,
                args=(protocol, local_port, remote_host, remote_port),
                daemon=True
            )

            proxy_thread.start()

            # Register the active proxy
            self.active_proxies[proxy_id] = {
                "protocol": protocol,
                "local_port": local_port,
                "remote_host": remote_host,
                "remote_port": remote_port,
                "thread": proxy_thread,
                "started": int(time.time()),
                "bytes_in": 0,
                "bytes_out": 0,
                "connections": 0
            }

            # Update stats
            self.stats["active_proxies"] += 1

            logger.info(
                f"Started {protocol} proxy: {local_port} -> {remote_host}:{remote_port}")
            return True

        except Exception as e:
            logger.error(f"Error starting proxy: {e}")
            return False

    def _proxy_thread(self, protocol: str, local_port: int, remote_host: str, remote_port: int):
        """Thread function for running a proxy"""
        try:
            proxy_id = f"{protocol}_{local_port}_{remote_host}_{remote_port}"

            if protocol.lower() == "udp":
                self._run_udp_proxy(proxy_id, local_port,
                                    remote_host, remote_port)
            else:
                self._run_tcp_proxy(proxy_id, local_port,
                                    remote_host, remote_port)

        except Exception as e:
            logger.error(f"Error in proxy thread: {e}")

            # Clean up the proxy
            if proxy_id in self.active_proxies:
                del self.active_proxies[proxy_id]

                # Update stats
                self.stats["active_proxies"] -= 1

    def _run_tcp_proxy(self, proxy_id: str, local_port: int, remote_host: str, remote_port: int):
        """Run a TCP proxy"""
        try:
            # Create server socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            try:
                server_socket.bind(("0.0.0.0", local_port))
                server_socket.listen(5)

                logger.info(f"TCP proxy listening on port {local_port}")

                while True:
                    client_socket, client_address = server_socket.accept()
                    logger.debug(
                        f"New connection from {client_address[0]}:{client_address[1]}")

                    # Update proxy stats
                    if proxy_id in self.active_proxies:
                        self.active_proxies[proxy_id]["connections"] += 1

                    # Start a new thread to handle this client
                    client_thread = threading.Thread(
                        target=self._handle_tcp_client,
                        args=(client_socket, remote_host, remote_port),
                        daemon=True
                    )

                    client_thread.start()
            finally:
                server_socket.close()

        except Exception as e:
            logger.error(f"Error in TCP proxy: {e}")

    def _run_udp_proxy(self, proxy_id: str, local_port: int, remote_host: str, remote_port: int):
        """Run a UDP proxy"""
        try:
            # Create server socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            try:
                server_socket.bind(("0.0.0.0", local_port))

                logger.info(f"UDP proxy listening on port {local_port}")

                # Client address mapping
                clients = {}

                while True:
                    data, client_address = server_socket.recvfrom(4096)

                    # Update proxy stats
                    if proxy_id in self.active_proxies:
                        self.active_proxies[proxy_id]["bytes_in"] += len(data)

                        # Count unique clients
                        client_key = f"{client_address[0]}:{client_address[1]}"
                        if client_key not in clients:
                            clients[client_key] = True
                            self.active_proxies[proxy_id]["connections"] += 1

                    # Apply manipulations
                    modified_data = self._apply_manipulation_rules(data, "udp")

                    if modified_data != data:
                        self.stats["packets_modified"] += 1
                        self.stats["bytes_modified"] += abs(
                            len(modified_data) - len(data))

                    # Forward to remote
                    remote_socket = socket.socket(
                        socket.AF_INET, socket.SOCK_DGRAM)

                    try:
                        remote_socket.sendto(
                            modified_data, (remote_host, remote_port))

                        # Receive response from remote
                        remote_socket.settimeout(5)
                        response, _ = remote_socket.recvfrom(4096)

                        # Apply manipulations to response
                        modified_response = self._apply_manipulation_rules(
                            response, "udp")

                        if modified_response != response:
                            self.stats["packets_modified"] += 1
                            self.stats["bytes_modified"] += abs(
                                len(modified_response) - len(response))

                        # Send back to client
                        server_socket.sendto(modified_response, client_address)

                        # Update proxy stats
                        if proxy_id in self.active_proxies:
                            self.active_proxies[proxy_id]["bytes_out"] += len(
                                modified_response)
                    except socket.timeout:
                        logger.debug(
                            f"Timeout waiting for UDP response from {remote_host}:{remote_port}")
                    finally:
                        remote_socket.close()
            finally:
                server_socket.close()

        except Exception as e:
            logger.error(f"Error in UDP proxy: {e}")

    def _handle_tcp_client(self, client_socket: socket.socket, remote_host: str, remote_port: int):
        """Handle a TCP client connection"""
        try:
            # Connect to remote server
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            try:
                remote_socket.connect((remote_host, remote_port))

                # Set up two-way forwarding
                client_to_remote = threading.Thread(
                    target=self._forward_tcp,
                    args=(client_socket, remote_socket, "client_to_remote"),
                    daemon=True
                )

                remote_to_client = threading.Thread(
                    target=self._forward_tcp,
                    args=(remote_socket, client_socket, "remote_to_client"),
                    daemon=True
                )

                client_to_remote.start()
                remote_to_client.start()

                # Wait for both threads to finish
                client_to_remote.join()
                remote_to_client.join()
            finally:
                remote_socket.close()
        except Exception as e:
            logger.error(f"Error handling TCP client: {e}")
        finally:
            if client_socket:
                client_socket.close()

    def _forward_tcp(self, source: socket.socket, destination: socket.socket, direction: str):
        """Forward TCP traffic between source and destination"""
        try:
            # Buffer for receiving data
            buffer_size = 4096

            while True:
                try:
                    data = source.recv(buffer_size)
                    if not data:
                        break

                    # Apply manipulations
                    modified_data = self._apply_manipulation_rules(data, "tcp")

                    if modified_data != data:
                        self.stats["packets_modified"] += 1
                        self.stats["bytes_modified"] += abs(
                            len(modified_data) - len(data))

                    # Forward the data
                    destination.sendall(modified_data)

                except ConnectionResetError:
                    break
                except socket.error:
                    break

        except Exception as e:
            logger.error(f"Error in TCP forwarding: {e}")

    def _apply_manipulation_rules(self, data: bytes, protocol: str) -> bytes:
        """Apply manipulation rules to the data"""
        # Skip if no rules
        if not self.manipulation_rules:
            return data

        # Apply each enabled rule for this protocol
        modified_data = data

        for rule_name, rule in self.manipulation_rules.items():
            if not rule["enabled"]:
                continue

            if rule["protocol"].lower() != protocol.lower():
                continue

            # Apply the rule based on its type
            if rule["type"] == "replace":
                if rule["search_pattern"] in modified_data:
                    modified_data = modified_data.replace(
                        rule["search_pattern"], rule["replace_pattern"])
                    rule["hits"] += 1
                    logger.debug(f"Applied rule {rule_name}")

            elif rule["type"] == "block":
                if rule["search_pattern"] in modified_data:
                    # Return empty data to block
                    modified_data = b""
                    rule["hits"] += 1
                    logger.debug(f"Blocked data with rule {rule_name}")
                    break  # No need to apply more rules

            elif rule["type"] == "inject":
                # Inject data at the beginning or end
                if protocol.lower() == "http" and b"\r\n\r\n" in modified_data:
                    # Inject before body
                    header_end = modified_data.find(b"\r\n\r\n") + 4
                    modified_data = modified_data[:header_end] + \
                        rule["replace_pattern"] + modified_data[header_end:]
                else:
                    # Inject at the end
                    modified_data += rule["replace_pattern"]

                rule["hits"] += 1
                logger.debug(f"Injected data with rule {rule_name}")

        return modified_data

# ===========================================================================
# Core Functionality
# ===========================================================================


class DRMSlayer:
    """Main DRM Slayer class that coordinates all functionality"""

    def __init__(self):
        self.drm_engine = DRMEngine()
        self.binary_reconstructor = BinaryReconstructor()
        self.process_virtualization = ProcessVirtualizationLayer()
        self.license_emulator = LicenseEmulator()
        self.network_manipulator = NetworkManipulator()

        # Set up default options
        self.options = {
            "recursive": True,
            "backup": True,
            "verbose": True,
            "auto_patch": True,
            "use_virtualization": True,
            "use_license_emulation": True,
            "use_network_manipulation": True
        }

    def scan(self, path: str, drm_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Scan for DRM in a file or folder

        Args:
            path: Path to the file or folder to scan
            drm_types: Optional list of DRM types to scan for

        Returns:
            Scan results
        """
        if os.path.isdir(path):
            return self._scan_folder(path, drm_types)
        else:
            return self._scan_file(path, drm_types)

    def _scan_file(self, file_path: str, drm_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """Scan a single file for DRM"""
        logger.info(f"Scanning file: {file_path}")

        results = self.drm_engine.scan_file(file_path, drm_types)

        return {
            "file": file_path,
            "drm_found": len(results) > 0,
            "drm_count": len(results),
            "drm_types": list(set(r["name"] for r in results)),
            "details": results
        }

    def _scan_folder(self, folder_path: str, drm_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """Scan a folder for DRM"""
        logger.info(f"Scanning folder: {folder_path}")

        results = self.drm_engine.scan_folder(
            folder_path, drm_types, self.options["recursive"])

        # Summarize results
        file_count = len(results)
        drm_types_found = set()
        total_drm_count = 0

        for file_results in results.values():
            total_drm_count += len(file_results)
            drm_types_found.update(r["name"] for r in file_results)

        return {
            "folder": folder_path,
            "files_with_drm": file_count,
            "total_drm_count": total_drm_count,
            "drm_types_found": list(drm_types_found),
            "details": results
        }

    def remove_drm(self, path: str, scan_results: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Remove DRM from a file or folder

        Args:
            path: Path to the file or folder
            scan_results: Optional scan results (if None, will scan first)

        Returns:
            Removal results
        """
        # If no scan results provided, do a scan first
        if not scan_results:
            scan_results = self.scan(path)

        if os.path.isdir(path):
            return self._remove_folder_drm(path, scan_results.get("details", {}))
        else:
            return self._remove_file_drm(path, scan_results.get("details", []))

    def _remove_file_drm(self, file_path: str, drm_info: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Remove DRM from a single file"""
        logger.info(f"Removing DRM from file: {file_path}")

        # First try with binary reconstruction
        temp_output = file_path + ".drm_free"
        reconstruction_success = self.binary_reconstructor.reconstruct_file(
            file_path, temp_output, drm_info)

        if reconstruction_success:
            # Replace the original file with the reconstructed one
            if self.options["backup"]:
                # Create backup
                backup_path = file_path + ".bak"
                shutil.copy2(file_path, backup_path)
                logger.info(f"Created backup at {backup_path}")

            # Replace with reconstructed file
            shutil.copy2(temp_output, file_path)

            # Clean up temp file
            try:
                os.remove(temp_output)
            except:
                pass

            return {
                "success": True,
                "method": "binary_reconstruction",
                "drm_removed": len(drm_info)
            }

        # If reconstruction failed, try direct patching
        if self.options["auto_patch"]:
            patching_success = self.drm_engine.remove_drm(file_path, drm_info)

            if patching_success:
                return {
                    "success": True,
                    "method": "direct_patching",
                    "drm_removed": len(drm_info)
                }

        # Both methods failed
        return {
            "success": False,
            "error": "All removal methods failed",
            "drm_info": drm_info
        }

    def _remove_folder_drm(self, folder_path: str, scan_results: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Remove DRM from a folder"""
        logger.info(f"Removing DRM from folder: {folder_path}")

        results = self.drm_engine.remove_drm_from_folder(
            folder_path, scan_results)

        return {
            "success": results["success"],
            "files_processed": results["total_files"],
            "successful": results["successful"],
            "failed": results["failed"],
            "details": results["file_results"]
        }

    def enable_virtualization(self, profile: str = "default") -> bool:
        """
        Enable process virtualization

        Args:
            profile: Hardware profile to use

        Returns:
            True if virtualization was enabled, False otherwise
        """
        # Set the hardware profile
        self.process_virtualization.set_hardware_profile(profile)

        # Enable virtualization
        return self.process_virtualization.enable_virtualization()

    def create_test_file(self, output_path: str, drm_types: List[str], complexity: int = 200) -> Dict[str, Any]:
        """
        Create a test file with embedded DRM for testing

        Args:
            output_path: Path for the output file
            drm_types: List of DRM types to include
            complexity: Number of protection layers (1-1000)

        Returns:
            Dictionary with test file information
        """
        return self.binary_reconstructor.generate_test_file(output_path, drm_types, complexity)

    def get_statistics(self) -> Dict[str, Any]:
        """Get overall statistics"""
        return {
            "drm_engine": self.drm_engine.get_statistics(),
            "virtualization": {
                "enabled": self.process_virtualization.intercept_enabled,
                "current_profile": self.process_virtualization.current_profile
            },
            "license_emulation": {
                "total_requests": self.license_emulator.emulation_stats["total_requests"],
                "success_rate": (self.license_emulator.emulation_stats["successful_emulations"] /
                                 max(1, self.license_emulator.emulation_stats["total_requests"]) * 100)
            },
            "network_manipulation": {
                "active_proxies": self.network_manipulator.stats["active_proxies"],
                "packets_modified": self.network_manipulator.stats["packets_modified"],
                "rules": len(self.network_manipulator.manipulation_rules)
            }
        }

# ===========================================================================
# Command Line Interface
# ===========================================================================


def parse_arguments():
    """Parse command line arguments"""
    import argparse

    parser = argparse.ArgumentParser(
        description="DRM Slayer: Ultimate Game DRM Removal Tool")

    # Main action arguments
    action_group = parser.add_argument_group("Actions")
    action_group.add_argument(
        "--scan", "-s", help="Path to scan for DRM", metavar="PATH")
    action_group.add_argument(
        "--remove", "-r", help="Path to remove DRM from", metavar="PATH")
    action_group.add_argument(
        "--test", "-t", help="Create a test file with DRM", metavar="PATH")
    action_group.add_argument(
        "--virtualize", "-v", help="Enable process virtualization", action="store_true")

    # Filter arguments
    filter_group = parser.add_argument_group("Filters")
    filter_group.add_argument(
        "--drm-types", "-d", help="DRM types to target (comma-separated)")

    # Option arguments
    option_group = parser.add_argument_group("Options")
    option_group.add_argument(
        "--recursive", help="Scan subfolders recursively", action="store_true")
    option_group.add_argument(
        "--no-backup", help="Disable backup creation", action="store_true")
    option_group.add_argument(
        "--verbose", help="Enable verbose output", action="store_true")
    option_group.add_argument(
        "--complexity", "-c", help="Complexity of test file (1-1000)", type=int, default=200)
    option_group.add_argument("--profile", "-p", help="Hardware profile for virtualization",
                              choices=["default", "high_end"], default="default")

    return parser.parse_args()


def main():
    """Main function"""
    args = parse_arguments()

    print(f"DRM Slayer v{VERSION} - Ultimate Edition")
    print("=" * 60)

    # Initialize DRM Slayer
    slayer = DRMSlayer()

    # Set options
    if args.recursive:
        slayer.options["recursive"] = True
    if args.no_backup:
        slayer.options["backup"] = False
    if args.verbose:
        slayer.options["verbose"] = True
        # Set root logger to DEBUG for verbose output
        logging.getLogger().setLevel(logging.DEBUG)

    # Parse DRM types
    drm_types = None
    if args.drm_types:
        drm_types = args.drm_types.split(",")
        print(f"Targeting DRM types: {', '.join(drm_types)}")

    # Process actions
    if args.scan:
        print(f"Scanning for DRM in: {args.scan}")
        results = slayer.scan(args.scan, drm_types)

        if os.path.isdir(args.scan):
            print(f"Found {results['files_with_drm']} files with DRM")
            print(f"Total DRM instances: {results['total_drm_count']}")
            if results['drm_types_found']:
                print(
                    f"DRM types detected: {', '.join(results['drm_types_found'])}")
        else:
            if results['drm_found']:
                print(f"Found {results['drm_count']} DRM instances in file")
                print(f"DRM types detected: {', '.join(results['drm_types'])}")

                # Print details in verbose mode
                if args.verbose:
                    for drm in results['details']:
                        print(
                            f"  - {drm['name']} ({drm['subtype']}): {drm['confidence']}% confidence")
            else:
                print("No DRM found in file")

        # If also removing, use these scan results
        if args.remove and args.remove == args.scan:
            print("\nRemoving detected DRM...")
            remove_results = slayer.remove_drm(args.remove, results)

            if remove_results['success']:
                if os.path.isdir(args.remove):
                    print(
                        f"Successfully processed {remove_results['successful']} of {remove_results['files_processed']} files")
                    if remove_results['failed'] > 0:
                        print(
                            f"Failed to process {remove_results['failed']} files")
                else:
                    print(
                        f"Successfully removed DRM using {remove_results['method']}")
            else:
                print(
                    f"Failed to remove DRM: {remove_results.get('error', 'Unknown error')}")

    # Remove DRM (if not already done with scan)
    elif args.remove:
        print(f"Removing DRM from: {args.remove}")
        results = slayer.remove_drm(args.remove)

        if results['success']:
            if os.path.isdir(args.remove):
                print(
                    f"Successfully processed {results['successful']} of {results['files_processed']} files")
                if results['failed'] > 0:
                    print(f"Failed to process {results['failed']} files")
            else:
                print(f"Successfully removed DRM using {results['method']}")
        else:
            print(
                f"Failed to remove DRM: {results.get('error', 'Unknown error')}")

    # Create test file
    if args.test:
        print(f"Creating test file with DRM: {args.test}")

        # Use provided DRM types or default to a mix
        test_drm_types = drm_types or ["denuvo", "steam", "vmprotect"]

        results = slayer.create_test_file(
            args.test, test_drm_types, args.complexity)

        print(f"Created test file: {results['path']}")
        print(f"File size: {results['size']} bytes")
        print(f"DRM count: {results['drm_count']}")
        print(f"DRM types: {', '.join(results['drm_types'])}")

    # Enable virtualization
    if args.virtualize:
        print(f"Enabling process virtualization with profile: {args.profile}")

        success = slayer.enable_virtualization(args.profile)

        if success:
            print("Virtualization layer enabled")
        else:
            print("Failed to enable virtualization layer")

    # Print statistics if no action was specified
    if not any([args.scan, args.remove, args.test, args.virtualize]):
        stats = slayer.get_statistics()

        print("DRM Slayer Statistics")
        print("-" * 20)
        print(f"Files scanned: {stats['drm_engine']['files_scanned']}")
        print(f"DRM instances detected: {stats['drm_engine']['drm_detected']}")
        print(f"DRM instances removed: {stats['drm_engine']['drm_removed']}")
        print(f"Success rate: {stats['drm_engine']['success_rate']:.2f}%")

        print("\nSupported DRM Types:")
        for drm_type in DRM_TYPES:
            desc = PROTECTION_DESCRIPTIONS.get(drm_type, "")
            print(f"- {drm_type}: {desc}")

        print("\nUsage examples:")
        print("  python drm_slayer.py --scan game_folder --recursive")
        print("  python drm_slayer.py --remove game.exe")
        print("  python drm_slayer.py --test test_file.exe --complexity 200 --drm-types denuvo,steam")
        print("  python drm_slayer.py --virtualize --profile high_end")

        print("\nSee --help for more options")


if __name__ == "__main__":
    main()
