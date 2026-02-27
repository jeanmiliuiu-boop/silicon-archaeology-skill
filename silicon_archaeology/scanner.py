"""
Hardware Scanner Module for Silicon Archaeology Skill

Detects and fingerprints vintage computing hardware.
"""

import json
import platform
import subprocess
import sys
from typing import Dict, Optional


# Silicon Epoch classification based on CPU families
SILICON_EPOCHS = {
    # Epoch 0: Pre-VLSI (pre-1980)
    "pdq-11": {"epoch": 0, "year_estimate": 1975, "multiplier": 4.0},
    "altair": {"epoch": 0, "year_estimate": 1975, "multiplier": 4.0},
    "z80": {"epoch": 0, "year_estimate": 1976, "multiplier": 4.0},
    "6502": {"epoch": 0, "year_estimate": 1976, "multiplier": 4.0},
    
    # Epoch 1: VLSI Dawn (1980-1992)
    "68000": {"epoch": 1, "year_estimate": 1984, "multiplier": 3.5},
    "mc68000": {"epoch": 1, "year_estimate": 1984, "multiplier": 3.5},
    "intel 80386": {"epoch": 1, "year_estimate": 1985, "multiplier": 3.5},
    "i386": {"epoch": 1, "year_estimate": 1985, "multiplier": 3.5},
    "amiga": {"epoch": 1, "year_estimate": 1985, "multiplier": 3.5},
    "atari st": {"epoch": 1, "year_estimate": 1985, "multiplier": 3.5},
    
    # Epoch 2: RISC Wars (1993-2005)
    "powerpc": {"epoch": 2, "year_estimate": 1994, "multiplier": 2.5},
    "g3": {"epoch": 2, "year_estimate": 1997, "multiplier": 2.5},
    "g4": {"epoch": 2, "year_estimate": 1999, "multiplier": 2.0},
    "g5": {"epoch": 2, "year_estimate": 2003, "multiplier": 2.0},
    "power mac": {"epoch": 2, "year_estimate": 1997, "multiplier": 2.0},
    "sparc": {"epoch": 2, "year_estimate": 1992, "multiplier": 2.0},
    "mips": {"epoch": 2, "year_estimate": 1992, "multiplier": 2.0},
    "alpha": {"epoch": 2, "year_estimate": 1992, "multiplier": 2.0},
    
    # Epoch 3: x86 Dominance (2006-2019)
    "core 2": {"epoch": 3, "year_estimate": 2006, "multiplier": 1.3},
    "nehalem": {"epoch": 3, "year_estimate": 2008, "multiplier": 1.3},
    "sandy bridge": {"epoch": 3, "year_estimate": 2011, "multiplier": 1.2},
    "ivy bridge": {"epoch": 3, "year_estimate": 2012, "multiplier": 1.2},
    "haswell": {"epoch": 3, "year_estimate": 2013, "multiplier": 1.2},
    "broadwell": {"epoch": 3, "year_estimate": 2014, "multiplier": 1.1},
    "skylake": {"epoch": 3, "year_estimate": 2015, "multiplier": 1.1},
    "kaby lake": {"epoch": 3, "year_estimate": 2016, "multiplier": 1.1},
    "coffee lake": {"epoch": 3, "year_estimate": 2017, "multiplier": 1.1},
    "comet lake": {"epoch": 3, "year_estimate": 2019, "multiplier": 1.1},
    
    # Epoch 4: Post-Moore (2020+)
    "apple silicon": {"epoch": 4, "year_estimate": 2020, "multiplier": 1.2},
    "m1": {"epoch": 4, "year_estimate": 2020, "multiplier": 1.2},
    "m2": {"epoch": 4, "year_estimate": 2022, "multiplier": 1.1},
    "m3": {"epoch": 4, "year_estimate": 2023, "multiplier": 1.1},
    "m4": {"epoch": 4, "year_estimate": 2024, "multiplier": 1.0},
    "risc-v": {"epoch": 4, "year_estimate": 2020, "multiplier": 1.2},
    "zen": {"epoch": 4, "year_estimate": 2017, "multiplier": 1.1},
    "zen 2": {"epoch": 4, "year_estimate": 2019, "multiplier": 1.1},
    "zen 3": {"epoch": 4, "year_estimate": 2020, "multiplier": 1.1},
    "zen 4": {"epoch": 4, "year_estimate": 2022, "multiplier": 1.0},
}


def get_linux_cpu_info() -> Dict:
    """Get CPU info from /proc/cpuinfo on Linux."""
    try:
        with open("/proc/cpuinfo", "r") as f:
            content = f.read()
        
        info = {}
        for line in content.split("\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                info[key.strip()] = value.strip()
        
        model = info.get("model name", info.get("Hardware", "Unknown"))
        return {"family": info.get("vendor_id", "Unknown"), "model": model}
    except Exception as e:
        return {"error": str(e)}


def get_macos_cpu_info() -> Dict:
    """Get CPU info using sysctl on macOS."""
    try:
        result = subprocess.run(
            ["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"],
            capture_output=True, text=True
        )
        model = result.stdout.strip() if result.stdout else "Unknown"
        
        result = subprocess.run(
            ["/usr/sbin/sysctl", "-n", "hw.model"],
            capture_output=True, text=True
        )
        hardware = result.stdout.strip() if result.stdout else "Unknown"
        
        return {"family": "Apple", "model": model, "hardware": hardware}
    except Exception as e:
        return {"error": str(e)}


def get_windows_cpu_info() -> Dict:
    """Get CPU info on Windows."""
    try:
        result = subprocess.run(
            ["wmic", "cpu", "get", "name"],
            capture_output=True, text=True
        )
        lines = result.stdout.strip().split("\n")
        model = lines[1].strip() if len(lines) > 1 else "Unknown"
        return {"family": "Intel/AMD", "model": model}
    except Exception:
        return {"family": "Unknown", "model": platform.processor()}


def detect_cpu_family(cpu_info: Dict) -> str:
    """Detect CPU family from CPU info."""
    model = cpu_info.get("model", "").lower()
    family = cpu_info.get("family", "").lower()
    hardware = cpu_info.get("hardware", "").lower()
    
    # Check for Apple Silicon
    if "apple" in model or "arm" in hardware or "m4" in model.lower():
        if "m1" in model:
            return "m1"
        elif "m2" in model:
            return "m2"
        elif "m3" in model:
            return "m3"
        elif "m4" in model:
            return "m4"
        return "apple silicon"
    
    # Check for Apple PowerPC
    if "power mac" in hardware or "powerbook" in hardware:
        if "g5" in model:
            return "g5"
        elif "g4" in model:
            return "g4"
        elif "g3" in model:
            return "g3"
        return "powerpc"
    
    # Check for x86
    if "intel" in family or "intel" in model:
        if "core 2" in model:
            return "core 2"
        elif "nehalem" in model:
            return "nehalem"
        elif "sandy bridge" in model:
            return "sandy bridge"
        elif "ivy bridge" in model:
            return "ivy bridge"
        elif "haswell" in model:
            return "haswell"
        elif "broadwell" in model:
            return "broadwell"
        elif "skylake" in model:
            return "skylake"
        elif "kaby lake" in model:
            return "kaby lake"
        elif "coffee lake" in model:
            return "coffee lake"
        elif "comet lake" in model:
            return "comet lake"
        elif "i386" in model or "80386" in model:
            return "intel 80386"
        return "x86"
    
    # Check for AMD
    if "amd" in family or "amd" in model:
        if "zen 4" in model or "ryzen 7000" in model:
            return "zen 4"
        elif "zen 3" in model or "ryzen 5000" in model:
            return "zen 3"
        elif "zen 2" in model or "ryzen 3000" in model:
            return "zen 2"
        elif "zen" in model or "ryzen" in model:
            return "zen"
        return "x86"
    
    # Check for RISC
    if "powerpc" in model or "power" in model:
        if "g5" in model:
            return "g5"
        elif "g4" in model:
            return "g4"
        elif "g3" in model:
            return "g3"
        return "powerpc"
    
    if "sparc" in model:
        return "sparc"
    
    if "mips" in model:
        return "mips"
    
    if "alpha" in model:
        return "alpha"
    
    if "risc" in model or "riscv" in model:
        return "risc-v"
    
    # Check for vintage
    if "68000" in model or "mc68000" in model:
        return "68000"
    
    if "6502" in model:
        return "6502"
    
    return "unknown"


def classify_to_epoch(family: str) -> Dict:
    """Classify CPU family to silicon epoch."""
    family_key = family.lower()
    
    if family_key in SILICON_EPOCHS:
        epoch_info = SILICON_EPOCHS[family_key]
        return {
            "family": family,
            "epoch": epoch_info["epoch"],
            "year_estimate": epoch_info["year_estimate"],
            "rustchain_multiplier": epoch_info["multiplier"]
        }
    
    # Default for unknown - assume modern
    return {
        "family": family,
        "epoch": 4,
        "year_estimate": 2024,
        "rustchain_multiplier": 1.0
    }


def scan_hardware() -> Dict:
    """
    Scan and fingerprint local hardware.
    
    Returns:
        Dict with family, model, epoch, year_estimate, rustchain_multiplier
    """
    system = platform.system()
    
    if system == "Linux":
        cpu_info = get_linux_cpu_info()
    elif system == "Darwin":
        cpu_info = get_macos_cpu_info()
    elif system == "Windows":
        cpu_info = get_windows_cpu_info()
    else:
        cpu_info = {"family": "Unknown", "model": "Unknown"}
    
    if "error" in cpu_info:
        return {
            "family": "unknown",
            "model": "unknown",
            "epoch": -1,
            "year_estimate": None,
            "rustchain_multiplier": 0.0,
            "error": cpu_info["error"]
        }
    
    family = detect_cpu_family(cpu_info)
    classification = classify_to_epoch(family)
    
    return {
        "family": classification["family"],
        "model": cpu_info.get("model", "Unknown"),
        "epoch": classification["epoch"],
        "year_estimate": classification["year_estimate"],
        "rustchain_multiplier": classification["rustchain_multiplier"],
        "platform": system
    }


def main():
    """CLI entry point."""
    result = scan_hardware()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
