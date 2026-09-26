#!/usr/bin/env python3
"""
Generate r2 zignatures from FreeRTOS-Kernel for ARM Cortex-M targets.

Downloads FreeRTOS-Kernel source from GitHub, compiles Cortex-M port files
using Clang (--target=arm-none-eabi), and generates zsig files for function
recognition in bare-metal RTOS firmware.

Coverage:
  freertos-cm0.zsig  — Cortex-M0/M0+ (ARMv6-M Thumb)  e.g. DJI Lightbridge MCU
  freertos-cm3.zsig  — Cortex-M3     (ARMv7-M Thumb-2) e.g. DJI gimbal, STM32F103
  freertos-cm4.zsig  — Cortex-M4/M4F (ARMv7E-M + FPU)  e.g. DJI flyc, STM32F4xx
  freertos-cm7.zsig  — Cortex-M7     (ARMv7E-M + FPU)  e.g. STM32H7xx

Key functions named in output:
  vTaskDelay, xQueueCreate, pvPortMalloc, xSemaphoreGive, xTimerCreate,
  xEventGroupCreate, vTaskSuspend, uxTaskGetStackHighWaterMark, vPortFree, ...

Requirements:
  clang >= 10 with ARM target support (apt install clang)
  rasign2 (bundled with radare2)

Usage:
  generate-freertos-zsig.py
  generate-freertos-zsig.py --version V11.1.0
  generate-freertos-zsig.py --targets cm3 cm4
  generate-freertos-zsig.py --force         # regenerate existing
"""
import argparse
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
SCRIPT_DIR  = Path(__file__).parent
R2_DATA_DIR = Path(os.environ.get("R2_DATA_DIR",
                   Path.home() / ".local" / "share" / "radare2"))
ZSIG_OUT_DIR = R2_DATA_DIR / "zigns" / "embedded" / "arm-none-eabi"
CACHE_DIR    = R2_DATA_DIR / "cache" / "freertos"

FREERTOS_DEFAULT_VERSION = "V11.1.0"
FREERTOS_TARBALL_URL = (
    "https://github.com/FreeRTOS/FreeRTOS-Kernel/archive/refs/tags/{version}.tar.gz"
)

# ---------------------------------------------------------------------------
# Cortex-M compilation targets
# ---------------------------------------------------------------------------
TARGETS = {
    "cm0": {
        "clang_flags": ["-march=armv6-m", "-mthumb"],
        "port_dir":    "portable/GCC/ARM_CM0",
        "desc":        "Cortex-M0/M0+ (ARMv6-M)",
    },
    "cm3": {
        "clang_flags": ["-march=armv7-m", "-mthumb"],
        "port_dir":    "portable/GCC/ARM_CM3",
        "desc":        "Cortex-M3 (ARMv7-M)",
    },
    "cm4": {
        "clang_flags": ["-march=armv7e-m", "-mthumb",
                        "-mfpu=fpv4-sp-d16", "-mfloat-abi=hard"],
        "port_dir":    "portable/GCC/ARM_CM4F",
        "desc":        "Cortex-M4/M4F (ARMv7E-M + FPU)",
    },
    "cm7": {
        "clang_flags": ["-march=armv7e-m", "-mthumb",
                        "-mfpu=fpv5-d16", "-mfloat-abi=hard"],
        "port_dir":    "portable/GCC/ARM_CM7/r0p1",
        "desc":        "Cortex-M7 (ARMv7E-M + FPU, r0p1)",
    },
}

# FreeRTOS kernel source files (relative to kernel root)
KERNEL_SOURCES = [
    "tasks.c",
    "queue.c",
    "list.c",
    "event_groups.c",
    "timers.c",
    "stream_buffer.c",
    "portable/MemMang/heap_4.c",
]

# ---------------------------------------------------------------------------
# Minimal FreeRTOSConfig.h — compiles for all Cortex-M variants
# ---------------------------------------------------------------------------
FREERTOS_CONFIG_H = """\
#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

/* Scheduler behaviour */
#define configUSE_PREEMPTION                    1
#define configUSE_PORT_OPTIMISED_TASK_SELECTION 0
#define configUSE_TICKLESS_IDLE                 0
#define configCPU_CLOCK_HZ                      168000000UL
#define configSYSTICK_CLOCK_HZ                  configCPU_CLOCK_HZ
#define configTICK_RATE_HZ                      1000
#define configMAX_PRIORITIES                    32
#define configMINIMAL_STACK_SIZE                128
#define configMAX_TASK_NAME_LEN                 16
#define configUSE_16_BIT_TICKS                  0
#define configIDLE_SHOULD_YIELD                 1
#define configUSE_TASK_NOTIFICATIONS            1
#define configTASK_NOTIFICATION_ARRAY_ENTRIES   3
#define configUSE_MUTEXES                       1
#define configUSE_RECURSIVE_MUTEXES             1
#define configUSE_COUNTING_SEMAPHORES           1
#define configUSE_ALTERNATIVE_API               0
#define configQUEUE_REGISTRY_SIZE               10
#define configUSE_QUEUE_SETS                    1
#define configUSE_TIME_SLICING                  1
#define configUSE_NEWLIB_REENTRANT              0
#define configENABLE_BACKWARD_COMPATIBILITY     0
#define configNUM_REGION_PARAMETERS             0
#define configSTACK_DEPTH_TYPE                  uint16_t
#define configMESSAGE_BUFFER_LENGTH_TYPE        size_t
#define configHEAP_CLEAR_MEMORY_ON_FREE         1

/* Memory */
#define configTOTAL_HEAP_SIZE                   ((size_t)(256 * 1024))
#define configAPPLICATION_ALLOCATED_HEAP        0
#define configSTACK_ALLOCATION_FROM_SEPARATE_HEAP 0

/* Hook functions */
#define configUSE_IDLE_HOOK                     0
#define configUSE_TICK_HOOK                     0
#define configCHECK_FOR_STACK_OVERFLOW          0
#define configUSE_MALLOC_FAILED_HOOK            0
#define configUSE_DAEMON_TASK_STARTUP_HOOK      0

/* Stats and trace */
#define configGENERATE_RUN_TIME_STATS           0
#define configUSE_TRACE_FACILITY                1
#define configUSE_STATS_FORMATTING_FUNCTIONS    1

/* Co-routines */
#define configUSE_CO_ROUTINES                   0
#define configMAX_CO_ROUTINE_PRIORITIES         2

/* Software timers */
#define configUSE_TIMERS                        1
#define configTIMER_TASK_PRIORITY               (configMAX_PRIORITIES - 1)
#define configTIMER_QUEUE_LENGTH                10
#define configTIMER_TASK_STACK_DEPTH            configMINIMAL_STACK_SIZE

/* Event groups / stream buffers */
#define configUSE_EVENT_GROUPS                  1

/* Cortex-M security extensions (CM23/CM33/CM0 with TrustZone) */
#define configENABLE_MPU                        0
#define configENABLE_FPU                        0
#define configENABLE_TRUSTZONE                  0
#define configRUN_FREERTOS_SECURE_ONLY          0

/* Cortex-M interrupt priorities */
#define configLIBRARY_LOWEST_INTERRUPT_PRIORITY     15
#define configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY 5
#define configKERNEL_INTERRUPT_PRIORITY    (configLIBRARY_LOWEST_INTERRUPT_PRIORITY << 4)
#define configMAX_SYSCALL_INTERRUPT_PRIORITY (configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY << 4)
#define configMAX_API_CALL_INTERRUPT_PRIORITY configMAX_SYSCALL_INTERRUPT_PRIORITY

/* API function includes */
#define INCLUDE_vTaskPrioritySet                1
#define INCLUDE_uxTaskPriorityGet               1
#define INCLUDE_vTaskDelete                     1
#define INCLUDE_vTaskSuspend                    1
#define INCLUDE_xResumeFromISR                  1
#define INCLUDE_vTaskDelayUntil                 1
#define INCLUDE_vTaskDelay                      1
#define INCLUDE_xTaskGetSchedulerState          1
#define INCLUDE_xTaskGetCurrentTaskHandle       1
#define INCLUDE_uxTaskGetStackHighWaterMark      1
#define INCLUDE_xTaskGetIdleTaskHandle          1
#define INCLUDE_eTaskGetState                   1
#define INCLUDE_xEventGroupSetBitFromISR        1
#define INCLUDE_xTimerPendFunctionCall          1
#define INCLUDE_xTaskAbortDelay                 1
#define INCLUDE_xTaskGetHandle                  1
#define INCLUDE_xTaskResumeFromISR              1

/* Assertion */
#define configASSERT(x) do { if(!(x)) { __asm volatile("bkpt #01"); } } while(0)

#endif /* FREERTOS_CONFIG_H */
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd: list, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, **kwargs)


def check_clang():
    """Verify clang supports arm-none-eabi target."""
    r = run(["clang", "--version"])
    if r.returncode != 0:
        sys.exit("clang not found. Install with: apt install clang")
    # Quick compile test
    test = run(["clang", "-target", "arm-none-eabi", "-march=armv7-m", "-mthumb",
                "-x", "c", "-c", "/dev/null", "-o", "/dev/null"])
    if test.returncode != 0:
        sys.exit("clang does not support arm-none-eabi target.\n"
                 "Install with: apt install clang")
    print(f"  clang: {r.stdout.decode().splitlines()[0].strip()}")


def download_freertos(version: str, cache_dir: Path) -> Path:
    """Download and cache FreeRTOS-Kernel tarball. Return path to extracted root."""
    tarball = cache_dir / f"FreeRTOS-Kernel-{version}.tar.gz"
    extract_dir = cache_dir / f"FreeRTOS-Kernel-{version.lstrip('V')}"

    if extract_dir.exists():
        print(f"  FreeRTOS {version}: cached at {extract_dir}")
        return extract_dir

    if not tarball.exists():
        url = FREERTOS_TARBALL_URL.format(version=version)
        print(f"  Downloading FreeRTOS-Kernel {version}...")
        try:
            urllib.request.urlretrieve(url, tarball)
        except Exception as exc:
            sys.exit(f"Download failed: {exc}\nURL: {url}")

    print(f"  Extracting {tarball.name}...")
    cache_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball, "r:gz") as tf:
        tf.extractall(cache_dir)

    # GitHub tarballs extract as FreeRTOS-Kernel-{version without V}
    candidates = [p for p in cache_dir.glob("FreeRTOS-Kernel-*") if p.is_dir()]
    if not candidates:
        sys.exit("Could not locate extracted FreeRTOS-Kernel directory")
    return candidates[0]


def compile_sources(freertos_root: Path, port_dir: str,
                    clang_flags: list, work_dir: Path) -> list[Path]:
    """Compile FreeRTOS kernel + port sources. Return list of .o paths."""
    config_dir = work_dir / "config"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "FreeRTOSConfig.h").write_text(FREERTOS_CONFIG_H)

    # Stub headers: FreeRTOS needs stdlib.h + string.h declarations only.
    # The glibc /usr/include versions pull in host-arch-specific internal
    # headers that don't exist in a cross-compile context.  Provide minimal
    # stubs that satisfy the #include directives without platform specifics.
    stubs_dir = work_dir / "stubs"
    stubs_dir.mkdir(exist_ok=True)
    (stubs_dir / "stdlib.h").write_text(
        "#pragma once\n"
        "#include <stddef.h>\n"
        "void *malloc(size_t size);\n"
        "void  free(void *ptr);\n"
        "void *calloc(size_t n, size_t size);\n"
        "void *realloc(void *ptr, size_t size);\n"
        "void  abort(void);\n"
        "void  exit(int status);\n"
    )
    (stubs_dir / "string.h").write_text(
        "#pragma once\n"
        "#include <stddef.h>\n"
        "void *memcpy(void *d, const void *s, size_t n);\n"
        "void *memmove(void *d, const void *s, size_t n);\n"
        "void *memset(void *s, int c, size_t n);\n"
        "int   memcmp(const void *s1, const void *s2, size_t n);\n"
        "size_t strlen(const char *s);\n"
        "int   strcmp(const char *a, const char *b);\n"
        "char *strcpy(char *d, const char *s);\n"
        "char *strcat(char *d, const char *s);\n"
    )
    (stubs_dir / "stdio.h").write_text(
        "#pragma once\n"
        "typedef void FILE;\n"
        "int printf(const char *fmt, ...);\n"
        "int sprintf(char *buf, const char *fmt, ...);\n"
    )

    # Clang's built-in freestanding headers (stdint.h, stddef.h, etc.)
    clang_builtins = Path(
        run(["clang", "--print-resource-dir"]).stdout.decode().strip()
    ) / "include"

    include_dirs = [
        str(stubs_dir),             # stub stdlib.h / string.h (highest priority)
        str(clang_builtins),         # stdint.h, stddef.h, etc.
        str(freertos_root / "include"),
        str(freertos_root / port_dir),
        str(config_dir),
    ]

    sources = KERNEL_SOURCES + [f"{port_dir}/port.c"]
    obj_files = []
    failed = []

    for src_rel in sources:
        src = freertos_root / src_rel
        if not src.exists():
            print(f"    SKIP (not found): {src_rel}")
            continue

        obj = work_dir / (src_rel.replace("/", "_").replace(".c", ".o"))
        inc_args = [arg for d in include_dirs for arg in ("-I", d)]
        cmd = (["clang", "--target=arm-none-eabi"] + clang_flags +
               ["-Os", "-ffunction-sections", "-fdata-sections",
                "-ffreestanding",
                "-D__GNUC__=12", "-DGCC_ARMCM4"] +
               inc_args +
               ["-c", str(src), "-o", str(obj)])

        r = run(cmd)
        if r.returncode == 0 and obj.exists():
            obj_files.append(obj)
        else:
            err = r.stderr.decode(errors="replace").strip()
            print(f"    WARN compile failed {src.name}: {err[:120]}")
            failed.append(src_rel)

    print(f"    compiled {len(obj_files)}/{len(sources)} sources"
          + (f" ({len(failed)} failed)" if failed else ""))
    return obj_files


def generate_zsig(obj_files: list[Path], out_zsig: Path, prefix: str) -> int:
    """Generate and merge zsig from .o files. Return signature count."""
    out_zsig.parent.mkdir(parents=True, exist_ok=True)
    part_zsigs = []

    with tempfile.TemporaryDirectory() as tmp:
        for obj in obj_files:
            part = Path(tmp) / f"{obj.stem}.zsig"
            r2_script = f"e zign.prefix={prefix}; aa; zg; zos {part}"
            result = run(["r2", "-q", "-c", r2_script, str(obj)],
                         timeout=60)
            if result.returncode == 0 and part.exists() and part.stat().st_size > 0:
                part_zsigs.append(str(part))

        if not part_zsigs:
            print("    ERROR: no zsig parts generated")
            return 0

        # Merge all parts in one r2 session
        import r2pipe
        r2 = r2pipe.open("malloc://1", flags=["-e", "scr.color=0", "-2"])
        for p in part_zsigs:
            r2.cmd(f"zo {p}")
        r2.cmd(f"zos {out_zsig}")
        r2.quit()

    # Count via strings for accuracy
    result = run(["strings", str(out_zsig)])
    count = sum(1 for l in result.stdout.decode().splitlines()
                if l.startswith("zign|"))
    return count


# ---------------------------------------------------------------------------
# Per-target entry point
# ---------------------------------------------------------------------------

def generate_target(target_name: str, freertos_root: Path,
                    out_dir: Path, force: bool) -> bool:
    cfg = TARGETS[target_name]
    out_zsig = out_dir / f"freertos-{target_name}.zsig"

    if out_zsig.exists() and not force:
        print(f"  freertos-{target_name}: already exists"
              f" ({out_zsig.stat().st_size:,} bytes) — skipping")
        return True

    print(f"\n  [{target_name}] {cfg['desc']}")
    port_dir = cfg["port_dir"]

    # Verify port directory exists
    if not (freertos_root / port_dir).exists():
        # Try alternate CM7 path
        alt = port_dir.replace("/r0p1", "")
        if (freertos_root / alt).exists():
            port_dir = alt
            print(f"    using alternate port path: {port_dir}")
        else:
            print(f"    SKIP: port directory not found: {port_dir}")
            return False

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        obj_files = compile_sources(freertos_root, port_dir,
                                    cfg["clang_flags"], work)
        if not obj_files:
            print(f"    ERROR: nothing compiled for {target_name}")
            return False

        count = generate_zsig(obj_files, out_zsig, prefix=f"freertos_{target_name}")

    if count > 0:
        print(f"    -> {out_zsig.name}: {count} sigs ({out_zsig.stat().st_size:,} bytes)")
        return True
    else:
        print(f"    ERROR: zsig generation failed")
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version",  default=FREERTOS_DEFAULT_VERSION,
                    help=f"FreeRTOS-Kernel tag (default: {FREERTOS_DEFAULT_VERSION})")
    ap.add_argument("--targets",  nargs="+", choices=list(TARGETS),
                    default=list(TARGETS),
                    help="Cortex-M variants to generate (default: all)")
    ap.add_argument("--output-dir",
                    help=f"Override output dir (default: {ZSIG_OUT_DIR})")
    ap.add_argument("--force", action="store_true",
                    help="Regenerate even if output zsig already exists")
    ap.add_argument("--list-targets", action="store_true",
                    help="List available targets and exit")
    args = ap.parse_args()

    if args.list_targets:
        print("Available Cortex-M targets:")
        for name, cfg in TARGETS.items():
            print(f"  {name:<8} {cfg['desc']}")
        return

    print("=== FreeRTOS zsig generator ===")
    check_clang()

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    out_dir = Path(args.output_dir) if args.output_dir else ZSIG_OUT_DIR

    freertos_root = download_freertos(args.version, CACHE_DIR)
    print(f"  FreeRTOS root: {freertos_root}")

    total = ok = 0
    for target in args.targets:
        total += 1
        try:
            if generate_target(target, freertos_root, out_dir, args.force):
                ok += 1
        except Exception as exc:
            import traceback
            print(f"  {target}: EXCEPTION: {exc}")
            traceback.print_exc()

    print(f"\n{'='*40}")
    print(f"Done: {ok}/{total} targets")
    if ok < total:
        sys.exit(1)


if __name__ == "__main__":
    main()
