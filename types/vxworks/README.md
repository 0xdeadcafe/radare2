# VxWorks Type Definitions

C headers for VxWorks 7 RTOS analysis. Load with `to vxworks/vxworks.h`.

## Usage

```r2
e dir.types=~/.local/share/radare2/types
to vxworks/vxworks.h
aaft

# Look up VxWorks status / task state values
te vx_task_state 0x01     # PEND
te vx_task_state 0x04     # SUSPEND
te vx_sem_opts 0x08       # SEM_INVERSION_SAFE
```

Or loaded automatically via:
- `profiles/vxworks7-x86_64.r2` — VxWorks 7 Intel BSP
- `profiles/icom-vxworks-mips.r2` — Icom AP-90M / JRC JUE-100GX (MIPS32)
- `profiles/icom-ap90m-vxworks.r2` — Icom AP-90M FIRM container

## Files

| File | Source | Key Types |
|------|--------|-----------|
| `vxworks.h` | VxWorks 7 SDK 25.09 + AP-90M/JRC analysis | Task, semaphore, socket, errno APIs |

## Key Types

| Type | Description |
|------|-------------|
| `STATUS` | `int`, `OK=0`, `ERROR=-1` |
| `SEM_ID` | Semaphore handle (`void *`) |
| `TASK_ID` | Task handle (`int`) |
| `MSG_Q_ID` | Message queue handle |
| `vx_task_state` | Task state flags enum (READY/PEND/SUSPEND/STOP/DELAY) |
| `vx_sem_opts` | Semaphore creation option flags |

## Common API Signatures (after `aaft`)

```
taskSpawn(name, priority, options, stackSize, entryPt, ...)  → TASK_ID
semBCreate(options, initialState)                             → SEM_ID
semTake(semId, timeout)                                      → STATUS
semGive(semId)                                               → STATUS
msgQCreate(maxMsgs, maxMsgLength, options)                   → MSG_Q_ID
```

## Target Platforms

| Platform | Profile |
|----------|---------|
| VxWorks 7 x86-64 (Intel BSP) | `vxworks7-x86_64.r2` |
| VxWorks 6.9 MIPS32 BE (Icom, JRC) | `icom-vxworks-mips.r2` |
| Icom AP-90M FIRM container | `icom-ap90m-vxworks.r2` |
