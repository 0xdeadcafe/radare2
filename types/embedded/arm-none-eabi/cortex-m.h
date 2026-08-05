/*
 * ARM Cortex-M CMSIS peripheral register definitions for radare2
 *
 * Covers: Cortex-M0/M0+, Cortex-M3, Cortex-M4/M4F, Cortex-M7
 * Typical targets: STM32, NXP LPC, Nordic nRF, Atmel SAM, TI Stellaris/Tiva
 *
 * Usage:
 *   to embedded/arm-none-eabi/cortex-m.h
 *   tsc NVIC_Type      # show NVIC register layout
 *   tsc SCB_Type       # show System Control Block
 *   te IRQn_cortex_m   # show Cortex-M core exception numbers
 *
 * After loading, struct annotations appear when seeking to peripheral bases:
 *   s 0xE000E100       # NVIC base
 *   pf.NVIC_Type
 *   s 0xE000ED00       # SCB base
 *   pf.SCB_Type
 */

/* ============================================================================
 * Cortex-M Core Exception / IRQ Numbers
 * Negative = core exceptions, positive = device-specific IRQs (vendor-defined)
 * ============================================================================ */

enum IRQn_cortex_m {
    NonMaskableInt_IRQn   = -14,
    HardFault_IRQn        = -13,
    MemoryManagement_IRQn = -12,   /* Cortex-M3/M4/M7 only */
    BusFault_IRQn         = -11,   /* Cortex-M3/M4/M7 only */
    UsageFault_IRQn       = -10,   /* Cortex-M3/M4/M7 only */
    SVCall_IRQn           = -5,
    DebugMonitor_IRQn     = -4,    /* Cortex-M3/M4/M7 only */
    PendSV_IRQn           = -2,
    SysTick_IRQn          = -1
};

/* ============================================================================
 * NVIC — Nested Vectored Interrupt Controller
 * Base: 0xE000E100
 * ============================================================================ */

struct NVIC_Type {
    int ISER[8];      /* [0x000] Interrupt Set Enable Register (8 x 32 bits = 256 IRQs) */
    int RESERVED0[24];
    int ICER[8];      /* [0x080] Interrupt Clear Enable Register */
    int RESERVED1[24];
    int ISPR[8];      /* [0x100] Interrupt Set Pending Register */
    int RESERVED2[24];
    int ICPR[8];      /* [0x180] Interrupt Clear Pending Register */
    int RESERVED3[24];
    int IABR[8];      /* [0x200] Interrupt Active Bit Register (M3/M4/M7 only) */
    int RESERVED4[56];
    char IP[240];     /* [0x300] Interrupt Priority Register (8-bit each) */
    int RESERVED5[644];
    int STIR;         /* [0xE00] Software Trigger Interrupt Register */
};

/* ============================================================================
 * SCB — System Control Block
 * Base: 0xE000ED00
 * ============================================================================ */

struct SCB_Type {
    int CPUID;        /* [0x00] CPUID Base Register (RO) */
    int ICSR;         /* [0x04] Interrupt Control and State Register */
    int VTOR;         /* [0x08] Vector Table Offset Register */
    int AIRCR;        /* [0x0C] Application Interrupt and Reset Control Register */
    int SCR;          /* [0x10] System Control Register */
    int CCR;          /* [0x14] Configuration Control Register */
    char SHP[12];     /* [0x18] System Handlers Priority Registers (4-7, 8-11, 12-15) */
    int SHCSR;        /* [0x24] System Handler Control and State Register */
    int CFSR;         /* [0x28] Configurable Fault Status Register */
    int HFSR;         /* [0x2C] HardFault Status Register */
    int DFSR;         /* [0x30] Debug Fault Status Register */
    int MMFAR;        /* [0x34] MemManage Fault Address Register */
    int BFAR;         /* [0x38] BusFault Address Register */
    int AFSR;         /* [0x3C] Auxiliary Fault Status Register */
    int PFR[2];       /* [0x40] Processor Feature Register */
    int DFR;          /* [0x48] Debug Feature Register */
    int ADR;          /* [0x4C] Auxiliary Feature Register */
    int MMFR[4];      /* [0x50] Memory Model Feature Register */
    int ISAR[5];      /* [0x60] Instruction Set Attributes Register */
    int RESERVED0[5];
    int CPACR;        /* [0x88] Coprocessor Access Control Register (M4/M7 with FPU) */
};

/* AIRCR key values */
enum SCB_AIRCR {
    AIRCR_VECTKEY     = 0x05FA0000,   /* Write key (upper 16 bits) */
    AIRCR_SYSRESETREQ = 0x00000004,   /* System Reset Request bit */
    AIRCR_VECTCLRACTIVE = 0x00000002
};

/* ICSR flag bits */
enum SCB_ICSR {
    ICSR_NMIPENDSET   = 0x80000000,
    ICSR_PENDSVSET    = 0x10000000,
    ICSR_PENDSVCLR    = 0x08000000,
    ICSR_PENDSTSET    = 0x04000000,
    ICSR_PENDSTCLR    = 0x02000000,
    ICSR_ISRPENDING   = 0x00400000,
    ICSR_VECTPENDING  = 0x001FF000,
    ICSR_RETOBASE     = 0x00000800,
    ICSR_VECTACTIVE   = 0x000001FF
};

/* ============================================================================
 * SysTick — System Tick Timer
 * Base: 0xE000E010
 * ============================================================================ */

struct SysTick_Type {
    int CTRL;         /* [0x00] Control and Status Register */
    int LOAD;         /* [0x04] Reload Value Register */
    int VAL;          /* [0x08] Current Value Register */
    int CALIB;        /* [0x0C] Calibration Value Register */
};

/* SysTick CTRL bits */
enum SysTick_CTRL {
    SYSTICK_COUNTFLAG = 0x00010000,
    SYSTICK_CLKSOURCE = 0x00000004,   /* 0 = external ref, 1 = processor clock */
    SYSTICK_TICKINT   = 0x00000002,   /* 1 = enable SysTick exception */
    SYSTICK_ENABLE    = 0x00000001    /* 1 = counter enabled */
};

/* ============================================================================
 * MPU — Memory Protection Unit (Cortex-M3/M4/M7)
 * Base: 0xE000ED90
 * ============================================================================ */

struct MPU_Type {
    int TYPE;         /* [0x00] MPU Type Register (RO) */
    int CTRL;         /* [0x04] MPU Control Register */
    int RNR;          /* [0x08] MPU Region RNRber Register */
    int RBAR;         /* [0x0C] MPU Region Base Address Register */
    int RASR;         /* [0x10] MPU Region Attribute and Size Register */
    int RBAR_A1;      /* [0x14] MPU Alias 1 Region Base Address Register */
    int RASR_A1;      /* [0x18] MPU Alias 1 Region Attribute and Size Register */
    int RBAR_A2;      /* [0x1C] MPU Alias 2 Region Base Address Register */
    int RASR_A2;      /* [0x20] MPU Alias 2 Region Attribute and Size Register */
    int RBAR_A3;      /* [0x24] MPU Alias 3 Region Base Address Register */
    int RASR_A3;      /* [0x28] MPU Alias 3 Region Attribute and Size Register */
};

/* ============================================================================
 * DWT — Data Watchpoint and Trace (Cortex-M3/M4/M7)
 * Base: 0xE0001000
 * ============================================================================ */

struct DWT_Type {
    int CTRL;         /* [0x00] Control Register */
    int CYCCNT;       /* [0x04] Cycle Count Register */
    int CPICNT;       /* [0x08] CPI Count Register */
    int EXCCNT;       /* [0x0C] Exception Overhead Count Register */
    int SLEEPCNT;     /* [0x10] Sleep Count Register */
    int LSUCNT;       /* [0x14] LSU Count Register */
    int FOLDCNT;      /* [0x18] Folded-instruction Count Register */
    int PCSR;         /* [0x1C] Program Counter Sample Register */
    int COMP0;        /* [0x20] Comparator Register 0 */
    int MASK0;        /* [0x24] Mask Register 0 */
    int FUNCTION0;    /* [0x28] Function Register 0 */
    int RESERVED0;
    int COMP1;        /* [0x30] Comparator Register 1 */
    int MASK1;        /* [0x34] Mask Register 1 */
    int FUNCTION1;    /* [0x38] Function Register 1 */
    int RESERVED1;
    int COMP2;        /* [0x40] Comparator Register 2 */
    int MASK2;        /* [0x44] Mask Register 2 */
    int FUNCTION2;    /* [0x48] Function Register 2 */
    int RESERVED2;
    int COMP3;        /* [0x50] Comparator Register 3 */
    int MASK3;        /* [0x54] Mask Register 3 */
    int FUNCTION3;    /* [0x58] Function Register 3 */
};

/* ============================================================================
 * CoreDebug — Core Debug registers (Cortex-M3/M4/M7)
 * Base: 0xE000EDF0
 * ============================================================================ */

struct CoreDebug_Type {
    int DHCSR;        /* [0x00] Debug Halting Control and Status Register */
    int DCRSR;        /* [0x04] Debug Core Register Selector Register */
    int DCRDR;        /* [0x08] Debug Core Register Data Register */
    int DEMCR;        /* [0x0C] Debug Exception and Monitor Control Register */
};

/* DHCSR key + bits */
enum CoreDebug_DHCSR {
    DHCSR_DBGKEY      = 0xA05F0000,   /* Write key */
    DHCSR_S_RESET_ST  = 0x02000000,   /* Core has been reset */
    DHCSR_S_RETIRE_ST = 0x01000000,   /* Core has executed instruction */
    DHCSR_S_LOCKUP    = 0x00080000,   /* Core is locked up */
    DHCSR_S_SLEEP     = 0x00040000,   /* Core is sleeping */
    DHCSR_S_HALT      = 0x00020000,   /* Core is halted */
    DHCSR_S_REGRDY    = 0x00010000,   /* Register R/W transfer complete */
    DHCSR_C_SNAPSTALL = 0x00000020,   /* Halt after stall (M3/M4) */
    DHCSR_C_MASKINTS  = 0x00000008,   /* Mask PendSV, SysTick, external IRQs */
    DHCSR_C_STEP      = 0x00000004,   /* Single step */
    DHCSR_C_HALT      = 0x00000002,   /* Halt core */
    DHCSR_C_DEBUGEN   = 0x00000001    /* Enable debug */
};

/* ============================================================================
 * FPU — Floating Point Unit (Cortex-M4F / M7 with FP extension)
 * Base: 0xE000EF30
 * ============================================================================ */

struct FPU_Type {
    int RESERVED0;
    int FPCCR;        /* [0x04] Floating-Point Context Control Register */
    int FPCAR;        /* [0x08] Floating-Point Context Address Register */
    int FPDSCR;       /* [0x0C] Floating-Point Default Status Control Register */
    int MVFR0;        /* [0x10] Media and FP Feature Register 0 (RO) */
    int MVFR1;        /* [0x14] Media and FP Feature Register 1 (RO) */
};

/* ============================================================================
 * Peripheral base addresses (reference only — vendor-specific)
 * These match the Cortex-M standard address map
 * ============================================================================ */

enum cortex_m_base_addr {
    SCS_BASE            = 0xE000E000,   /* System Control Space */
    ITM_BASE            = 0xE0000000,   /* Instrumentation Trace Macrocell */
    DWT_BASE            = 0xE0001000,   /* Data Watchpoint and Trace */
    TPI_BASE            = 0xE0040000,   /* Trace Port Interface */
    CoreDebug_BASE      = 0xE000EDF0,   /* Core Debug */
    SysTick_BASE        = 0xE000E010,   /* SysTick Timer */
    NVIC_BASE           = 0xE000E100,   /* Nested Vectored Interrupt Controller */
    SCB_BASE            = 0xE000ED00,   /* System Control Block */
    MPU_BASE            = 0xE000ED90,   /* Memory Protection Unit */
    FPU_BASE            = 0xE000EF30    /* Floating Point Unit */
};

/* ============================================================================
 * Common CMSIS functions (vendor HAL layer, always present)
 * ============================================================================ */

void NVIC_EnableIRQ(int IRQn);
void NVIC_DisableIRQ(int IRQn);
int NVIC_GetPendingIRQ(int IRQn);
void NVIC_SetPendingIRQ(int IRQn);
void NVIC_ClearPendingIRQ(int IRQn);
int NVIC_GetActive(int IRQn);
void NVIC_SetPriority(int IRQn, int priority);
int NVIC_GetPriority(int IRQn);
void NVIC_SystemReset(void);
void __WFI(void);
void __WFE(void);
void __SEV(void);
void __ISB(void);
void __DSB(void);
void __DMB(void);
void __NOP(void);
void __BKPT(int value);
int __get_MSP(void);
void __set_MSP(int topOfMainStack);
int __get_PSP(void);
void __set_PSP(int topOfProcStack);
int __get_PRIMASK(void);
void __set_PRIMASK(int priMask);
int __get_CONTROL(void);
void __set_CONTROL(int control);

/* SysTick configuration */
int SysTick_Config(int ticks);
