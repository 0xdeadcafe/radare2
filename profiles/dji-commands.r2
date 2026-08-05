# DJI Firmware Analysis Commands for radare2
#
# Source this file in r2: . ~/.local/share/radare2/profiles/dji-commands.r2
# Or add to radare2rc: . ~/.local/share/radare2/profiles/dji-commands.r2

# Aliases for DJI format parsing
"(dji_xv4_hdr addr, pf.dji_xv4_header @ $0)"
"(dji_xv4_entry addr, pf.dji_xv4_entry @ $0)"
"(dji_imah_hdr addr, pf.dji_imah_header @ $0)"
"(dji_imah_chunk addr, pf.dji_imah_chunk @ $0)"
"(dji_amba_part addr, pf.amba_part_header @ $0)"
"(dji_amba_romfs addr, pf.amba_romfs_header @ $0)"
"(dji_dupc55 addr, pf.dji_dupc55_full @ $0)"

# ARM Cortex-M setup for Flight Controller (m0306)
"(dji_flyc_setup, e asm.arch=arm; e asm.bits=32; e asm.cpu=cortex; e asm.armthumb=true; e anal.hasnext=true; omb. 0x08020000; echo 'Configured for DJI Flight Controller (STM32F4 @ 0x08020000)')"

# ARM Cortex-M setup for Lightbridge MCU (m0900)
"(dji_lb_setup, e asm.arch=arm; e asm.bits=32; e asm.cpu=cortex; e asm.armthumb=true; e anal.hasnext=true; omb. 0x08000000; echo 'Configured for DJI Lightbridge MCU (STM32F103 @ 0x08000000)')"

# ARM Cortex-M setup for Gimbal (m0400/m1400)
"(dji_gimbal_setup, e asm.arch=arm; e asm.bits=32; e asm.cpu=cortex; e asm.armthumb=true; e anal.hasnext=true; omb. 0x08000000; echo 'Configured for DJI Gimbal MCU (STM32/LPC @ 0x08000000)')"

# ARM9 setup for Ambarella camera (m0100)
"(dji_amba_setup, e asm.arch=arm; e asm.bits=32; e asm.cpu=arm926; e anal.hasnext=true; omb. 0x00100000; echo 'Configured for Ambarella A9 (ARM926EJ-S @ 0x00100000)')"

# ARM9 setup for DaVinci encoder (m0800)
"(dji_dm368_setup, e asm.arch=arm; e asm.bits=32; e asm.cpu=arm926; e anal.hasnext=true; omb. 0x80000000; echo 'Configured for TI DM368 (ARM926EJ-S @ 0x80000000)')"

# Search for DJI magic signatures
"(dji_find_xv4, /x 78563412; echo 'Searching for xV4 containers (0x12345678)')"
"(dji_find_imah, /x 494d2a48; echo 'Searching for IM*H modules')"
"(dji_find_amba, /x 90eb24a3; echo 'Searching for Ambarella partitions (0xA324EB90)')"
"(dji_find_romfs, /x 8a32fc66; echo 'Searching for ROMFS (0x66FC328A)')"

# Search for common FlyC strings
"(dji_find_flyc_strings, /z g_config; /z fly_limit; /z max_height; /z max_radius)"

# Quick analysis with zignature matching
"(dji_analyze, aa; z/; echo 'Analysis complete. Run z to list matches.')"

# Print DJI analysis help
"(dji_help, echo '=== DJI Analysis Commands ==='; echo 'Setup:'; echo '  .(dji_flyc_setup)   - Configure for Flight Controller'; echo '  .(dji_lb_setup)     - Configure for Lightbridge MCU'; echo '  .(dji_gimbal_setup) - Configure for Gimbal'; echo '  .(dji_amba_setup)   - Configure for Ambarella camera'; echo '  .(dji_dm368_setup)  - Configure for DM368 encoder'; echo ''; echo 'Search:'; echo '  .(dji_find_xv4)     - Find xV4 containers'; echo '  .(dji_find_imah)    - Find IM*H modules'; echo '  .(dji_find_amba)    - Find Ambarella partitions'; echo ''; echo 'Parse headers:'; echo '  .(dji_xv4_hdr 0)    - Parse xV4 header at offset'; echo '  .(dji_imah_hdr 0)   - Parse IM*H header at offset'; echo ''; echo 'Symbols (address-based, version-specific):'; echo '  . symbols/dji/flyc/wm220_0306.r2'; echo '  . symbols/dji/flyc/P3X_V01.07.0060.r2'; echo '  .(dji_analyze)      - Analyze and match signatures')"

# Show help on load
echo "DJI commands loaded. Run .(dji_help) for usage."
