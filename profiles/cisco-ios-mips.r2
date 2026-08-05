# Cisco IOS MIPS32-BE — dispatcher stub
# Routes to the full cisco-ios-mips32.r2 profile.
#
# profiles_config.json routes "mips/32/cisco" here.
# This stub exists so the r2 profile loader can use a short key; it sources
# the complete IOS 15.x MIPS analysis profile which has all type, zsig, and
# analysis settings.
#
# Direct usage: r2 -i profiles/cisco-ios-mips32.r2 C1900-UN.BIN

. /root/.local/share/radare2/profiles/cisco-ios-mips32.r2
