/*
 * SafeGuard 初始 YARA 规则
 * 仅包含 EICAR 官方测试串规则 + 3 条通用启发式规则。
 * 更多规则请自行维护：python scripts/update_yara.py
 */
rule EICAR_Test_File
{
    meta:
        description = "EICAR 官方防病毒测试文件"
        author = "SafeGuard"
        level = 5
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        uint16(0) == 0x3558 and $eicar
}

rule Suspicious_PowerShell_EncodedCommand
{
    meta:
        description = "检测编码执行的 PowerShell 命令"
        author = "SafeGuard"
        level = 4
    strings:
        $a = "-EncodedCommand" nocase
        $b = "-e " nocase
        $c = "-EncodedCommand" nocase ascii wide
    condition:
        filesize < 2MB and any of ($a, $b, $c)
}

rule UPX_Packed_PE
{
    meta:
        description = "检测 UPX 加壳的可执行文件"
        author = "SafeGuard"
        level = 3
    strings:
        $mz = { 4D 5A }
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
    condition:
        $mz at 0 and $upx0 and $upx1
}

rule Suspicious_Autorun_INF
{
    meta:
        description = "检测可疑的 autorun.inf（U盘传播常用载体）"
        author = "SafeGuard"
        level = 4
    strings:
        $autorun = "autorun" nocase
        $open = "open=" nocase
        $shell = "shell=" nocase
    condition:
        filename matches /autorun\.inf/i and $autorun and ($open or $shell)
}
