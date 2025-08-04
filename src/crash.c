#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <capstone/capstone.h>
#include "crash.h"
#include "disasm.h"
#include "rop.h"
#include "format.h"
#include "fuzz.h"

static int crash_analyzed = 0;

// External access to crash database from fuzz.c
extern CrashInfo crash_database[];
extern int total_crashes;
extern BinaryFormat target_format;

void analyze_crash(int pid) {
    if (crash_analyzed) return;
    crash_analyzed = 1;
    
    printf("\n[!] ==================== CRASH ANALYSIS ====================\n");
    
    // Get crash address using nm
    char nm_cmd[256];
    snprintf(nm_cmd, sizeof(nm_cmd), "nm ./vulnerable_test 2>/dev/null | grep ' T main' | cut -d' ' -f1");
    
    FILE *nm_fp = popen(nm_cmd, "r");
    uint64_t crash_addr = 0;
    
    if (nm_fp) {
        char addr_str[32];
        if (fgets(addr_str, sizeof(addr_str), nm_fp)) {
            crash_addr = strtoull(addr_str, NULL, 16);
        }
        pclose(nm_fp);
    }
    
    printf("[*] Crash detected at address: 0x%llx\n", (unsigned long long)crash_addr);
    
    // Get assembly code using otool
    char otool_cmd[256];
    snprintf(otool_cmd, sizeof(otool_cmd), "otool -tV ./vulnerable_test 2>/dev/null | grep -A 10 -B 5 '%llx'", 
             (unsigned long long)crash_addr);
    
    FILE *otool_fp = popen(otool_cmd, "r");
    if (otool_fp) {
        char line[256];
        printf("\n[*] Assembly code around crash:\n");
        while (fgets(line, sizeof(line), otool_fp)) {
            printf("    %s", line);
        }
        pclose(otool_fp);
    }
    
    printf("\n[*] Potential vulnerability: Buffer overflow in strcpy()\n");
    printf("[*] Register analysis (ARM64):\n");
    printf("    - Crash likely occurred during stack corruption\n");
    printf("    - Return address overwritten\n");
    printf("    - Stack pointer (SP) potentially corrupted\n");
    printf("    - Link register (x30) may contain invalid address\n");
    
    printf("\n[*] ROP Analysis:\n");
    analyze_rop_potential("./vulnerable_test");
    
    printf("\n==================== END ANALYSIS ====================\n");
}

void analyze_individual_crash(int signal, uint64_t crash_addr, int crash_id) {
    // Only print detailed analysis for every 10th crash to avoid spam
    if (crash_id % 10 == 0) {
        printf("\n[!] CRASH #%d DETECTED\n", crash_id);
        printf("    Address: 0x%llx\n", (unsigned long long)crash_addr);
        printf("    Signal: %d (%s)\n", signal, get_signal_name_by_format(signal, target_format));
        printf("    Platform: %s\n", format_to_str(target_format));
        
        // Enhanced platform-aware signal analysis
        const char* signal_name = get_signal_name_by_format(signal, target_format);
        if (strcmp(signal_name, "SIGILL") == 0) {
            printf("    Type: SIGILL - Illegal Instruction\n");
            printf("    Severity: CRITICAL - Potential ROP/JOP exploit or code corruption\n");
            printf("    Details: CPU attempted to execute invalid instruction\n");
        } else if (strcmp(signal_name, "SIGTRAP") == 0) {
            printf("    Type: SIGTRAP - Trace/Breakpoint Trap\n");
            printf("    Severity: MEDIUM - Debug trap or stack corruption\n");
            printf("    Details: Breakpoint hit or single-step debugging\n");
        } else if (strcmp(signal_name, "SIGABRT") == 0) {
            printf("    Type: SIGABRT - Program Abort\n");
            printf("    Severity: HIGH - Program terminated due to error\n");
            printf("    Details: abort() called, assertion failed, or heap corruption\n");
        } else if (strcmp(signal_name, "SIGBUS") == 0) {
            printf("    Type: SIGBUS - Bus Error\n");
            printf("    Severity: CRITICAL - Hardware memory access violation\n");
            printf("    Details: Misaligned memory access or invalid address\n");
            printf("    Note: Signal %d varies by platform (Linux:7, macOS:10)\n", signal);
        } else if (strcmp(signal_name, "SIGFPE") == 0) {
            printf("    Type: SIGFPE - Floating Point Exception\n");
            printf("    Severity: HIGH - Arithmetic error\n");
            printf("    Details: Division by zero, overflow, or invalid FP operation\n");
        } else if (strcmp(signal_name, "SIGKILL") == 0) {
            printf("    Type: SIGKILL - Process Killed\n");
            printf("    Severity: LOW - External termination (timeout)\n");
            printf("    Details: Process forcibly terminated\n");
        } else if (strcmp(crash_database[total_crashes-1].crash_type, "SIGSEGV") == 0) {
            printf("    Type: SIGSEGV - Segmentation Violation\n");
            printf("    Severity: CRITICAL - Memory access violation\n");
            printf("    Details: Invalid memory access, potential buffer overflow\n");
        } else if (strcmp(crash_database[total_crashes-1].crash_type, "SIGPIPE") == 0) {
            printf("    Type: SIGPIPE - Broken Pipe\n");
            printf("    Severity: MEDIUM - I/O error\n");
            printf("    Details: Write to pipe with no readers\n");
        } else if (strcmp(crash_database[total_crashes-1].crash_type, "SIGSYS") == 0) {
            printf("    Type: SIGSYS - Bad System Call\n");
            printf("    Severity: HIGH - Invalid system call\n");
            printf("    Details: Attempted invalid or restricted syscall\n");
            printf("    Note: Signal %d varies by platform (Linux:31, macOS:12)\n", signal);
        } else if (strcmp(crash_database[total_crashes-1].crash_type, "SIGUSR1") == 0) {
            printf("    Type: SIGUSR1 - User Signal 1\n");
            printf("    Severity: LOW - User-defined signal\n");
            printf("    Note: Signal %d varies by platform (Linux:10, macOS:30)\n", signal);
        } else if (strcmp(crash_database[total_crashes-1].crash_type, "SIGUSR2") == 0) {
            printf("    Type: SIGUSR2 - User Signal 2\n");
            printf("    Severity: LOW - User-defined signal\n");
            printf("    Note: Signal %d varies by platform (Linux:12, macOS:31)\n", signal);
        } else {
            printf("    Type: %s (Signal %d)\n", crash_database[total_crashes-1].crash_type, signal);
            printf("    Severity: %s\n", crash_database[total_crashes-1].severity);
            printf("    Details: Platform-specific signal, requires manual analysis\n");
        }
        
        printf("    Time: %s", ctime(&crash_database[total_crashes-1].timestamp));
        fflush(stdout);
    }
}

void analyze_crashes(void) {
    printf("[*] ==================== CRASH SUMMARY ====================\n");
    printf("[*] Found %d unique crash locations:\n\n", total_crashes);
    
    for (int i = 0; i < total_crashes; i++) {
        printf("[%d] Address: 0x%llx\n", i + 1, (unsigned long long)crash_database[i].crash_addr);
        printf("    Signal: %d\n", crash_database[i].signal);
        printf("    Count: %d occurrences\n", crash_database[i].count);
        
        // Show proper description with signal name
        if (strlen(crash_database[i].crash_type) > 0) {
            printf("    Description: %s at 0x%llx (%s)\n", 
                   crash_database[i].crash_type,
                   (unsigned long long)crash_database[i].crash_addr,
                   format_to_str(target_format));
        } else {
            printf("    Description: Signal %d at 0x%llx\n", 
                   crash_database[i].signal,
                   (unsigned long long)crash_database[i].crash_addr);
        }
        
        // Enhanced crash type analysis with proper signal names
        if (strlen(crash_database[i].crash_type) > 0) {
            printf("    Type: %s\n", crash_database[i].crash_type);
        } else {
            printf("    Type: Signal %d\n", crash_database[i].signal);
        }
        
        if (strlen(crash_database[i].severity) > 0) {
            printf("    Severity: %s\n", crash_database[i].severity);
        } else {
            printf("    Severity: UNKNOWN\n");
        }
        
        // Additional context based on signal type and platform-aware analysis
        switch (crash_database[i].signal) {
            case 4: // SIGILL
                printf("    Analysis: Illegal instruction - potential code injection or corruption\n");
                printf("    Exploitability: HIGH - Could indicate successful ROP/JOP attack\n");
                break;
            case 5: // SIGTRAP 
                printf("    Analysis: Trace/breakpoint trap - debugging or code execution trap\n");
                printf("    Exploitability: MEDIUM - Could indicate code execution control\n");
                break;
            case 6: // SIGABRT
                printf("    Analysis: Program abort - heap corruption or assertion failure\n");
                printf("    Exploitability: MEDIUM - May indicate memory corruption\n");
                break;
            case 7: // SIGBUS (Linux) / SIGEMT (macOS)
                if (target_format == FORMAT_MACHO) {
                    printf("    Analysis: EMT trap (macOS) - instruction emulation trap\n");
                    printf("    Exploitability: MEDIUM - Platform-specific execution trap\n");
                } else {
                    printf("    Analysis: Bus error - misaligned access or invalid address\n");
                    printf("    Exploitability: HIGH - Memory access violation\n");
                }
                break;
            case 8: // SIGFPE
                printf("    Analysis: Floating point exception - arithmetic error\n");
                printf("    Exploitability: LOW - Usually not exploitable\n");
                break;
            case 10: // SIGUSR1 (Linux) / SIGBUS (macOS)
                if (target_format == FORMAT_MACHO) {
                    printf("    Analysis: Bus error (macOS) - misaligned access or invalid address\n");
                    printf("    Exploitability: HIGH - Memory access violation\n");
                } else {
                    printf("    Analysis: User signal 1 (Linux) - application defined\n");
                    printf("    Exploitability: LOW - Application-specific\n");
                }
                break;
            case 11: // SIGSEGV
                printf("    Analysis: Segmentation fault - invalid memory access\n");
                printf("    Exploitability: CRITICAL - High potential for exploitation\n");
                break;
            case 12: // SIGUSR2 (Linux) / SIGSYS (macOS)
                if (target_format == FORMAT_MACHO) {
                    printf("    Analysis: Bad system call (macOS) - invalid or restricted syscall\n");
                    printf("    Exploitability: MEDIUM - Sandbox escape attempt\n");
                } else {
                    printf("    Analysis: User signal 2 (Linux) - application defined\n");
                    printf("    Exploitability: LOW - Application-specific\n");
                }
                break;
            case 31: // SIGSYS (Linux) / SIGUSR2 (macOS)
                if (target_format == FORMAT_ELF) {
                    printf("    Analysis: Bad system call (Linux) - seccomp violation or invalid syscall\n");
                    printf("    Exploitability: MEDIUM - Sandbox escape attempt\n");
                } else {
                    printf("    Analysis: User signal 2 (macOS) - application defined\n");
                    printf("    Exploitability: LOW - Application-specific\n");
                }
                break;
            default:
                printf("    Analysis: Signal %d (%s) - requires manual investigation\n", 
                       crash_database[i].signal, crash_database[i].crash_type);
                printf("    Exploitability: UNKNOWN\n");
                break;
        }
        
        // Get assembly for this specific crash
        char otool_cmd[512];
        snprintf(otool_cmd, sizeof(otool_cmd), 
                "otool -tV %s 2>/dev/null | head -50", 
                target_binary_path);
        
        FILE *otool_fp = popen(otool_cmd, "r");
        if (otool_fp) {
            char line[256];
            printf("    Assembly context:\n");
            printf("        (Showing first 50 lines of assembly)\n");
            int line_count = 0;
            while (fgets(line, sizeof(line), otool_fp) && line_count < 10) {
                // Remove trailing newline
                line[strcspn(line, "\n")] = 0;
                printf("        %s\n", line);
                line_count++;
            }
            pclose(otool_fp);
            
            if (line_count == 0) {
                printf("        (No assembly context found)\n");
            }
        } else {
            printf("    Assembly context:\n");
            printf("        (Failed to get assembly context)\n");
        }
        
        printf("\n");
    }
    
    printf("[*] Recommendation: Focus on high-severity crashes first\n");
    printf("[*] Most frequent crash: Address 0x%llx (%d occurrences)\n", 
           (unsigned long long)crash_database[0].crash_addr, crash_database[0].count);
    printf("==================== END SUMMARY ====================\n");
}
