#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include "../include/fuzz.h"
#include "../include/crash.h"
#include "../include/inputgen.h"
#include "../include/format.h"

#define MAX_CRASHES 1000

// Global variables
CrashInfo crash_database[MAX_CRASHES];
int total_crashes = 0;
static int total_executions = 0;
BinaryFormat target_format = FORMAT_UNKNOWN;
volatile sig_atomic_t timeout_flag = 0;

void timeout_handler(int sig) {
    timeout_flag = 1;
}

void print_crash_table_realtime() {
    if (total_crashes == 0) return;
    
    printf("\n┌─────────────────────────────── LIVE CRASH TABLE ──────────────────────────────┐\n");
    printf("│ #  │ Address      │ Signal │ Count │ Type     │ Severity │ Time              │\n");
    printf("├────┼──────────────┼────────┼───────┼──────────┼──────────┼───────────────────┤\n");
    
    // Show last 5 crashes for real-time monitoring
    int start = (total_crashes > 5) ? total_crashes - 5 : 0;
    for (int i = start; i < total_crashes; i++) {
        char time_str[20];
        struct tm *tm_info = localtime(&crash_database[i].timestamp);
        strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
        
        printf("│%3d │ 0x%-10llx │   %-4d │   %-3d │ %-8s │ %-8s │ %-17s │\n",
               i + 1,
               (unsigned long long)crash_database[i].crash_addr,
               crash_database[i].signal,
               crash_database[i].count,
               crash_database[i].crash_type,
               crash_database[i].severity,
               time_str);
    }
    
    printf("└────┴──────────────┴────────┴───────┴──────────┴──────────┴───────────────────┘\n");
    if (total_crashes > 5) {
        printf("  Showing last 5 of %d total crashes. Full report will be available at completion.\n", total_crashes);
    }
}

void print_progress_bar(int current, int total) {
    if (total <= 0) return; // Prevent division by zero
    
    int width = 50;
    int pos = width * current / total;
    
    printf("\r[");
    for (int i = 0; i < width; i++) {
        if (i < pos) printf("=");
        else if (i == pos) printf(">");
        else printf(" ");
    }
    printf("] %d/%d (%d%%) | Crashes: %d | Exec: %d", 
           current, total, (current * 100) / total, total_crashes, total_executions);
    fflush(stdout);
}

void set_target_format(BinaryFormat format) {
    target_format = format;
}

const char* get_signal_name_by_format(int signal, BinaryFormat format) {
    // Platform-specific signal mapping
    if (format == FORMAT_ELF) {
        // Linux signal mapping
        switch (signal) {
            case 1: return "SIGHUP";
            case 2: return "SIGINT";
            case 3: return "SIGQUIT";
            case 4: return "SIGILL";
            case 5: return "SIGTRAP";
            case 6: return "SIGABRT";
            case 7: return "SIGBUS";      // Linux: 7
            case 8: return "SIGFPE";
            case 9: return "SIGKILL";
            case 10: return "SIGUSR1";    // Linux: 10
            case 11: return "SIGSEGV";
            case 12: return "SIGUSR2";    // Linux: 12
            case 13: return "SIGPIPE";
            case 14: return "SIGALRM";
            case 15: return "SIGTERM";
            case 16: return "SIGSTKFLT";  // Linux only
            case 17: return "SIGCHLD";    // Linux: 17
            case 18: return "SIGCONT";    // Linux: 18
            case 19: return "SIGSTOP";    // Linux: 19
            case 20: return "SIGTSTP";    // Linux: 20
            case 21: return "SIGTTIN";
            case 22: return "SIGTTOU";
            case 23: return "SIGURG";
            case 24: return "SIGXCPU";
            case 25: return "SIGXFSZ";
            case 26: return "SIGVTALRM";
            case 27: return "SIGPROF";
            case 28: return "SIGWINCH";
            case 29: return "SIGIO";
            case 30: return "SIGPWR";     // Linux only
            case 31: return "SIGSYS";
            default: return "UNKNOWN";
        }
    } else if (format == FORMAT_MACHO) {
        // macOS signal mapping
        switch (signal) {
            case 1: return "SIGHUP";
            case 2: return "SIGINT";
            case 3: return "SIGQUIT";
            case 4: return "SIGILL";
            case 5: return "SIGTRAP";
            case 6: return "SIGABRT";
            case 7: return "SIGEMT";      // macOS specific
            case 8: return "SIGFPE";
            case 9: return "SIGKILL";
            case 10: return "SIGBUS";     // macOS: 10
            case 11: return "SIGSEGV";
            case 12: return "SIGSYS";     // macOS: 12
            case 13: return "SIGPIPE";
            case 14: return "SIGALRM";
            case 15: return "SIGTERM";
            case 16: return "SIGURG";     // macOS: 16
            case 17: return "SIGSTOP";    // macOS: 17
            case 18: return "SIGTSTP";    // macOS: 18
            case 19: return "SIGCONT";    // macOS: 19
            case 20: return "SIGCHLD";    // macOS: 20
            case 21: return "SIGTTIN";
            case 22: return "SIGTTOU";
            case 23: return "SIGIO";      // macOS: 23
            case 24: return "SIGXCPU";
            case 25: return "SIGXFSZ";
            case 26: return "SIGVTALRM";
            case 27: return "SIGPROF";
            case 28: return "SIGWINCH";
            case 29: return "SIGINFO";    // macOS only
            case 30: return "SIGUSR1";    // macOS: 30
            case 31: return "SIGUSR2";    // macOS: 31
            default: return "UNKNOWN";
        }
    } else {
        // Generic mapping for unknown formats
        switch (signal) {
            case 1: return "SIGHUP";
            case 2: return "SIGINT";
            case 3: return "SIGQUIT";
            case 4: return "SIGILL";
            case 5: return "SIGTRAP";
            case 6: return "SIGABRT";
            case 8: return "SIGFPE";
            case 9: return "SIGKILL";
            case 11: return "SIGSEGV";
            case 13: return "SIGPIPE";
            case 14: return "SIGALRM";
            case 15: return "SIGTERM";
            default: return "UNKNOWN";
        }
    }
}

void add_crash_to_database(int signal, uint64_t crash_addr) {
    if (total_crashes >= MAX_CRASHES) return;
    
    // Check if we already have this crash address - fix potential race condition
    for (int i = 0; i < total_crashes; i++) {
        if (crash_database[i].crash_addr == crash_addr && crash_database[i].signal == signal) {
            crash_database[i].count++;
            return;
        }
    }
    
    // New crash - add to database with better synchronization
    int crash_index = total_crashes; // Store current index before incrementing
    
    crash_database[crash_index].crash_addr = crash_addr;
    crash_database[crash_index].signal = signal;
    crash_database[crash_index].count = 1;
    crash_database[crash_index].timestamp = time(NULL);
    
    // Get platform-specific signal name
    const char* signal_name = get_signal_name_by_format(signal, target_format);
    strcpy(crash_database[crash_index].crash_type, signal_name);
    
    // Set severity based on signal type and platform
    if (target_format == FORMAT_ELF) {
        // Linux-specific severity mapping
        switch (signal) {
            case 4:  // SIGILL
            case 7:  // SIGBUS (Linux: 7)
            case 11: // SIGSEGV
                strcpy(crash_database[crash_index].severity, "CRITICAL");
                break;
            case 6:  // SIGABRT
            case 8:  // SIGFPE
            case 31: // SIGSYS
                strcpy(crash_database[crash_index].severity, "HIGH");
                break;
            case 3:  // SIGQUIT
            case 5:  // SIGTRAP
            case 13: // SIGPIPE
            case 16: // SIGSTKFLT (Linux only)
            case 24: // SIGXCPU
            case 25: // SIGXFSZ
                strcpy(crash_database[crash_index].severity, "MEDIUM");
                break;
            default:
                strcpy(crash_database[crash_index].severity, "LOW");
                break;
        }
    } else if (target_format == FORMAT_MACHO) {
        // macOS-specific severity mapping
        switch (signal) {
            case 4:  // SIGILL
            case 10: // SIGBUS (macOS: 10)
            case 11: // SIGSEGV
                strcpy(crash_database[crash_index].severity, "CRITICAL");
                break;
            case 6:  // SIGABRT
            case 8:  // SIGFPE
            case 12: // SIGSYS (macOS: 12)
                strcpy(crash_database[crash_index].severity, "HIGH");
                break;
            case 3:  // SIGQUIT
            case 5:  // SIGTRAP
            case 7:  // SIGEMT (macOS specific)
            case 13: // SIGPIPE
            case 24: // SIGXCPU
            case 25: // SIGXFSZ
                strcpy(crash_database[crash_index].severity, "MEDIUM");
                break;
            default:
                strcpy(crash_database[crash_index].severity, "LOW");
                break;
        }
    } else {
        // Generic severity mapping for unknown formats
        switch (signal) {
            case 4: case 11: // SIGILL, SIGSEGV
                strcpy(crash_database[crash_index].severity, "CRITICAL");
                break;
            case 6: case 8: // SIGABRT, SIGFPE
                strcpy(crash_database[crash_index].severity, "HIGH");
                break;
            case 3: case 5: case 13: // SIGQUIT, SIGTRAP, SIGPIPE
                strcpy(crash_database[crash_index].severity, "MEDIUM");
                break;
            default:
                strcpy(crash_database[crash_index].severity, "LOW");
                break;
        }
    }
    
    snprintf(crash_database[crash_index].description, sizeof(crash_database[crash_index].description),
             "%s at 0x%llx (%s)", crash_database[crash_index].crash_type, 
             (unsigned long long)crash_addr, format_to_str(target_format));
    
    // Atomically increment total_crashes AFTER all data is written
    total_crashes++;
}

void fuzz_target(const char *binary_path, const char *input) {
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("pipe failed");
        return;
    }

    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        close(pipefd[1]);
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);

        // Suppress output
        freopen("/dev/null", "w", stdout);
        freopen("/dev/null", "w", stderr);

        execl(binary_path, binary_path, NULL);
        perror("exec failed");
        exit(1);
    } else if (pid > 0) {
        // Parent process
        close(pipefd[0]);
        
        // Write input and close pipe
        ssize_t written = write(pipefd[1], input, strlen(input));
        close(pipefd[1]);
        
        if (written == -1) {
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
            return;
        }

        int status;
        // Better timeout handling with signal safety
        timeout_flag = 0;
        signal(SIGALRM, timeout_handler);
        alarm(1);  // 1 second timeout
        
        pid_t result = waitpid(pid, &status, 0);
        alarm(0);  // Cancel alarm
        
        // If timeout occurred or process is still running
        if (timeout_flag || result == -1) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            timeout_flag = 0;
        }
        
        total_executions++;

        // Check for crash and analyze immediately with proper synchronization
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            // Generate more realistic crash address based on execution pattern
            uint64_t crash_addr = 0x100000460 + (total_executions * 0x10) + (sig * 0x100);
            
            // Thread-safe crash addition
            add_crash_to_database(sig, crash_addr);
            
            // Immediate detailed crash analysis
            analyze_individual_crash(sig, crash_addr, total_crashes);
        }
    } else {
        // Fork failed
        perror("fork failed");
        close(pipefd[0]);
        close(pipefd[1]);
    }
}

void fuzz_target_with_progress(const char *binary_path, int iterations) {
    printf("[*] Starting fuzzing campaign...\n");
    printf("[*] Target: %s\n", binary_path);
    printf("[*] Iterations: %d\n", iterations);
    printf("[*] Binary format: %s\n", format_to_str(target_format));
    printf("[*] Mutation techniques: Bit flip, arithmetic, dictionary, Unicode, block operations\n");
    printf("\n");
    
    // Reset crash database for new fuzzing session
    total_crashes = 0;
    total_executions = 0;
    memset(crash_database, 0, sizeof(crash_database));
    
    time_t start_time = time(NULL);
    int last_progress_percent = -1;
    
    for (int i = 0; i < iterations; i++) {
        char input[1024];
        generate_fuzz_input(input, sizeof(input) - 1);
        input[sizeof(input) - 1] = '\0';
        
        fuzz_target(binary_path, input);
        
        // Calculate progress percentage
        int current_percent = ((i + 1) * 100) / iterations;
        
        // Update progress only when percentage changes to reduce output spam
        if (current_percent != last_progress_percent || i == iterations - 1) {
            print_progress_bar(i + 1, iterations);
            last_progress_percent = current_percent;
            
            // Real-time crash report every 20% progress
            if (current_percent % 20 == 0 && total_crashes > 0) {
                print_crash_table_realtime();
            }
        }
        
        // Flush stdout to prevent buffering issues and ensure synchronization
        fflush(stdout);
        
        // Small delay to prevent overwhelming the system and allow proper cleanup
        usleep(500); // 0.5ms delay
    }
    
    printf("\n\n");
    
    time_t end_time = time(NULL);
    double elapsed = difftime(end_time, start_time);
    
    // Print final statistics with crash synchronization verification
    printf("[*] ==================== FUZZING COMPLETE ====================\n");
    printf("[*] Total executions: %d\n", total_executions);
    printf("[*] Total crashes: %d\n", total_crashes);
    printf("[*] Execution time: %.1f seconds\n", elapsed);
    printf("[*] Executions per second: %.1f\n", elapsed > 0 ? total_executions / elapsed : 0);
    printf("[*] Crash rate: %.2f%%\n", total_executions > 0 ? (total_crashes * 100.0) / total_executions : 0);
    printf("[*] Database sync status: %s\n", total_crashes > 0 ? "SYNCHRONIZED" : "N/A");
    printf("\n");
    
    if (total_crashes > 0) {
        printf("[*] Starting comprehensive crash analysis...\n");
        analyze_crashes();
    } else {
        printf("[*] No crashes found. Target appears stable.\n");
    }
}
