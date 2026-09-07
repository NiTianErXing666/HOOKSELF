/*
 * anti_debug.cpp — 反调试检测
 *
 * 1) /proc/self/stat   : State 字段 't' = "stopped by debugger"(被 ptrace 暂停)；
 *                        同时取 ppid/comm 用于与 status 交叉校验（两边不一致 => 读
 *                        到的 /proc 内容被 hook 篡改，如 LD_PRELOAD 假文件/Magisk 壳）。
 * 2) /proc/self/status : TracerPid != 0 => 正被调试器 ptrace 附加；
 *                        State 含 "tracing stop" 与 stat 交叉印证；TracerPid 行缺失
 *                        或文件读不到 => /proc/self/status 被篡改；
 *                        NoNewPrivs != 0 => 有代码调用过 prctl(PR_SET_NO_NEW_PRIVS,1)
 *                        —— 注入框架指纹（frida 注入器 / zygisk / ptrace 注入装
 *                        seccomp 前都会设它）。正常 app/zygote/shell 基线恒为 0
 *                        （Pixel 5 实测）；行缺失同判篡改。
 * 3) fork + exec `cat /proc/self/status` :
 *    - 解析子进程输出中的 Name 与 PPid：Name 必须 == "cat"（exec 未被劫持/替换），
 *      PPid 必须 == 本进程 pid（fork 关系未被 hook 重定向）。
 *    - 子进程自身 TracerPid != 0 => 调试器开启了 fork/children 跟随
 *      （gdb 默认跟随子进程、IDA 附加场景下子进程会被自动 ptrace，立刻暴露）。
 *    - 子进程被信号杀死（SIGTRAP/SIGSTOP 等）或超时无输出 => 同样可疑。
 * 4) task 目录批量扫描 : getdents64 枚举 /proc/self/task，逐线程读
 *    <tid>/stat —— 任一线程 State=='t' => 被调试；pid 字段/comm/线程数与
 *    /proc/self/status 不一致 => proc 内容被伪造。
 * 5) wchan 指纹 : /proc/self/wchan 与各线程 <tid>/wchan 出现 "ptrace"
 *    (内核里被 ptrace 停止的任务 wchan=ptrace_stop) => 被调试。
 *
 * 返回值为位掩码（与 AntiDebug.java 中常量一一对应）。
 */

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <unistd.h>

#include <cerrno>
#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

// arm64 getdents64 系统调用号（bionic 不暴露包装，走 raw syscall）
#ifndef __NR_getdents64
#define __NR_getdents64 61
#endif

// 内核 linux_dirent64 ABI（<linux/dirent.h> 用户态不可用，本地声明）
struct LinuxDirent64 {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];  // 变长, '\0' 结尾
};

#ifndef ANTIDEBUG_STANDALONE
#include <jni.h>
#endif

// ---------------------------------------------------------------- 位定义
enum AntiDebugBits {
    AD_OK                  = 0,
    AD_STAT_READ_FAIL      = 1u << 0,   // 1) /proc/self/stat 读取/解析失败
    AD_STAT_TRACED         = 1u << 1,   // 1) State == 't' (stopped by debugger)
    AD_STAT_PPID_MISMATCH  = 1u << 2,   // 1) stat.ppid != status.PPid (内容被篡改)
    AD_STATUS_READ_FAIL    = 1u << 3,   // 2) /proc/self/status 读取失败/TracerPid 行缺失
    AD_STATUS_TRACER       = 1u << 4,   // 2) TracerPid != 0
    AD_STATUS_STATE_TRACE  = 1u << 5,   // 2) State 含 "tracing stop"
    AD_EXEC_FAIL           = 1u << 6,   // 3) fork/exec 失败、无输出或超时
    AD_EXEC_NAME_BAD       = 1u << 7,   // 3) 子进程输出 Name != "cat" (exec 被劫持)
    AD_EXEC_PPID_BAD       = 1u << 8,   // 3) 子进程输出 PPid != 本进程 pid
    AD_EXEC_CHILD_TRACED   = 1u << 9,   // 3) 子进程 TracerPid != 0 (调试器跟随子进程)
    AD_EXEC_CHILD_SIGNAL   = 1u << 10,  // 3) 子进程被信号杀死 (如 SIGTRAP)
    AD_STAT_NAME_MISMATCH  = 1u << 11,  // 1) stat.comm != status.Name (内容被篡改)
    AD_STATUS_TAMPERED     = 1u << 12,  // 2) status 文件本身异常 => TracerPid 读数不可信
                                        //    (非 procfs / size!=0 / 必备字段缺失 / Tgid-Pid-Uid 与自身不符)
    AD_STATUS_TRACER_BADPID = 1u << 13, // 2) TracerPid 指向的进程不存在或不可见 (数值被伪造/隐藏)
    AD_STATUS_NONPRIVS     = 1u << 14,  // 2) NoNewPrivs != 0 (注入框架 prctl(PR_SET_NO_NEW_PRIVS) 指纹)
    AD_WCHAN_PTRACE        = 1u << 15,  // 5) wchan 含 "ptrace" (ptrace_stop 指纹)
    AD_TASK_SCAN_MISMATCH  = 1u << 16,  // 4) task 批量扫描一致性校验失败
};

struct ProcStatInfo {
    std::string comm;     // 字段 2 (comm)
    char state = '?';     // 字段 3
    long ppid = -1;       // 字段 4
};

struct ProcStatusInfo {
    std::string name;     // Name
    std::string state;    // State
    long ppid = -1;       // PPid
    long tracerPid = -1;  // TracerPid
    long noNewPrivs = -1; // NoNewPrivs (-1 = 行缺失, 篡改信号)
    long threads = -1;    // Threads (-1 = 行缺失)
};

struct ExecCatResult {
    bool execOk = false;  // 拿到了子进程输出
    std::string name;     // 输出中的 Name
    long ppid = -1;       // 输出中的 PPid
    long tracerPid = -1;  // 输出中的 TracerPid
    int exitCode = -1;    // 子进程 exit code
    int termSig = 0;      // 子进程被信号杀死时的信号号
    bool timeout = false; // 读取超时（子进程疑似被调试器卡住）
};

// ---------------------------------------------------------------- 工具

static bool read_text_file(const char* path, std::string* out) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    out->clear();
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) out->append(buf, (size_t)n);
    close(fd);
    return n == 0;  // 干净读到 EOF
}

static long now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void appendf(std::string* out, const char* fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    out->append(buf);
}

// 解析 /proc/xx/stat。comm(字段2) 可能含空格和括号，因此取最后一个 ')' 之后切字段：
// ')后 token[0]=State(3) token[1]=PPid(4) token[2]=Pgrp(5) token[6]=Flags(9) ...
static bool parse_proc_stat(const std::string& s, ProcStatInfo* info) {
    size_t l = s.find('(');
    size_t r = s.rfind(')');
    if (l == std::string::npos || r == std::string::npos || r < l) return false;
    info->comm.assign(s, l + 1, r - l - 1);

    std::string rest = s.substr(r + 1);
    std::vector<char*> toks;
    char* save = nullptr;
    for (char* t = strtok_r(&rest[0], " \t\n", &save); t; t = strtok_r(nullptr, " \t\n", &save))
        toks.push_back(t);
    if (toks.size() < 2) return false;
    info->state = toks[0][0];
    info->ppid = strtol(toks[1], nullptr, 10);
    return true;
}

// 通用 "Key: Value" 行解析（/proc/xx/status 及 cat 的输出都用这个）。
// 只返回是否至少解析到了一行，未识别的 key 忽略。
static bool parse_status_kv(const std::string& s, ProcStatusInfo* info) {
    bool got = false;
    size_t start = 0;
    while (start < s.size()) {
        size_t end = s.find('\n', start);
        if (end == std::string::npos) end = s.size();
        std::string line = s.substr(start, end - start);
        start = end + 1;

        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string key = line.substr(0, colon);
        size_t vs = colon + 1;
        while (vs < line.size() && (line[vs] == ' ' || line[vs] == '\t')) vs++;
        std::string val = line.substr(vs);

        if      (key == "Name")      { info->name = val;      got = true; }
        else if (key == "State")     { info->state = val;     got = true; }
        else if (key == "PPid")      { info->ppid = strtol(val.c_str(), nullptr, 10); got = true; }
        else if (key == "TracerPid") { info->tracerPid = strtol(val.c_str(), nullptr, 10); got = true; }
        else if (key == "NoNewPrivs"){ info->noNewPrivs = strtol(val.c_str(), nullptr, 10); got = true; }
        else if (key == "Threads")   { info->threads = strtol(val.c_str(), nullptr, 10); got = true; }
    }
    return got;
}

// ---------------------------------------------------------------- 检测 1: /proc/self/stat
static unsigned check_stat(const ProcStatInfo& st, const ProcStatusInfo& ps, bool haveStatus,
                           std::string* log) {
    unsigned bits = 0;
    // 't' = stopped by debugger (ptrace tracing stop)。
    // 注意 'T' 只是 SIGSTOP/SIGTSTP 停止，可能是正常暂停，不作为调试判定。
    if (st.state == 't') bits |= AD_STAT_TRACED;

    // 与 status 交叉校验：正常的 /proc 两边必然一致，不一致说明读路径被 hook 篡改
    if (haveStatus) {
        if (st.ppid >= 0 && ps.ppid >= 0 && st.ppid != ps.ppid) bits |= AD_STAT_PPID_MISMATCH;
        if (!st.comm.empty() && !ps.name.empty() && st.comm != ps.name) bits |= AD_STAT_NAME_MISMATCH;
    }

    appendf(log, "[1] /proc/self/stat   : state=%c comm=%s ppid=%ld\n",
            st.state, st.comm.c_str(), st.ppid);
    return bits;
}

// ---------------------------------------------------------------- 检测 2: /proc/self/status
static unsigned check_status(const ProcStatusInfo& ps, std::string* log) {
    unsigned bits = 0;
    if (ps.tracerPid > 0) bits |= AD_STATUS_TRACER;
    if (ps.state.find("tracing stop") != std::string::npos) bits |= AD_STATUS_STATE_TRACE;
    // 正常基线 0（app/zygote/shell 实测均为 0）；1 = 被注入框架设置过
    if (ps.noNewPrivs > 0) bits |= AD_STATUS_NONPRIVS;

    appendf(log, "[2] /proc/self/status : name=%s state=%s ppid=%ld tracerPid=%ld noNewPrivs=%ld threads=%ld\n",
            ps.name.c_str(), ps.state.c_str(), ps.ppid, ps.tracerPid,
            ps.noNewPrivs, ps.threads);
    return bits;
}

// ---------------------------------------------------------------- 检测 3: exec cat /proc/self/status
static unsigned check_exec_cat(ExecCatResult* res, std::string* log) {
    unsigned bits = 0;
    pid_t self = getpid();

    int fds[2];
    if (pipe2(fds, O_CLOEXEC) != 0) {
        bits |= AD_EXEC_FAIL;
        appendf(log, "[3] exec cat          : pipe() failed errno=%d\n", errno);
        return bits;
    }

    pid_t child = fork();
    if (child < 0) {
        close(fds[0]);
        close(fds[1]);
        bits |= AD_EXEC_FAIL;
        appendf(log, "[3] exec cat          : fork() failed errno=%d\n", errno);
        return bits;
    }

    if (child == 0) {
        // 子进程：stdout 接管道（dup2 出来的 fd 无 CLOEXEC，exec 后保留）
        dup2(fds[1], STDOUT_FILENO);
        close(fds[0]);
        close(fds[1]);
        execl("/system/bin/cat", "cat", "/proc/self/status", (char*)NULL);
        execl("/system/xbin/cat", "cat", "/proc/self/status", (char*)NULL);
        execlp("cat", "cat", "/proc/self/status", (char*)NULL);  // 兜底走 PATH
        _exit(127);  // 全部 exec 失败
    }

    close(fds[1]);  // 父进程必须关闭写端，否则 EOF 永远不来

    // 读取子进程输出，带 3s 超时预算：
    // 若调试器停在子进程里，read 会永远阻塞，这里靠 poll 超时兜底并 SIGKILL
    std::string out;
    bool timedOut = false;
    long deadline = now_ms() + 3000;
    for (;;) {
        long left = deadline - now_ms();
        if (left <= 0) { timedOut = true; kill(child, SIGKILL); break; }
        struct pollfd p = { fds[0], POLLIN, 0 };
        int pr = poll(&p, 1, (int)left);
        if (pr < 0) { if (errno == EINTR) continue; break; }
        if (pr == 0) { timedOut = true; kill(child, SIGKILL); break; }
        char buf[4096];
        ssize_t n = read(fds[0], buf, sizeof(buf));
        if (n > 0) out.append(buf, (size_t)n);
        else if (n == 0) break;               // EOF: 子进程退出
        else if (errno != EINTR) break;
    }
    close(fds[0]);

    int status = 0;
    if (waitpid(child, &status, 0) == child) {
        if (WIFEXITED(status)) res->exitCode = WEXITSTATUS(status);
        if (WIFSIGNALED(status)) res->termSig = WTERMSIG(status);
    }

    res->execOk = !out.empty();
    if (res->execOk) {
        ProcStatusInfo childInfo{};
        res->execOk = parse_status_kv(out, &childInfo);
        res->name = childInfo.name;
        res->ppid = childInfo.ppid;
        res->tracerPid = childInfo.tracerPid;
    }

    if (!res->execOk || timedOut) {
        bits |= AD_EXEC_FAIL;   // 无输出/超时/exec 127 => 直接判失败
    } else {
        if (res->name != "cat") bits |= AD_EXEC_NAME_BAD;        // 进程名不对 => exec 被劫持/替换
        if (res->ppid != (long)self) bits |= AD_EXEC_PPID_BAD;   // ppid 不对 => fork 关系被 hook
        if (res->tracerPid > 0) bits |= AD_EXEC_CHILD_TRACED;    // 子进程被调试 => 调试器跟随子进程
    }
    if (res->termSig != 0) bits |= AD_EXEC_CHILD_SIGNAL;

    appendf(log, "[3] exec cat          : name=%s ppid=%ld(self=%d) tracerPid=%ld exit=%d sig=%d timeout=%d\n",
            res->name.c_str(), res->ppid, (int)self, res->tracerPid,
            res->exitCode, res->termSig, (int)timedOut);
    return bits;
}

// ---------------------------------------------------------------- 检测 4/5: task 批量扫描 + wchan

// getdents64 枚举 /proc/self/task 下所有线程 tid
static bool list_task_tids(std::vector<long>* tids) {
    int fd = open("/proc/self/task", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return false;
    char buf[4096];
    for (;;) {
        long n = syscall(__NR_getdents64, fd, buf, sizeof(buf));
        if (n == -1 && errno == EINTR) continue;
        if (n <= 0) break;
        char* p = buf;
        char* end = buf + n;
        while (p < end) {
            const auto* d = reinterpret_cast<const LinuxDirent64*>(p);
            if (d->d_reclen == 0) break;  // 防御: 内核返回异常记录
            const char* name = d->d_name;
            if (name[0] >= '0' && name[0] <= '9') {
                char* endp = nullptr;
                const long tid = strtol(name, &endp, 10);
                if (endp != nullptr && *endp == '\0' && tid > 0) {
                    tids->push_back(tid);
                }
            }
            p += d->d_reclen;
        }
    }
    close(fd);
    return true;
}

// 从 stat 行首解析 pid 字段（comm 取最后一个 ')'，与 parse_proc_stat 同约定）
static long stat_leading_pid(const std::string& s) {
    size_t i = 0;
    while (i < s.size() && s[i] == ' ') i++;
    long pid = 0;
    bool digits = false;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
        pid = pid * 10 + (s[i] - '0');
        i++;
        digits = true;
    }
    return digits ? pid : -1;
}

// 逐线程批量扫描：每个线程的 stat State、pid/comm 一致性、wchan 指纹。
// 线程中途退出导致的 ENOENT 属正常竞态，不算失败。
// 线程数一致性用双读防 TOCTOU：两次 task 枚举结果一致才与 Threads: 比对
// （app 线程池弹性伸缩会让单次枚举 vs status 快照产生瞬时误报）。
static unsigned check_task_scan(std::string* log) {
    unsigned bits = 0;
    std::vector<long> tids;
    std::vector<long> tidsAgain;
    const bool listed = list_task_tids(&tids);
    int tracedThreads = 0;
    int wchanPtrace = 0;
    int mismatches = 0;
    std::string firstAnomaly;

    for (const long tid : tids) {
        char statPath[64];
        snprintf(statPath, sizeof(statPath), "/proc/self/task/%ld/stat", tid);
        std::string raw;
        if (!read_text_file(statPath, &raw)) continue;  // 竞态: 线程已退出
        const long leading = stat_leading_pid(raw);
        if (leading != tid) {  // 目录 tid 与内容 pid 不符 => 伪造
            mismatches++;
            if (firstAnomaly.empty()) {
                firstAnomaly = "tid=" + std::to_string(tid) + " stat_pid=" +
                               std::to_string(leading);
            }
            continue;
        }
        ProcStatInfo st{};
        if (parse_proc_stat(raw, &st)) {
            if (st.state == 't') {
                tracedThreads++;
                if (firstAnomaly.empty()) {
                    firstAnomaly = "tid=" + std::to_string(tid) + " state=t";
                }
            }
        }
        char wchanPath[64];
        snprintf(wchanPath, sizeof(wchanPath),
                 "/proc/self/task/%ld/wchan", tid);
        std::string wchanRaw;
        if (read_text_file(wchanPath, &wchanRaw) &&
            wchanRaw.find("ptrace") != std::string::npos) {
            wchanPtrace++;
            if (firstAnomaly.empty()) {
                firstAnomaly = "tid=" + std::to_string(tid) + " wchan=" +
                               wchanRaw.substr(0, 24);
            }
        }
    }

    // 自身 wchan
    std::string selfWchan;
    if (read_text_file("/proc/self/wchan", &selfWchan) &&
        selfWchan.find("ptrace") != std::string::npos) {
        wchanPtrace++;
    }

    // 线程数一致性（双读防 TOCTOU）：扫描完成后再取一次 task 目录与当前
    // status Threads，两次枚举一致且 != Threads 才判不一致。
    const bool listedAgain = list_task_tids(&tidsAgain);
    std::string statusNow;
    ProcStatusInfo psNow{};
    const bool statusNowOk =
            read_text_file("/proc/self/status", &statusNow) &&
            parse_status_kv(statusNow, &psNow);
    const bool stable =
            listed && listedAgain && tids.size() == tidsAgain.size();
    if (stable && statusNowOk && psNow.threads >= 0 &&
        psNow.threads != static_cast<long>(tids.size())) {
        mismatches++;
        if (firstAnomaly.empty()) {
            firstAnomaly = "threads=" + std::to_string(psNow.threads) +
                           " task_entries=" + std::to_string(tids.size());
        }
    }

    if (tracedThreads > 0) bits |= AD_STAT_TRACED;   // 线程级 ptrace 停止
    if (wchanPtrace > 0) bits |= AD_WCHAN_PTRACE;
    if (mismatches > 0 || (listed && tids.empty())) bits |= AD_TASK_SCAN_MISMATCH;

    appendf(log, "[4] task scan          : entries=%zu traced=%d wchan_ptrace=%d mismatch=%d %s\n",
            tids.size(), tracedThreads, wchanPtrace, mismatches,
            firstAnomaly.c_str());
    return bits;
}

// ---------------------------------------------------------------- 汇总

static const char* bit_name(unsigned bit) {
    switch (bit) {
        case AD_STAT_READ_FAIL:     return "STAT_READ_FAIL";
        case AD_STAT_TRACED:        return "STAT_TRACED";
        case AD_STAT_PPID_MISMATCH: return "STAT_PPID_MISMATCH";
        case AD_STATUS_READ_FAIL:   return "STATUS_READ_FAIL";
        case AD_STATUS_TRACER:      return "STATUS_TRACER";
        case AD_STATUS_STATE_TRACE: return "STATUS_STATE_TRACE";
        case AD_EXEC_FAIL:          return "EXEC_FAIL";
        case AD_EXEC_NAME_BAD:      return "EXEC_NAME_BAD";
        case AD_EXEC_PPID_BAD:      return "EXEC_PPID_BAD";
        case AD_EXEC_CHILD_TRACED:  return "EXEC_CHILD_TRACED";
        case AD_EXEC_CHILD_SIGNAL:  return "EXEC_CHILD_SIGNAL";
        case AD_STAT_NAME_MISMATCH: return "STAT_NAME_MISMATCH";
        case AD_STATUS_TAMPERED:    return "STATUS_TAMPERED";
        case AD_STATUS_TRACER_BADPID: return "STATUS_TRACER_BADPID";
        case AD_STATUS_NONPRIVS:    return "STATUS_NONPRIVS";
        case AD_WCHAN_PTRACE:       return "WCHAN_PTRACE";
        case AD_TASK_SCAN_MISMATCH: return "TASK_SCAN_MISMATCH";
        default: return "?";
    }
}

static void bit_names(unsigned bits, std::string* out) {
    bool first = true;
    for (unsigned b = 0; b < 32; b++) {
        unsigned bit = 1u << b;
        if (bits & bit) {
            if (!first) out->append(",");
            out->append(bit_name(bit));
            first = false;
        }
    }
}

// 三项检测一次跑完。report 可为 NULL；返回位掩码，0 = 干净。
unsigned ad_detect_all(std::string* report) {
    unsigned bits = 0;
    std::string log;
    ProcStatInfo st{};
    ProcStatusInfo ps{};
    ExecCatResult ec{};

    std::string statRaw, statusRaw;
    bool statOk = read_text_file("/proc/self/stat", &statRaw) && parse_proc_stat(statRaw, &st);
    if (!statOk) bits |= AD_STAT_READ_FAIL;

    bool statusOk = read_text_file("/proc/self/status", &statusRaw) && parse_status_kv(statusRaw, &ps);
    if (statusOk && (ps.tracerPid < 0 || ps.noNewPrivs < 0)) statusOk = false;  // 必备行缺失 => status 被篡改
    if (!statusOk) bits |= AD_STATUS_READ_FAIL;

    if (statOk) bits |= check_stat(st, ps, statusOk, &log);
    if (statusOk) bits |= check_status(ps, &log);
    bits |= check_exec_cat(&ec, &log);
    bits |= check_task_scan(&log);

    if (report) {
        report->append("AntiDebug report:\n");
        report->append(log);
        char hdr[96];
        snprintf(hdr, sizeof(hdr), "bitmask=0x%08x verdict=%s", bits, bits ? "DETECTED" : "CLEAN");
        report->append(hdr);
        if (bits) {
            report->append(" [");
            bit_names(bits, report);
            report->append("]");
        }
        report->append("\n");
    }
    return bits;
}

// 单项入口（Java 侧可只跑其中一项）
#ifndef ANTIDEBUG_STANDALONE
static unsigned ad_check_stat_only() {
    std::string log, r;
    ProcStatInfo st{};
    ProcStatusInfo ps{};
    bool statOk = read_text_file("/proc/self/stat", &r) && parse_proc_stat(r, &st);
    if (!statOk) return AD_STAT_READ_FAIL;
    bool statusOk = read_text_file("/proc/self/status", &r) && parse_status_kv(r, &ps);
    return check_stat(st, ps, statusOk, &log);
}

static unsigned ad_check_status_only() {
    std::string log, r;
    ProcStatusInfo ps{};
    bool ok = read_text_file("/proc/self/status", &r) && parse_status_kv(r, &ps);
    if (!ok || ps.tracerPid < 0 || ps.noNewPrivs < 0) return AD_STATUS_READ_FAIL;
    return check_status(ps, &log);
}

static unsigned ad_check_exec_cat_only() {
    std::string log;
    ExecCatResult ec{};
    return check_exec_cat(&ec, &log);
}
#endif  // !ANTIDEBUG_STANDALONE

// ---------------------------------------------------------------- JNI
#ifndef ANTIDEBUG_STANDALONE
extern "C" JNIEXPORT jint JNICALL
Java_com_android_calvin_AntiDebug_nativeDetect(JNIEnv*, jobject) {
    std::string report;
    return (jint)ad_detect_all(&report);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_android_calvin_AntiDebug_nativeDetectAll(JNIEnv* env, jobject) {
    std::string report;
    ad_detect_all(&report);
    return env->NewStringUTF(report.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_android_calvin_AntiDebug_nativeCheckStat(JNIEnv*, jobject) {
    return (jint)ad_check_stat_only();
}

extern "C" JNIEXPORT jint JNICALL
Java_com_android_calvin_AntiDebug_nativeCheckStatus(JNIEnv*, jobject) {
    return (jint)ad_check_status_only();
}

extern "C" JNIEXPORT jint JNICALL
Java_com_android_calvin_AntiDebug_nativeCheckExecCat(JNIEnv*, jobject) {
    return (jint)ad_check_exec_cat_only();
}

#else  // ANTIDEBUG_STANDALONE: 宿主/adb 独立调试用

int main() {
    std::string report;
    unsigned bits = ad_detect_all(&report);
    fputs(report.c_str(), stdout);
    return bits != 0;
}

#endif
