// SPDX-License-Identifier: Apache-2.0
/*
 * iptables.c - Install/remove the NFQUEUE rules that hand outbound traffic to
 * Passewall, plus detection of conflicting services (ufw, firewalld,
 * systemd-resolved).
 */

#include "iptables.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* The rule set, expressed as the arguments that follow the chain action.
 * The same tuples are used for insertion (-I) and deletion (-D). */
struct rule {
    const char *proto;   /* "tcp" / "udp" */
    const char *dport;   /* "80" / "443" / "53" */
};

static const struct rule kRules[] = {
    { "tcp", "80"  },
    { "tcp", "443" },
    { "udp", "53"  },
    { "udp", "443" },
};
static const int kRuleCount = (int)(sizeof(kRules) / sizeof(kRules[0]));

/* Run argv[] to completion. Returns the child's exit status (0 == success),
 * or -1 if the process could not be started. stderr/stdout are inherited so
 * failures are visible; callers that expect failure suppress logging. */
static int run(char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) {
        BD_ERR("fork: %s", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        /* Silence the "-D" probing during revert. */
        execvp(argv[0], argv);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return -1;
}

/* Run a command with stdout/stderr redirected to /dev/null. */
static int run_quiet(char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        int nul = open("/dev/null", O_WRONLY);
        if (nul >= 0) {
            dup2(nul, 1);
            dup2(nul, 2);
            if (nul > 2)
                close(nul);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return -1;
}

static char queue_arg[16];
static char mark_arg[16];

static void init_queue_arg(void)
{
    snprintf(queue_arg, sizeof(queue_arg), "%d", BYEDPI_QUEUE_NUM);
    snprintf(mark_arg, sizeof(mark_arg), "0x%x", BYEDPI_FWMARK);
}

/* The mark-skip rule: accept (and stop processing) any packet carrying our
 * fwmark, so injected packets never reach the NFQUEUE rules. */
static int mark_op(const char *bin, const char *op, int quiet)
{
    char *const argv[] = {
        (char *)bin, (char *)op, "OUTPUT",
        "-m", "mark", "--mark", mark_arg,
        "-j", "ACCEPT",
        NULL
    };
    return quiet ? run_quiet(argv) : run(argv);
}

/* op is "-I" (insert) or "-D" (delete). */
static int rule_op(const char *bin, const char *op, const struct rule *r,
                   int quiet)
{
    char *const argv[] = {
        (char *)bin, (char *)op, "OUTPUT",
        "-p", (char *)r->proto,
        "--dport", (char *)r->dport,
        "-j", "NFQUEUE",
        "--queue-num", queue_arg,
        NULL
    };
    return quiet ? run_quiet(argv) : run(argv);
}

/* Apply all rules for a single binary (iptables or ip6tables). Rolls back on
 * failure. Returns 0 on success. */
static int apply_for(const char *bin)
{
    for (int i = 0; i < kRuleCount; i++) {
        if (rule_op(bin, "-I", &kRules[i], 0) != 0) {
            BD_ERR("%s: failed to insert rule for %s/%s",
                   bin, kRules[i].proto, kRules[i].dport);
            /* Roll back the ones we already inserted. */
            for (int k = i - 1; k >= 0; k--)
                rule_op(bin, "-D", &kRules[k], 1);
            return -1;
        }
    }
    /* Insert the mark-skip rule last so it lands at the very top of OUTPUT,
     * ahead of the NFQUEUE rules. */
    if (mark_op(bin, "-I", 0) != 0) {
        BD_ERR("%s: failed to insert fwmark skip rule", bin);
        for (int k = 0; k < kRuleCount; k++)
            rule_op(bin, "-D", &kRules[k], 1);
        return -1;
    }
    BD_INFO("%s: installed %d NFQUEUE rules + skip rule (queue %d)",
            bin, kRuleCount, BYEDPI_QUEUE_NUM);
    return 0;
}

static void revert_for(const char *bin)
{
    /* Delete each rule once. Ignore errors (they may already be gone). */
    mark_op(bin, "-D", 1);
    for (int i = 0; i < kRuleCount; i++)
        rule_op(bin, "-D", &kRules[i], 1);
    BD_INFO("%s: removed NFQUEUE rules", bin);
}

int bd_iptables_apply(const bd_config *cfg)
{
    init_queue_arg();

    if (apply_for("iptables") != 0)
        return -1;

    if (cfg->ipv6) {
        if (apply_for("ip6tables") != 0) {
            /* Keep IPv4 clean if IPv6 fails. */
            revert_for("iptables");
            return -1;
        }
    }
    return 0;
}

void bd_iptables_revert(const bd_config *cfg)
{
    init_queue_arg();
    revert_for("iptables");
    if (cfg->ipv6)
        revert_for("ip6tables");
}

bool bd_service_active(const char *unit)
{
    char *const argv[] = {
        "systemctl", "is-active", "--quiet", (char *)unit, NULL
    };
    return run_quiet(argv) == 0;
}

bool bd_systemd_resolved_active(void)
{
    if (bd_service_active("systemd-resolved"))
        return true;
    /* Fallback: the stub resolver drops this file when running. */
    if (access("/run/systemd/resolve/stub-resolv.conf", 0 /* F_OK */) == 0)
        return true;
    return false;
}
