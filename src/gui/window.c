// SPDX-License-Identifier: Apache-2.0
/*
 * window.c - GTK4 + libadwaita application window. Every control is wired to
 * the shared bd_config and the engine, and mirrors its state into the tray.
 */

#include "gui/gui.h"

#include <adwaita.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define BD_URL_GITHUB  "https://github.com/TaigaLinux/byedpi"
#define BD_URL_DISCORD "https://discord.gg/ABNRndZhcF"

typedef struct {
    AdwApplication *app;
    bd_config      *cfg;
    bd_engine      *engine;
    bd_tray        *tray;
    bool            start_hidden;
    bool            has_window;

    GtkWindow      *window;
    AdwToastOverlay*toasts;
    GtkWidget      *banner;       /* AdwBanner: first-run root notice */

    GtkWidget      *sw_main;      /* AdwSwitchRow: master enable   */
    GtkWidget      *status_row;   /* AdwActionRow: status          */
    GtkWidget      *status_dot;   /* GtkLabel dot                  */
    GtkWidget      *status_label; /* GtkLabel Active/Inactive      */

    GtkWidget      *entry_test;   /* AdwEntryRow: test target host */
    GtkWidget      *btn_test;     /* GtkButton: run bypass test    */
    GtkWidget      *test_result;  /* GtkLabel: inline test result  */

    GtkWidget      *combo_dns;
    GtkWidget      *entry_dns;

    GtkWidget      *scale_ttl;
    GtkWidget      *ttl_row;

    GtkWidget      *sw_http;
    GtkWidget      *sw_tls;
    GtkWidget      *sw_dns;
    GtkWidget      *sw_quic;
    GtkWidget      *sw_ipv6;

    GtkWidget      *sw_autostart;
    GtkWidget      *sw_mintray;
    GtkWidget      *sw_closetray;

    GtkWidget      *sw_verbose;
    GtkWidget      *btn_logtoggle;/* GtkButton: Show Log / Hide Log */
    GtkWidget      *log_revealer;
    GtkTextView    *logview;
    GtkTextBuffer  *logbuf;

    bool            suppress;     /* guard reentrant switch updates */
    bool            min_tray;     /* start minimized to tray        */
    bool            close_to_tray;/* X button hides instead of quits*/
} App;

/* ---- helpers ------------------------------------------------------------- */

static void show_toast(App *a, const char *text)
{
    if (a->toasts)
        adw_toast_overlay_add_toast(a->toasts, adw_toast_new(text));
}

static GtkWidget *make_switch_row(const char *title, const char *subtitle,
                                  gboolean initial)
{
    GtkWidget *r = adw_switch_row_new();
    g_object_set(r, "title", title, "subtitle", subtitle, NULL);
    adw_switch_row_set_active(ADW_SWITCH_ROW(r), initial);
    return r;
}

static gboolean is_valid_ip(const char *s)
{
    struct in_addr a4;
    struct in6_addr a6;
    if (!s || !s[0])
        return FALSE;
    return inet_pton(AF_INET, s, &a4) == 1 || inet_pton(AF_INET6, s, &a6) == 1;
}

static void set_status_ui(App *a, gboolean active)
{
    /* Dot: green + pulse when active, grey and still when inactive. */
    gtk_widget_remove_css_class(a->status_dot, "bd-active");
    gtk_widget_remove_css_class(a->status_dot, "bd-inactive");
    gtk_widget_remove_css_class(a->status_dot, "bd-pulse");
    if (active) {
        gtk_widget_add_css_class(a->status_dot, "bd-active");
        gtk_widget_add_css_class(a->status_dot, "bd-pulse");
    } else {
        gtk_widget_add_css_class(a->status_dot, "bd-inactive");
    }

    /* Label: coloured text. */
    gtk_widget_remove_css_class(a->status_label, "bd-active");
    gtk_widget_remove_css_class(a->status_label, "bd-inactive");
    gtk_widget_add_css_class(a->status_label, active ? "bd-active" : "bd-inactive");
    gtk_label_set_text(GTK_LABEL(a->status_label), active ? "Active" : "Inactive");

    /* Test button only makes sense while the bypass is running. */
    if (a->btn_test)
        gtk_widget_set_sensitive(a->btn_test, active);

    if (a->tray)
        bd_tray_set_active(a->tray, active);
}

/* ---- engine control ------------------------------------------------------ */

static void set_main_switch(App *a, gboolean on)
{
    a->suppress = true;
    adw_switch_row_set_active(ADW_SWITCH_ROW(a->sw_main), on);
    a->suppress = false;
}

static void on_main_toggled(GObject *obj, GParamSpec *ps, gpointer user)
{
    (void)ps;
    App *a = user;
    if (a->suppress)
        return;
    gboolean want = adw_switch_row_get_active(ADW_SWITCH_ROW(obj));

    if (want) {
        if (bd_engine_start(a->engine) != 0) {
            show_toast(a, "Failed to start - check that ByeDPI runs as root");
            set_main_switch(a, FALSE);
            set_status_ui(a, FALSE);
            return;
        }
        show_toast(a, "DPI bypass active");
    } else {
        bd_engine_stop(a->engine);
        show_toast(a, "DPI bypass stopped");
    }
    set_status_ui(a, bd_engine_is_running(a->engine));
}

/* ---- connection test ----------------------------------------------------- */

typedef struct { App *app; char host[256]; } TestJob;
typedef struct { App *app; gboolean ok; char msg[128]; } TestResult;

static gboolean test_done_idle(gpointer data)
{
    TestResult *r = data;
    App *a = r->app;
    gtk_label_set_text(GTK_LABEL(a->test_result), r->msg);
    gtk_widget_remove_css_class(a->test_result, "bd-ok");
    gtk_widget_remove_css_class(a->test_result, "bd-fail");
    gtk_widget_add_css_class(a->test_result, r->ok ? "bd-ok" : "bd-fail");
    /* Re-enable only if the engine is still running. */
    gtk_widget_set_sensitive(a->btn_test, bd_engine_is_running(a->engine));
    g_free(r);
    return G_SOURCE_REMOVE;
}

/* Resolve `host`, connect to port 80 and send an HTTP HEAD. Success means the
 * whole DNS -> TCP -> HTTP path completed, i.e. traffic passed through. */
static gboolean tcp_head_ok(const char *host)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    if (getaddrinfo(host, "80", &hints, &res) != 0 || !res)
        return FALSE;

    gboolean ok = FALSE;
    for (struct addrinfo *ai = res; ai && !ok; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (fd < 0)
            continue;

        int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc < 0 && errno == EINPROGRESS) {
            struct pollfd p = { .fd = fd, .events = POLLOUT };
            if (poll(&p, 1, 5000) > 0 && (p.revents & POLLOUT)) {
                int err = 0;
                socklen_t l = sizeof(err);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &l);
                rc = err ? -1 : 0;
            } else {
                rc = -1;
            }
        }

        if (rc == 0) {
            /* Back to blocking with a receive timeout for the response. */
            int fl = fcntl(fd, F_GETFL);
            fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
            struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            char req[512];
            int n = snprintf(req, sizeof(req),
                "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: ByeDPI-Test\r\n"
                "Connection: close\r\n\r\n", host);
            ssize_t sent = 0;
            while (sent < n) {
                ssize_t w = send(fd, req + sent, n - sent, MSG_NOSIGNAL);
                if (w <= 0)
                    break;
                sent += w;
            }
            if (sent == n) {
                char buf[64];
                ssize_t got = recv(fd, buf, sizeof(buf) - 1, 0);
                if (got >= 5 && strncmp(buf, "HTTP/", 5) == 0)
                    ok = TRUE;
            }
        }
        close(fd);
    }
    freeaddrinfo(res);
    return ok;
}

static gpointer test_worker(gpointer data)
{
    TestJob *j = data;
    gboolean ok = tcp_head_ok(j->host);

    TestResult *r = g_new0(TestResult, 1);
    r->app = j->app;
    r->ok  = ok;
    snprintf(r->msg, sizeof(r->msg), "%s",
             ok ? "\xE2\x9C\x93 Bypass working"    /* ✓ */
                : "\xE2\x9C\x97 Not detected");     /* ✗ */
    g_idle_add(test_done_idle, r);

    g_free(j);
    return NULL;
}

static void on_test_clicked(GtkButton *btn, gpointer user)
{
    (void)btn;
    App *a = user;
    const char *host = gtk_editable_get_text(GTK_EDITABLE(a->entry_test));
    if (!host || !host[0])
        host = "example.com";

    gtk_label_set_text(GTK_LABEL(a->test_result), "Testing\xE2\x80\xA6"); /* … */
    gtk_widget_remove_css_class(a->test_result, "bd-ok");
    gtk_widget_remove_css_class(a->test_result, "bd-fail");
    gtk_widget_set_sensitive(a->btn_test, FALSE);

    TestJob *j = g_new0(TestJob, 1);
    j->app = a;
    snprintf(j->host, sizeof(j->host), "%s", host);
    GThread *t = g_thread_new("bd-test", test_worker, j);
    if (t)
        g_thread_unref(t);
}

/* ---- config handlers ----------------------------------------------------- */

static void apply_custom_dns(App *a)
{
    const char *t = gtk_editable_get_text(GTK_EDITABLE(a->entry_dns));
    if (is_valid_ip(t)) {
        snprintf(a->cfg->dns_addr, sizeof(a->cfg->dns_addr), "%s", t);
        gtk_widget_remove_css_class(a->entry_dns, "error");
    } else {
        /* Flag the field; leave the previous valid value in the config. */
        gtk_widget_add_css_class(a->entry_dns, "error");
    }
}

static void on_dns_selected(GObject *obj, GParamSpec *ps, gpointer user)
{
    (void)ps;
    App *a = user;
    guint sel = adw_combo_row_get_selected(ADW_COMBO_ROW(obj));
    switch (sel) {
    case 0:
        snprintf(a->cfg->dns_addr, sizeof(a->cfg->dns_addr), "1.1.1.1");
        snprintf(a->cfg->dns_fallback, sizeof(a->cfg->dns_fallback), "8.8.8.8");
        gtk_widget_set_visible(a->entry_dns, FALSE);
        gtk_widget_remove_css_class(a->entry_dns, "error");
        break;
    case 1:
        snprintf(a->cfg->dns_addr, sizeof(a->cfg->dns_addr), "8.8.8.8");
        snprintf(a->cfg->dns_fallback, sizeof(a->cfg->dns_fallback), "1.1.1.1");
        gtk_widget_set_visible(a->entry_dns, FALSE);
        gtk_widget_remove_css_class(a->entry_dns, "error");
        break;
    default: /* Custom */
        gtk_widget_set_visible(a->entry_dns, TRUE);
        apply_custom_dns(a);
        break;
    }
}

static void on_dns_entry_changed(GtkEditable *e, gpointer user)
{
    (void)e;
    App *a = user;
    if (adw_combo_row_get_selected(ADW_COMBO_ROW(a->combo_dns)) != 2)
        return;
    apply_custom_dns(a);
}

static void on_ttl_changed(GtkRange *range, gpointer user)
{
    App *a = user;
    int v = (int)gtk_range_get_value(range);
    if (v < 1) v = 1;
    if (v > 10) v = 10;
    a->cfg->ttl = v;
    char sub[64];
    snprintf(sub, sizeof(sub), "Fake packet TTL: %d", v);
    g_object_set(a->ttl_row, "subtitle", sub, NULL);
}

static void on_http_toggled(GObject *o, GParamSpec *p, gpointer u)
{ (void)p; App *a = u; a->cfg->enable_http = adw_switch_row_get_active(ADW_SWITCH_ROW(o)); }
static void on_tls_toggled(GObject *o, GParamSpec *p, gpointer u)
{ (void)p; App *a = u; a->cfg->enable_tls = adw_switch_row_get_active(ADW_SWITCH_ROW(o)); }
static void on_dnsintercept_toggled(GObject *o, GParamSpec *p, gpointer u)
{ (void)p; App *a = u; a->cfg->enable_dns = adw_switch_row_get_active(ADW_SWITCH_ROW(o)); }
static void on_quic_toggled(GObject *o, GParamSpec *p, gpointer u)
{ (void)p; App *a = u; a->cfg->enable_quic = adw_switch_row_get_active(ADW_SWITCH_ROW(o)); }

static void on_ipv6_toggled(GObject *o, GParamSpec *p, gpointer u)
{
    (void)p;
    App *a = u;
    a->cfg->ipv6 = adw_switch_row_get_active(ADW_SWITCH_ROW(o));
    if (bd_engine_is_running(a->engine))
        show_toast(a, "IPv6 change applies after you toggle the bypass off/on");
}

static void refresh_autostart(App *a)
{
    if (adw_switch_row_get_active(ADW_SWITCH_ROW(a->sw_autostart))) {
        if (bd_autostart_enable(a->min_tray) != 0)
            show_toast(a, "Could not write autostart entry");
    } else {
        bd_autostart_disable();
    }
}

static void on_autostart_toggled(GObject *o, GParamSpec *p, gpointer u)
{ (void)o; (void)p; refresh_autostart((App *)u); }

static void on_mintray_toggled(GObject *o, GParamSpec *p, gpointer u)
{
    (void)p;
    App *a = u;
    a->min_tray = adw_switch_row_get_active(ADW_SWITCH_ROW(o));
    /* Keep the autostart entry's Exec line in sync if it exists. */
    if (adw_switch_row_get_active(ADW_SWITCH_ROW(a->sw_autostart)))
        refresh_autostart(a);
}

static void on_closetray_toggled(GObject *o, GParamSpec *p, gpointer u)
{
    (void)p;
    App *a = u;
    a->close_to_tray = adw_switch_row_get_active(ADW_SWITCH_ROW(o));
}

static void on_verbose_toggled(GObject *o, GParamSpec *p, gpointer u)
{
    (void)p;
    App *a = u;
    gboolean on = adw_switch_row_get_active(ADW_SWITCH_ROW(o));
    a->cfg->verbose = on;
    bd_log_set_level(on ? BD_LOG_DEBUG : BD_LOG_INFO);
}

static void on_log_toggle(GtkButton *btn, gpointer user)
{
    (void)btn;
    App *a = user;
    gboolean shown = gtk_revealer_get_reveal_child(GTK_REVEALER(a->log_revealer));
    gtk_revealer_set_reveal_child(GTK_REVEALER(a->log_revealer), !shown);
    gtk_button_set_label(GTK_BUTTON(a->btn_logtoggle),
                         !shown ? "Hide Log" : "Show Log");
}

/* ---- live log sink ------------------------------------------------------- */

#define BD_LOG_MAX_LINES 200

typedef struct { App *app; char *line; } LogMsg;

static gboolean append_log_idle(gpointer data)
{
    LogMsg *m = data;
    App *a = m->app;

    if (a->logbuf) {
        /* Keep at most BD_LOG_MAX_LINES; drop the oldest. */
        int lc = gtk_text_buffer_get_line_count(a->logbuf);
        if (lc > BD_LOG_MAX_LINES) {
            GtkTextIter s, e;
            gtk_text_buffer_get_start_iter(a->logbuf, &s);
            e = s;
            gtk_text_iter_forward_lines(&e, lc - BD_LOG_MAX_LINES);
            gtk_text_buffer_delete(a->logbuf, &s, &e);
        }
        GtkTextIter end;
        gtk_text_buffer_get_end_iter(a->logbuf, &end);
        gtk_text_buffer_insert(a->logbuf, &end, m->line, -1);
        gtk_text_buffer_insert(a->logbuf, &end, "\n", 1);

        GtkTextMark *mark = gtk_text_buffer_create_mark(a->logbuf, NULL, &end, FALSE);
        gtk_text_view_scroll_to_mark(a->logview, mark, 0.0, FALSE, 0, 0);
        gtk_text_buffer_delete_mark(a->logbuf, mark);
    }
    g_free(m->line);
    g_free(m);
    return G_SOURCE_REMOVE;
}

static void gui_log_sink(bd_log_level level, const char *line, void *user)
{
    (void)level;
    App *a = user;
    LogMsg *m = g_new0(LogMsg, 1);
    m->app = a;
    m->line = g_strdup(line);
    g_idle_add(append_log_idle, m);
}

/* ---- window / tray actions ---------------------------------------------- */

static void present_window(App *a)
{
    if (!a->window)
        return;
    gtk_window_present(a->window);
}

static void do_quit(App *a)
{
    if (bd_engine_is_running(a->engine))
        bd_engine_stop(a->engine);
    g_application_quit(G_APPLICATION(a->app));
}

static gboolean on_close_request(GtkWindow *win, gpointer user)
{
    (void)win;
    App *a = user;
    /* When a tray icon is present and "Close to tray" is enabled, hide the
     * window instead of quitting. The tray "Quit" item still exits. */
    if (a->tray && a->close_to_tray) {
        gtk_widget_set_visible(GTK_WIDGET(a->window), FALSE);
        return TRUE; /* stop default destroy */
    }
    do_quit(a);
    return TRUE;
}

static void on_banner_dismiss(AdwBanner *banner, gpointer user)
{
    (void)user;
    adw_banner_set_revealed(banner, FALSE);
}

/* Tray callbacks (invoked on the GLib main context = GTK thread). */
static void tray_on_toggle(bool enable, void *user)
{
    App *a = user;
    adw_switch_row_set_active(ADW_SWITCH_ROW(a->sw_main), enable);
}
static void tray_on_show(void *user)   { present_window((App *)user); }
static void tray_on_quit(void *user)   { do_quit((App *)user); }

/* Open a URL in the user's default browser. */
static void open_uri(const char *uri)
{
    GError *err = NULL;
    if (!g_app_info_launch_default_for_uri(uri, NULL, &err)) {
        BD_WARN("could not open %s: %s", uri, err ? err->message : "unknown");
        g_clear_error(&err);
    }
}

static void on_github_clicked(GtkButton *b, gpointer u)
{ (void)b; (void)u; open_uri(BD_URL_GITHUB); }

static void on_discord_clicked(GtkButton *b, gpointer u)
{ (void)b; (void)u; open_uri(BD_URL_DISCORD); }

/* Header-bar menu actions. */
static void act_quit(GSimpleAction *ac, GVariant *p, gpointer user)
{ (void)ac; (void)p; do_quit((App *)user); }

static void act_about(GSimpleAction *ac, GVariant *p, gpointer user)
{
    (void)ac; (void)p;
    App *a = user;
    const char *comments = "A DPI circumvention tool for Linux, in the spirit "
                           "of GoodbyeDPI.";
#if ADW_CHECK_VERSION(1, 5, 0)
    GtkWidget *about = GTK_WIDGET(adw_about_dialog_new());
    g_object_set(about,
        "application-name", BYEDPI_APP_NAME,
        "application-icon", BYEDPI_APP_ID,
        "version", BYEDPI_VERSION,
        "developer-name", "The ByeDPI Authors",
        "license-type", GTK_LICENSE_APACHE_2_0,
        "website", BD_URL_GITHUB,
        "issue-url", BD_URL_GITHUB "/issues",
        "comments", comments,
        NULL);
    adw_about_dialog_add_link(ADW_ABOUT_DIALOG(about),
                              "Discord community", BD_URL_DISCORD);
    adw_dialog_present(ADW_DIALOG(about), GTK_WIDGET(a->window));
#else
    GtkWidget *about = adw_about_window_new();
    gtk_window_set_transient_for(GTK_WINDOW(about), a->window);
    g_object_set(about,
        "application-name", BYEDPI_APP_NAME,
        "application-icon", BYEDPI_APP_ID,
        "version", BYEDPI_VERSION,
        "developer-name", "The ByeDPI Authors",
        "license-type", GTK_LICENSE_APACHE_2_0,
        "website", BD_URL_GITHUB,
        "issue-url", BD_URL_GITHUB "/issues",
        "comments", comments,
        NULL);
    adw_about_window_add_link(ADW_ABOUT_WINDOW(about),
                              "Discord community", BD_URL_DISCORD);
    gtk_window_present(GTK_WINDOW(about));
#endif
}

/* ---- CSS ----------------------------------------------------------------- */

static void install_css(void)
{
    static const char css[] =
        "@keyframes bd-pulse {"
        "  0%   { opacity: 1;    }"
        "  50%  { opacity: 0.30; }"
        "  100% { opacity: 1;    }"
        "}\n"
        ".bd-dot { font-size: 20px; }\n"
        ".bd-inactive { color: #9aa0a6; }\n"
        ".bd-active   { color: #2ec27e; }\n"
        ".bd-pulse    { animation: bd-pulse 1.6s ease-in-out infinite; }\n"
        ".bd-ok   { color: #2ec27e; font-weight: bold; }\n"
        ".bd-fail { color: #e01b24; font-weight: bold; }\n"
        ".bd-log  { font-family: monospace; }\n"
        ".bd-terminal { background-color: #17181a; border-radius: 8px; }\n"
        ".bd-terminal textview, .bd-terminal text {"
        "  background-color: transparent; color: #d6d6d6;"
        "}\n"
        ".bd-primary { min-height: 62px; }\n"
        ".bd-primary .title { font-size: 1.15em; font-weight: 700; }\n";
    GtkCssProvider *p = gtk_css_provider_new();
#if GTK_CHECK_VERSION(4, 12, 0)
    gtk_css_provider_load_from_string(p, css);
#else
    gtk_css_provider_load_from_data(p, css, -1);
#endif
    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(), GTK_STYLE_PROVIDER(p),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(p);
}

/* ---- UI construction ----------------------------------------------------- */

static GtkWidget *build_status_group(App *a)
{
    GtkWidget *group = adw_preferences_group_new();
    adw_preferences_group_set_title(ADW_PREFERENCES_GROUP(group), "Bypass");

    /* Primary action: made visually prominent via the bd-primary CSS class. */
    a->sw_main = make_switch_row("DPI Bypass",
                                 "Start the circumvention engine and firewall rules",
                                 FALSE);
    gtk_widget_add_css_class(a->sw_main, "bd-primary");
    g_signal_connect(a->sw_main, "notify::active",
                     G_CALLBACK(on_main_toggled), a);
    adw_preferences_group_add(ADW_PREFERENCES_GROUP(group), a->sw_main);

    /* Status row with a coloured, pulsing dot. */
    a->status_row = adw_action_row_new();
    adw_preferences_row_set_title(ADW_PREFERENCES_ROW(a->status_row), "Status");

    a->status_dot = gtk_label_new("\xe2\x97\x8f"); /* ● */
    gtk_widget_add_css_class(a->status_dot, "bd-dot");
    gtk_widget_add_css_class(a->status_dot, "bd-inactive");
    adw_action_row_add_prefix(ADW_ACTION_ROW(a->status_row), a->status_dot);

    a->status_label = gtk_label_new("Inactive");
    gtk_widget_add_css_class(a->status_label, "bd-inactive");
    adw_action_row_add_suffix(ADW_ACTION_ROW(a->status_row), a->status_label);
    adw_preferences_group_add(ADW_PREFERENCES_GROUP(group), a->status_row);

    /* Connection test: editable target + Test button + inline result. */
    a->entry_test = adw_entry_row_new();
    g_object_set(a->entry_test, "title", "Test bypass (host)", NULL);
    gtk_editable_set_text(GTK_EDITABLE(a->entry_test), "example.com");

    a->test_result = gtk_label_new("");
    gtk_widget_set_valign(a->test_result, GTK_ALIGN_CENTER);

    a->btn_test = gtk_button_new_with_label("Test");
    gtk_widget_set_valign(a->btn_test, GTK_ALIGN_CENTER);
    gtk_widget_add_css_class(a->btn_test, "flat");
    gtk_widget_set_sensitive(a->btn_test, FALSE); /* enabled when active */
    g_signal_connect(a->btn_test, "clicked", G_CALLBACK(on_test_clicked), a);

    adw_entry_row_add_suffix(ADW_ENTRY_ROW(a->entry_test), a->test_result);
    adw_entry_row_add_suffix(ADW_ENTRY_ROW(a->entry_test), a->btn_test);
    adw_preferences_group_add(ADW_PREFERENCES_GROUP(group), a->entry_test);

    return group;
}

static GtkWidget *build_dns_group(App *a)
{
    GtkWidget *group = adw_preferences_group_new();
    adw_preferences_group_set_title(ADW_PREFERENCES_GROUP(group), "DNS");

    const char *const items[] = {
        "Cloudflare (1.1.1.1)", "Google (8.8.8.8)", "Custom", NULL
    };
    GtkStringList *model = gtk_string_list_new(items);

    a->combo_dns = adw_combo_row_new();
    g_object_set(a->combo_dns, "title", "Upstream resolver", NULL);
    adw_combo_row_set_model(ADW_COMBO_ROW(a->combo_dns), G_LIST_MODEL(model));
    adw_combo_row_set_selected(ADW_COMBO_ROW(a->combo_dns), 0);
    g_signal_connect(a->combo_dns, "notify::selected",
                     G_CALLBACK(on_dns_selected), a);
    adw_preferences_group_add(ADW_PREFERENCES_GROUP(group), a->combo_dns);

    a->entry_dns = adw_entry_row_new();
    g_object_set(a->entry_dns, "title", "Custom DNS server IP", NULL);
    gtk_editable_set_text(GTK_EDITABLE(a->entry_dns), a->cfg->dns_addr);
    gtk_widget_set_visible(a->entry_dns, FALSE);
    g_signal_connect(a->entry_dns, "changed",
                     G_CALLBACK(on_dns_entry_changed), a);
    adw_preferences_group_add(ADW_PREFERENCES_GROUP(group), a->entry_dns);

    return group;
}

static GtkWidget *build_evasion_group(App *a)
{
    GtkWidget *group = adw_preferences_group_new();
    adw_preferences_group_set_title(ADW_PREFERENCES_GROUP(group),
                                    "Evasion techniques");

    /* TTL slider row. */
    a->ttl_row = adw_action_row_new();
    adw_preferences_row_set_title(ADW_PREFERENCES_ROW(a->ttl_row), "Fake TTL");
    char sub[64];
    snprintf(sub, sizeof(sub), "Fake packet TTL: %d", a->cfg->ttl);
    g_object_set(a->ttl_row, "subtitle", sub, NULL);

    a->scale_ttl = gtk_scale_new_with_range(GTK_ORIENTATION_HORIZONTAL, 1, 10, 1);
    gtk_range_set_value(GTK_RANGE(a->scale_ttl), a->cfg->ttl);
    gtk_scale_set_draw_value(GTK_SCALE(a->scale_ttl), TRUE);
    gtk_scale_set_value_pos(GTK_SCALE(a->scale_ttl), GTK_POS_LEFT);
    for (int i = 1; i <= 10; i++)
        gtk_scale_add_mark(GTK_SCALE(a->scale_ttl), i, GTK_POS_BOTTOM, NULL);
    gtk_widget_set_hexpand(a->scale_ttl, TRUE);
    gtk_widget_set_size_request(a->scale_ttl, 220, -1);
    gtk_widget_set_valign(a->scale_ttl, GTK_ALIGN_CENTER);
    g_signal_connect(a->scale_ttl, "value-changed",
                     G_CALLBACK(on_ttl_changed), a);
    adw_action_row_add_suffix(ADW_ACTION_ROW(a->ttl_row), a->scale_ttl);
    adw_preferences_group_add(ADW_PREFERENCES_GROUP(group), a->ttl_row);

    a->sw_http = make_switch_row("HTTP splitting",
                                 "Fragment the Host header", a->cfg->enable_http);
    g_signal_connect(a->sw_http, "notify::active", G_CALLBACK(on_http_toggled), a);
    adw_preferences_group_add(ADW_PREFERENCES_GROUP(group), a->sw_http);

    a->sw_tls = make_switch_row("HTTPS / SNI splitting",
                                "Split the TLS ClientHello at the SNI",
                                a->cfg->enable_tls);
    g_signal_connect(a->sw_tls, "notify::active", G_CALLBACK(on_tls_toggled), a);
    adw_preferences_group_add(ADW_PREFERENCES_GROUP(group), a->sw_tls);

    a->sw_dns = make_switch_row("DNS interception",
                                "Forward DNS to the chosen upstream",
                                a->cfg->enable_dns);
    g_signal_connect(a->sw_dns, "notify::active",
                     G_CALLBACK(on_dnsintercept_toggled), a);
    adw_preferences_group_add(ADW_PREFERENCES_GROUP(group), a->sw_dns);

    a->sw_quic = make_switch_row("QUIC / HTTP3",
                                 "Drop QUIC Initials to force TCP fallback",
                                 a->cfg->enable_quic);
    g_signal_connect(a->sw_quic, "notify::active", G_CALLBACK(on_quic_toggled), a);
    adw_preferences_group_add(ADW_PREFERENCES_GROUP(group), a->sw_quic);

    return group;
}

static GtkWidget *build_network_group(App *a)
{
    GtkWidget *group = adw_preferences_group_new();
    adw_preferences_group_set_title(ADW_PREFERENCES_GROUP(group),
                                    "Network and startup");

    a->sw_ipv6 = make_switch_row("IPv6",
                                 "Also install ip6tables NFQUEUE rules",
                                 a->cfg->ipv6);
    g_signal_connect(a->sw_ipv6, "notify::active", G_CALLBACK(on_ipv6_toggled), a);
    adw_preferences_group_add(ADW_PREFERENCES_GROUP(group), a->sw_ipv6);

    a->sw_autostart = make_switch_row("Run on login",
                                      "Add a desktop autostart entry",
                                      bd_autostart_is_enabled());
    g_signal_connect(a->sw_autostart, "notify::active",
                     G_CALLBACK(on_autostart_toggled), a);
    adw_preferences_group_add(ADW_PREFERENCES_GROUP(group), a->sw_autostart);

    a->sw_closetray = make_switch_row("Close to tray",
                                      "Closing the window keeps ByeDPI in the tray",
                                      a->close_to_tray);
    g_signal_connect(a->sw_closetray, "notify::active",
                     G_CALLBACK(on_closetray_toggled), a);
    adw_preferences_group_add(ADW_PREFERENCES_GROUP(group), a->sw_closetray);

    a->sw_mintray = make_switch_row("Start minimized to tray",
                                    "Launch into the tray without a window",
                                    a->min_tray);
    g_signal_connect(a->sw_mintray, "notify::active",
                     G_CALLBACK(on_mintray_toggled), a);
    adw_preferences_group_add(ADW_PREFERENCES_GROUP(group), a->sw_mintray);

    return group;
}

static GtkWidget *build_log_group(App *a)
{
    GtkWidget *group = adw_preferences_group_new();
    adw_preferences_group_set_title(ADW_PREFERENCES_GROUP(group), "Activity log");
    adw_preferences_group_set_description(ADW_PREFERENCES_GROUP(group),
        "Live view of intercepted packets (domain, protocol, action)");

    /* Show/Hide toggle button in the group header, above the panel. */
    a->btn_logtoggle = gtk_button_new_with_label("Show Log");
    gtk_widget_add_css_class(a->btn_logtoggle, "flat");
    gtk_widget_set_valign(a->btn_logtoggle, GTK_ALIGN_CENTER);
    g_signal_connect(a->btn_logtoggle, "clicked", G_CALLBACK(on_log_toggle), a);
    adw_preferences_group_set_header_suffix(ADW_PREFERENCES_GROUP(group),
                                            a->btn_logtoggle);

    /* Verbose switch. */
    a->sw_verbose = make_switch_row("Verbose logging",
                                    "Log every intercepted packet",
                                    a->cfg->verbose);
    g_signal_connect(a->sw_verbose, "notify::active",
                     G_CALLBACK(on_verbose_toggled), a);
    adw_preferences_group_add(ADW_PREFERENCES_GROUP(group), a->sw_verbose);

    /* Terminal-style panel inside a revealer (toggled by the header button). */
    GtkWidget *scroller = gtk_scrolled_window_new();
    gtk_widget_set_size_request(scroller, -1, 220);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_add_css_class(scroller, "bd-terminal");

    a->logview = GTK_TEXT_VIEW(gtk_text_view_new());
    gtk_text_view_set_editable(a->logview, FALSE);
    gtk_text_view_set_cursor_visible(a->logview, FALSE);
    gtk_text_view_set_monospace(a->logview, TRUE);
    gtk_text_view_set_wrap_mode(a->logview, GTK_WRAP_NONE);
    gtk_text_view_set_left_margin(a->logview, 8);
    gtk_text_view_set_right_margin(a->logview, 8);
    gtk_text_view_set_top_margin(a->logview, 6);
    gtk_text_view_set_bottom_margin(a->logview, 6);
    gtk_widget_add_css_class(GTK_WIDGET(a->logview), "bd-log");
    a->logbuf = gtk_text_view_get_buffer(a->logview);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroller),
                                  GTK_WIDGET(a->logview));

    a->log_revealer = gtk_revealer_new();
    gtk_revealer_set_transition_type(GTK_REVEALER(a->log_revealer),
                                     GTK_REVEALER_TRANSITION_TYPE_SLIDE_DOWN);
    gtk_revealer_set_child(GTK_REVEALER(a->log_revealer), scroller);
    gtk_revealer_set_reveal_child(GTK_REVEALER(a->log_revealer), FALSE);

    GtkWidget *row = gtk_list_box_row_new();
    gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(row), FALSE);
    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), a->log_revealer);
    adw_preferences_group_add(ADW_PREFERENCES_GROUP(group), row);

    return group;
}

static void build_actions(App *a)
{
    static const GActionEntry entries[] = {
        { "quit",  act_quit,  NULL, NULL, NULL, {0} },
        { "about", act_about, NULL, NULL, NULL, {0} },
    };
    g_action_map_add_action_entries(G_ACTION_MAP(a->app), entries,
                                    G_N_ELEMENTS(entries), a);
}

static GtkWidget *build_menu_button(void)
{
    GMenu *menu = g_menu_new();
    g_menu_append(menu, "About ByeDPI", "app.about");
    g_menu_append(menu, "Quit", "app.quit");

    GtkWidget *btn = gtk_menu_button_new();
    gtk_menu_button_set_icon_name(GTK_MENU_BUTTON(btn), "open-menu-symbolic");
    gtk_menu_button_set_menu_model(GTK_MENU_BUTTON(btn), G_MENU_MODEL(menu));
    g_object_unref(menu);
    return btn;
}

static void build_window(App *a)
{
    GtkWidget *win = adw_application_window_new(GTK_APPLICATION(a->app));
    a->window = GTK_WINDOW(win);
    gtk_window_set_title(a->window, BYEDPI_APP_NAME);
    gtk_window_set_default_size(a->window, 500, 840);
    gtk_window_set_icon_name(a->window, BYEDPI_APP_ID);
    g_signal_connect(win, "close-request", G_CALLBACK(on_close_request), a);

    GtkWidget *header = adw_header_bar_new();

    /* App icon in the header bar (themed once installed). */
    GtkWidget *icon = gtk_image_new_from_icon_name(BYEDPI_APP_ID);
    gtk_image_set_pixel_size(GTK_IMAGE(icon), 24);
    adw_header_bar_pack_start(ADW_HEADER_BAR(header), icon);

    GtkWidget *title = adw_window_title_new(BYEDPI_APP_NAME, "DPI circumvention");
    adw_header_bar_set_title_widget(ADW_HEADER_BAR(header), title);
    adw_header_bar_pack_end(ADW_HEADER_BAR(header), build_menu_button());

    /* Quick links to the project and community (open in the browser). */
    GtkWidget *btn_github = gtk_button_new_from_icon_name("github-symbolic");
    gtk_widget_set_tooltip_text(btn_github, "GitHub");
    gtk_widget_add_css_class(btn_github, "flat");
    g_signal_connect(btn_github, "clicked", G_CALLBACK(on_github_clicked), a);
    adw_header_bar_pack_end(ADW_HEADER_BAR(header), btn_github);

    GtkWidget *btn_discord =
        gtk_button_new_from_icon_name("discord-symbolic");
    gtk_widget_set_tooltip_text(btn_discord, "Discord");
    gtk_widget_add_css_class(btn_discord, "flat");
    g_signal_connect(btn_discord, "clicked", G_CALLBACK(on_discord_clicked), a);
    adw_header_bar_pack_end(ADW_HEADER_BAR(header), btn_discord);

    /* First-run notice when not running as root. */
    a->banner = adw_banner_new(
        "ByeDPI needs root to manage firewall rules. Run with sudo.");
    adw_banner_set_button_label(ADW_BANNER(a->banner), "Dismiss");
    g_signal_connect(a->banner, "button-clicked",
                     G_CALLBACK(on_banner_dismiss), a);
    adw_banner_set_revealed(ADW_BANNER(a->banner), geteuid() != 0);

    GtkWidget *page = adw_preferences_page_new();
    adw_preferences_page_add(ADW_PREFERENCES_PAGE(page), ADW_PREFERENCES_GROUP(build_status_group(a)));
    adw_preferences_page_add(ADW_PREFERENCES_PAGE(page), ADW_PREFERENCES_GROUP(build_dns_group(a)));
    adw_preferences_page_add(ADW_PREFERENCES_PAGE(page), ADW_PREFERENCES_GROUP(build_evasion_group(a)));
    adw_preferences_page_add(ADW_PREFERENCES_PAGE(page), ADW_PREFERENCES_GROUP(build_network_group(a)));
    adw_preferences_page_add(ADW_PREFERENCES_PAGE(page), ADW_PREFERENCES_GROUP(build_log_group(a)));

    a->toasts = ADW_TOAST_OVERLAY(adw_toast_overlay_new());
    adw_toast_overlay_set_child(a->toasts, page);

    GtkWidget *tv = adw_toolbar_view_new();
    adw_toolbar_view_add_top_bar(ADW_TOOLBAR_VIEW(tv), header);
    adw_toolbar_view_add_top_bar(ADW_TOOLBAR_VIEW(tv), a->banner);
    adw_toolbar_view_set_content(ADW_TOOLBAR_VIEW(tv), GTK_WIDGET(a->toasts));

    adw_application_window_set_content(ADW_APPLICATION_WINDOW(win), tv);
    a->has_window = true;
}

/* ---- application lifecycle ----------------------------------------------- */

static void on_activate(GtkApplication *app, gpointer user)
{
    (void)app;
    App *a = user;

    if (!a->has_window) {
        install_css();
        /* Make the bundled github-symbolic / discord-symbolic icons resolvable
         * by name (they are embedded via GResource). */
        gtk_icon_theme_add_resource_path(
            gtk_icon_theme_get_for_display(gdk_display_get_default()),
            "/io/github/byedpi/ByeDPI/icons");
        build_actions(a);
        build_window(a);

        bd_tray_callbacks cb = {
            .on_toggle = tray_on_toggle,
            .on_show   = tray_on_show,
            .on_quit   = tray_on_quit,
            .user      = a,
        };
        a->tray = bd_tray_new(&cb);

        /* Keep the process alive even when no window is visible (tray mode). */
        g_application_hold(G_APPLICATION(a->app));
    }

    if (!a->start_hidden)
        present_window(a);
    else
        show_toast(a, "Running in the tray");
}

int bd_gui_run(bd_config *cfg, bool start_hidden)
{
    App *a = g_new0(App, 1);
    a->cfg = cfg;
    a->start_hidden = start_hidden;
    a->min_tray = start_hidden;
    a->close_to_tray = true;

    a->engine = bd_engine_new(cfg);
    if (!a->engine) {
        BD_ERR("failed to allocate engine");
        g_free(a);
        return 1;
    }

    /* Mirror engine logs into the on-screen console. */
    bd_log_set_sink(gui_log_sink, a);

    a->app = adw_application_new(BYEDPI_APP_ID, G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(a->app, "activate", G_CALLBACK(on_activate), a);

    int status = g_application_run(G_APPLICATION(a->app), 0, NULL);

    bd_log_set_sink(NULL, NULL);
    bd_tray_free(a->tray);
    bd_engine_free(a->engine);
    g_object_unref(a->app);
    g_free(a);
    return status;
}
