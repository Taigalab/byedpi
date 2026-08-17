// SPDX-License-Identifier: Apache-2.0
/*
 * autostart.c - Manage the freedesktop autostart entry used by the
 * "Run on login" toggle.
 */

#include "gui/gui.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define AUTOSTART_BASENAME BYEDPI_APP_ID ".desktop"

static const char *config_home(void)
{
    const char *xdg = getenv("XDG_CONFIG_HOME");
    if (xdg && xdg[0])
        return xdg;
    return NULL;
}

const char *bd_autostart_path(void)
{
    static char path[1024];
    const char *xdg = config_home();
    if (xdg) {
        snprintf(path, sizeof(path), "%s/autostart/%s", xdg, AUTOSTART_BASENAME);
    } else {
        const char *home = getenv("HOME");
        if (!home)
            home = "";
        snprintf(path, sizeof(path), "%s/.config/autostart/%s",
                 home, AUTOSTART_BASENAME);
    }
    return path;
}

/* mkdir -p for the directory containing `path`. */
static int ensure_parent_dir(const char *path)
{
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", path);

    char *slash = strrchr(tmp, '/');
    if (!slash)
        return 0;
    *slash = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

bool bd_autostart_is_enabled(void)
{
    return access(bd_autostart_path(), F_OK) == 0;
}

int bd_autostart_enable(bool tray)
{
    const char *path = bd_autostart_path();
    if (ensure_parent_dir(path) != 0) {
        BD_ERR("autostart: cannot create directory: %s", strerror(errno));
        return -1;
    }

    FILE *f = fopen(path, "w");
    if (!f) {
        BD_ERR("autostart: cannot write %s: %s", path, strerror(errno));
        return -1;
    }

    fprintf(f,
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=%s\n"
        "Comment=Start Passewall at login\n"
        "Exec=passewall%s\n"
        "Icon=%s\n"
        "Terminal=false\n"
        "Categories=Network;Security;\n"
        "X-GNOME-Autostart-enabled=true\n",
        BYEDPI_APP_NAME,
        tray ? " --tray" : "",
        BYEDPI_APP_ID);

    fclose(f);
    BD_INFO("autostart enabled (%s)%s", path, tray ? " [tray]" : "");
    return 0;
}

int bd_autostart_disable(void)
{
    const char *path = bd_autostart_path();
    if (unlink(path) != 0 && errno != ENOENT) {
        BD_ERR("autostart: cannot remove %s: %s", path, strerror(errno));
        return -1;
    }
    BD_INFO("autostart disabled");
    return 0;
}
