// SPDX-License-Identifier: Apache-2.0
/*
 * gui.h - GTK4/libadwaita front-end, tray integration and autostart helpers.
 * When the project is built without GUI support these declarations are simply
 * not compiled or linked; main.c guards its use with HAVE_GUI.
 */

#ifndef BYEDPI_GUI_H
#define BYEDPI_GUI_H

#include "byedpi.h"

/*
 * Run the full application: builds the window (unless start_hidden is true for
 * --tray), owns an engine bound to cfg, and blocks until the user quits.
 * Returns the process exit code.
 */
int bd_gui_run(bd_config *cfg, bool start_hidden);

/* ---- autostart (~/.config/autostart) ------------------------------------ */

/* Absolute path of the autostart .desktop entry (static buffer). */
const char *bd_autostart_path(void);

bool bd_autostart_is_enabled(void);

/* Write the entry. If tray is true, the Exec line passes --tray. Returns 0. */
int  bd_autostart_enable(bool tray);

/* Remove the entry. Returns 0 on success (or if it did not exist). */
int  bd_autostart_disable(void);

/* ---- tray (StatusNotifierItem / AppIndicator) --------------------------- */

typedef struct bd_tray bd_tray;

/* Callbacks invoked from tray menu items. */
typedef struct {
    void (*on_toggle)(bool enable, void *user); /* Enable / Disable  */
    void (*on_show)(void *user);                /* Open Window       */
    void (*on_quit)(void *user);                /* Quit              */
    void  *user;
} bd_tray_callbacks;

bd_tray *bd_tray_new(const bd_tray_callbacks *cb);
void     bd_tray_set_active(bd_tray *t, bool active);
void     bd_tray_free(bd_tray *t);

#endif /* BYEDPI_GUI_H */
