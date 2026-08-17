// SPDX-License-Identifier: Apache-2.0
/*
 * tray.c - System tray icon implemented as a freedesktop StatusNotifierItem
 * (org.kde.StatusNotifierItem) with a com.canonical.dbusmenu context menu,
 * spoken directly over GDBus.
 *
 * This avoids libayatana-appindicator, which is a GTK3 library and cannot be
 * loaded into the same process as our GTK4 UI. GDBus is part of GIO, which
 * GTK4 already depends on, so there is no extra dependency and no toolkit
 * clash. The icon is provided as an in-memory ARGB pixmap so it works without
 * the icon being installed in the active theme, and its colour changes with
 * the active/inactive state.
 */

#include "gui/gui.h"

#include <gio/gio.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Menu item identifiers. */
enum {
    ITEM_ROOT   = 0,
    ITEM_TOGGLE = 1,
    ITEM_SHOW   = 2,
    ITEM_SEP    = 3,
    ITEM_QUIT   = 4,
};

struct bd_tray {
    bd_tray_callbacks cb;
    GDBusConnection  *conn;
    guint             own_name_id;
    guint             sni_reg_id;
    guint             menu_reg_id;
    char              bus_name[64];
    gboolean          active;
    guint             revision;
};

/* ---- introspection ------------------------------------------------------- */

static const char kSniXml[] =
"<node>"
"  <interface name='org.kde.StatusNotifierItem'>"
"    <property name='Category'          type='s' access='read'/>"
"    <property name='Id'                type='s' access='read'/>"
"    <property name='Title'             type='s' access='read'/>"
"    <property name='Status'            type='s' access='read'/>"
"    <property name='WindowId'          type='i' access='read'/>"
"    <property name='IconName'          type='s' access='read'/>"
"    <property name='IconPixmap'        type='a(iiay)' access='read'/>"
"    <property name='OverlayIconName'   type='s' access='read'/>"
"    <property name='AttentionIconName' type='s' access='read'/>"
"    <property name='ToolTip'           type='(sa(iiay)ss)' access='read'/>"
"    <property name='ItemIsMenu'        type='b' access='read'/>"
"    <property name='Menu'              type='o' access='read'/>"
"    <method name='ContextMenu'>"
"      <arg name='x' type='i' direction='in'/>"
"      <arg name='y' type='i' direction='in'/>"
"    </method>"
"    <method name='Activate'>"
"      <arg name='x' type='i' direction='in'/>"
"      <arg name='y' type='i' direction='in'/>"
"    </method>"
"    <method name='SecondaryActivate'>"
"      <arg name='x' type='i' direction='in'/>"
"      <arg name='y' type='i' direction='in'/>"
"    </method>"
"    <method name='Scroll'>"
"      <arg name='delta'       type='i' direction='in'/>"
"      <arg name='orientation' type='s' direction='in'/>"
"    </method>"
"    <signal name='NewIcon'/>"
"    <signal name='NewStatus'>"
"      <arg name='status' type='s'/>"
"    </signal>"
"    <signal name='NewToolTip'/>"
"  </interface>"
"</node>";

static const char kMenuXml[] =
"<node>"
"  <interface name='com.canonical.dbusmenu'>"
"    <property name='Version'        type='u' access='read'/>"
"    <property name='Status'         type='s' access='read'/>"
"    <property name='TextDirection'  type='s' access='read'/>"
"    <property name='IconThemePath'  type='as' access='read'/>"
"    <method name='GetLayout'>"
"      <arg name='parentId'       type='i'  direction='in'/>"
"      <arg name='recursionDepth' type='i'  direction='in'/>"
"      <arg name='propertyNames'  type='as' direction='in'/>"
"      <arg name='revision'       type='u'  direction='out'/>"
"      <arg name='layout'         type='(ia{sv}av)' direction='out'/>"
"    </method>"
"    <method name='GetGroupProperties'>"
"      <arg name='ids'           type='ai' direction='in'/>"
"      <arg name='propertyNames' type='as' direction='in'/>"
"      <arg name='properties'    type='a(ia{sv})' direction='out'/>"
"    </method>"
"    <method name='GetProperty'>"
"      <arg name='id'    type='i' direction='in'/>"
"      <arg name='name'  type='s' direction='in'/>"
"      <arg name='value' type='v' direction='out'/>"
"    </method>"
"    <method name='Event'>"
"      <arg name='id'        type='i' direction='in'/>"
"      <arg name='eventId'   type='s' direction='in'/>"
"      <arg name='data'      type='v' direction='in'/>"
"      <arg name='timestamp' type='u' direction='in'/>"
"    </method>"
"    <method name='AboutToShow'>"
"      <arg name='id'         type='i' direction='in'/>"
"      <arg name='needUpdate' type='b' direction='out'/>"
"    </method>"
"    <signal name='LayoutUpdated'>"
"      <arg name='revision' type='u'/>"
"      <arg name='parent'   type='i'/>"
"    </signal>"
"    <signal name='ItemsPropertiesUpdated'>"
"      <arg name='updatedProps' type='a(ia{sv})'/>"
"      <arg name='removedProps' type='a(ias)'/>"
"    </signal>"
"  </interface>"
"</node>";

static GDBusNodeInfo *g_sni_node;
static GDBusNodeInfo *g_menu_node;

/* ---- icon pixmap --------------------------------------------------------- */

/* Build a 22x22 ARGB32 (network byte order) pixmap with a filled circle whose
 * colour reflects the active state. Returned as an 'a(iiay)' variant. */
static GVariant *build_icon_pixmap(gboolean active)
{
    const int W = 22, H = 22;
    guint8 buf[22 * 22 * 4];

    guint8 r = active ? 0x33 : 0x8a;
    guint8 g = active ? 0xc7 : 0x8a;
    guint8 b = active ? 0x59 : 0x8a;

    double cx = (W - 1) / 2.0, cy = (H - 1) / 2.0;
    double rad = 9.5;

    for (int y = 0; y < H; y++) {
        for (int x = 0; x < W; x++) {
            double dx = x - cx, dy = y - cy;
            double dist = dx * dx + dy * dy;
            guint8 a = (dist <= rad * rad) ? 0xff : 0x00;
            int i = (y * W + x) * 4;
            buf[i + 0] = a;   /* A */
            buf[i + 1] = r;   /* R */
            buf[i + 2] = g;   /* G */
            buf[i + 3] = b;   /* B */
        }
    }

    GVariant *bytes = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE,
                                                buf, sizeof(buf), 1);
    GVariantBuilder b_out;
    g_variant_builder_init(&b_out, G_VARIANT_TYPE("a(iiay)"));
    g_variant_builder_add(&b_out, "(ii@ay)", W, H, bytes);
    return g_variant_builder_end(&b_out);
}

static GVariant *empty_pixmap_array(void)
{
    GVariantBuilder b;
    g_variant_builder_init(&b, G_VARIANT_TYPE("a(iiay)"));
    return g_variant_builder_end(&b);
}

/* ---- SNI vtable ---------------------------------------------------------- */

static GVariant *sni_get_property(GDBusConnection *conn, const gchar *sender,
                                  const gchar *object_path, const gchar *iface,
                                  const gchar *name, GError **error,
                                  gpointer user_data)
{
    (void)conn; (void)sender; (void)object_path; (void)iface; (void)error;
    struct bd_tray *t = user_data;

    if (g_strcmp0(name, "Category") == 0)
        return g_variant_new_string("ApplicationStatus");
    if (g_strcmp0(name, "Id") == 0)
        return g_variant_new_string(BYEDPI_APP_ID);
    if (g_strcmp0(name, "Title") == 0)
        return g_variant_new_string(BYEDPI_APP_NAME);
    if (g_strcmp0(name, "Status") == 0)
        return g_variant_new_string("Active");
    if (g_strcmp0(name, "WindowId") == 0)
        return g_variant_new_int32(0);
    if (g_strcmp0(name, "IconName") == 0)
        return g_variant_new_string("");
    if (g_strcmp0(name, "IconPixmap") == 0)
        return build_icon_pixmap(t->active);
    if (g_strcmp0(name, "OverlayIconName") == 0 ||
        g_strcmp0(name, "AttentionIconName") == 0)
        return g_variant_new_string("");
    if (g_strcmp0(name, "ItemIsMenu") == 0)
        return g_variant_new_boolean(FALSE);
    if (g_strcmp0(name, "Menu") == 0)
        return g_variant_new_object_path("/MenuBar");
    if (g_strcmp0(name, "ToolTip") == 0) {
        return g_variant_new("(s@a(iiay)ss)", "",
                             empty_pixmap_array(),
                             t->active ? BYEDPI_APP_NAME " - Active"
                                       : BYEDPI_APP_NAME " - Inactive",
                             "");
    }
    g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_PROPERTY,
                "Unknown property %s", name);
    return NULL;
}

static void sni_method(GDBusConnection *conn, const gchar *sender,
                       const gchar *object_path, const gchar *iface,
                       const gchar *method, GVariant *params,
                       GDBusMethodInvocation *inv, gpointer user_data)
{
    (void)conn; (void)sender; (void)object_path; (void)iface; (void)params;
    struct bd_tray *t = user_data;

    if (g_strcmp0(method, "Activate") == 0) {
        if (t->cb.on_show)
            t->cb.on_show(t->cb.user);
    } else if (g_strcmp0(method, "SecondaryActivate") == 0) {
        if (t->cb.on_toggle)
            t->cb.on_toggle(!t->active, t->cb.user);
    }
    /* ContextMenu / Scroll: hosts render the menu from the Menu property. */
    g_dbus_method_invocation_return_value(inv, NULL);
}

static const GDBusInterfaceVTable kSniVtable = {
    .method_call  = sni_method,
    .get_property = sni_get_property,
    .set_property = NULL,
};

/* ---- DBusMenu vtable ----------------------------------------------------- */

static const char *toggle_label(struct bd_tray *t)
{
    return t->active ? "Disable" : "Enable";
}

/* Build the a{sv} property dict for a given menu id. */
static GVariant *item_props(struct bd_tray *t, int id)
{
    GVariantBuilder p;
    g_variant_builder_init(&p, G_VARIANT_TYPE("a{sv}"));
    switch (id) {
    case ITEM_ROOT:
        g_variant_builder_add(&p, "{sv}", "children-display",
                              g_variant_new_string("submenu"));
        break;
    case ITEM_TOGGLE:
        g_variant_builder_add(&p, "{sv}", "label",
                              g_variant_new_string(toggle_label(t)));
        g_variant_builder_add(&p, "{sv}", "enabled", g_variant_new_boolean(TRUE));
        g_variant_builder_add(&p, "{sv}", "visible", g_variant_new_boolean(TRUE));
        break;
    case ITEM_SHOW:
        g_variant_builder_add(&p, "{sv}", "label",
                              g_variant_new_string("Open Window"));
        g_variant_builder_add(&p, "{sv}", "enabled", g_variant_new_boolean(TRUE));
        g_variant_builder_add(&p, "{sv}", "visible", g_variant_new_boolean(TRUE));
        break;
    case ITEM_SEP:
        g_variant_builder_add(&p, "{sv}", "type",
                              g_variant_new_string("separator"));
        g_variant_builder_add(&p, "{sv}", "visible", g_variant_new_boolean(TRUE));
        break;
    case ITEM_QUIT:
        g_variant_builder_add(&p, "{sv}", "label", g_variant_new_string("Quit"));
        g_variant_builder_add(&p, "{sv}", "enabled", g_variant_new_boolean(TRUE));
        g_variant_builder_add(&p, "{sv}", "visible", g_variant_new_boolean(TRUE));
        break;
    default:
        break;
    }
    return g_variant_builder_end(&p);
}

/* A leaf menu node "(ia{sv}av)" with no children. */
static GVariant *leaf_node(struct bd_tray *t, int id)
{
    GVariantBuilder children;
    g_variant_builder_init(&children, G_VARIANT_TYPE("av"));
    return g_variant_new("(i@a{sv}av)", id, item_props(t, id), &children);
}

static GVariant *build_layout(struct bd_tray *t)
{
    GVariantBuilder children;
    g_variant_builder_init(&children, G_VARIANT_TYPE("av"));
    g_variant_builder_add_value(&children, g_variant_new_variant(leaf_node(t, ITEM_TOGGLE)));
    g_variant_builder_add_value(&children, g_variant_new_variant(leaf_node(t, ITEM_SHOW)));
    g_variant_builder_add_value(&children, g_variant_new_variant(leaf_node(t, ITEM_SEP)));
    g_variant_builder_add_value(&children, g_variant_new_variant(leaf_node(t, ITEM_QUIT)));

    GVariant *root = g_variant_new("(i@a{sv}av)", ITEM_ROOT,
                                   item_props(t, ITEM_ROOT), &children);
    return g_variant_new("(u@(ia{sv}av))", t->revision, root);
}

static GVariant *menu_get_property(GDBusConnection *conn, const gchar *sender,
                                   const gchar *object_path, const gchar *iface,
                                   const gchar *name, GError **error,
                                   gpointer user_data)
{
    (void)conn; (void)sender; (void)object_path; (void)iface;
    (void)user_data; (void)error;
    if (g_strcmp0(name, "Version") == 0)
        return g_variant_new_uint32(3);
    if (g_strcmp0(name, "Status") == 0)
        return g_variant_new_string("normal");
    if (g_strcmp0(name, "TextDirection") == 0)
        return g_variant_new_string("ltr");
    if (g_strcmp0(name, "IconThemePath") == 0) {
        GVariantBuilder b;
        g_variant_builder_init(&b, G_VARIANT_TYPE("as"));
        return g_variant_builder_end(&b);
    }
    g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_PROPERTY,
                "Unknown property %s", name);
    return NULL;
}

static void dispatch_item(struct bd_tray *t, int id)
{
    switch (id) {
    case ITEM_TOGGLE:
        if (t->cb.on_toggle)
            t->cb.on_toggle(!t->active, t->cb.user);
        break;
    case ITEM_SHOW:
        if (t->cb.on_show)
            t->cb.on_show(t->cb.user);
        break;
    case ITEM_QUIT:
        if (t->cb.on_quit)
            t->cb.on_quit(t->cb.user);
        break;
    default:
        break;
    }
}

static void menu_method(GDBusConnection *conn, const gchar *sender,
                        const gchar *object_path, const gchar *iface,
                        const gchar *method, GVariant *params,
                        GDBusMethodInvocation *inv, gpointer user_data)
{
    (void)conn; (void)sender; (void)object_path; (void)iface;
    struct bd_tray *t = user_data;

    if (g_strcmp0(method, "GetLayout") == 0) {
        g_dbus_method_invocation_return_value(inv, build_layout(t));
        return;
    }
    if (g_strcmp0(method, "GetGroupProperties") == 0) {
        GVariantBuilder out;
        g_variant_builder_init(&out, G_VARIANT_TYPE("a(ia{sv})"));
        for (int id = ITEM_TOGGLE; id <= ITEM_QUIT; id++)
            g_variant_builder_add(&out, "(i@a{sv})", id, item_props(t, id));
        g_dbus_method_invocation_return_value(inv,
            g_variant_new("(a(ia{sv}))", &out));
        return;
    }
    if (g_strcmp0(method, "GetProperty") == 0) {
        gint id; const gchar *name;
        g_variant_get(params, "(i&s)", &id, &name);
        GVariant *props = g_variant_ref_sink(item_props(t, id));
        GVariant *val = g_variant_lookup_value(props, name, NULL);
        g_dbus_method_invocation_return_value(inv,
            g_variant_new("(v)", val ? val : g_variant_new_string("")));
        if (val)
            g_variant_unref(val);
        g_variant_unref(props);
        return;
    }
    if (g_strcmp0(method, "Event") == 0) {
        gint id; const gchar *eventId;
        GVariant *edata = NULL;
        guint32 ts = 0;
        g_variant_get(params, "(i&svu)", &id, &eventId, &edata, &ts);
        if (g_strcmp0(eventId, "clicked") == 0)
            dispatch_item(t, id);
        if (edata)
            g_variant_unref(edata);
        g_dbus_method_invocation_return_value(inv, NULL);
        return;
    }
    if (g_strcmp0(method, "AboutToShow") == 0) {
        g_dbus_method_invocation_return_value(inv,
            g_variant_new("(b)", FALSE));
        return;
    }

    g_dbus_method_invocation_return_error(inv, G_DBUS_ERROR,
        G_DBUS_ERROR_UNKNOWN_METHOD, "Unknown method %s", method);
}

static const GDBusInterfaceVTable kMenuVtable = {
    .method_call  = menu_method,
    .get_property = menu_get_property,
    .set_property = NULL,
};

/* ---- registration -------------------------------------------------------- */

static void register_with_watcher(struct bd_tray *t)
{
    g_dbus_connection_call(t->conn,
        "org.kde.StatusNotifierWatcher",
        "/StatusNotifierWatcher",
        "org.kde.StatusNotifierWatcher",
        "RegisterStatusNotifierItem",
        g_variant_new("(s)", t->bus_name),
        NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL, NULL);
}

static void on_name_acquired(GDBusConnection *conn, const gchar *name,
                             gpointer user_data)
{
    (void)name;
    struct bd_tray *t = user_data;
    t->conn = conn;

    GError *err = NULL;
    t->sni_reg_id = g_dbus_connection_register_object(conn,
        "/StatusNotifierItem", g_sni_node->interfaces[0],
        &kSniVtable, t, NULL, &err);
    if (err) {
        BD_WARN("tray: register SNI object: %s", err->message);
        g_clear_error(&err);
    }
    t->menu_reg_id = g_dbus_connection_register_object(conn,
        "/MenuBar", g_menu_node->interfaces[0],
        &kMenuVtable, t, NULL, &err);
    if (err) {
        BD_WARN("tray: register menu object: %s", err->message);
        g_clear_error(&err);
    }

    register_with_watcher(t);
    BD_INFO("tray: StatusNotifierItem registered (%s)", t->bus_name);
}

static void on_name_lost(GDBusConnection *conn, const gchar *name,
                         gpointer user_data)
{
    (void)conn; (void)user_data;
    BD_WARN("tray: could not own bus name %s (no StatusNotifier host?)", name);
}

/* ---- public API ---------------------------------------------------------- */

bd_tray *bd_tray_new(const bd_tray_callbacks *cb)
{
    GError *err = NULL;
    if (!g_sni_node) {
        g_sni_node = g_dbus_node_info_new_for_xml(kSniXml, &err);
        if (err) {
            BD_ERR("tray: parse SNI xml: %s", err->message);
            g_clear_error(&err);
            return NULL;
        }
    }
    if (!g_menu_node) {
        g_menu_node = g_dbus_node_info_new_for_xml(kMenuXml, &err);
        if (err) {
            BD_ERR("tray: parse menu xml: %s", err->message);
            g_clear_error(&err);
            return NULL;
        }
    }

    struct bd_tray *t = g_new0(struct bd_tray, 1);
    t->cb = *cb;
    t->active = FALSE;
    t->revision = 1;
    snprintf(t->bus_name, sizeof(t->bus_name),
             "org.kde.StatusNotifierItem-%d-1", (int)getpid());

    t->own_name_id = g_bus_own_name(G_BUS_TYPE_SESSION, t->bus_name,
        G_BUS_NAME_OWNER_FLAGS_NONE,
        NULL, on_name_acquired, on_name_lost, t, NULL);

    return t;
}

void bd_tray_set_active(bd_tray *t, bool active)
{
    if (!t)
        return;
    gboolean a = active ? TRUE : FALSE;
    if (a == t->active)
        return;
    t->active = a;

    if (!t->conn)
        return;

    /* Refresh the icon colour and the menu (toggle label changed). */
    g_dbus_connection_emit_signal(t->conn, NULL, "/StatusNotifierItem",
        "org.kde.StatusNotifierItem", "NewIcon", NULL, NULL);
    g_dbus_connection_emit_signal(t->conn, NULL, "/StatusNotifierItem",
        "org.kde.StatusNotifierItem", "NewToolTip", NULL, NULL);

    t->revision++;
    g_dbus_connection_emit_signal(t->conn, NULL, "/MenuBar",
        "com.canonical.dbusmenu", "LayoutUpdated",
        g_variant_new("(ui)", t->revision, ITEM_ROOT), NULL);
}

void bd_tray_free(bd_tray *t)
{
    if (!t)
        return;
    if (t->conn) {
        if (t->sni_reg_id)
            g_dbus_connection_unregister_object(t->conn, t->sni_reg_id);
        if (t->menu_reg_id)
            g_dbus_connection_unregister_object(t->conn, t->menu_reg_id);
    }
    if (t->own_name_id)
        g_bus_unown_name(t->own_name_id);
    g_free(t);
}
