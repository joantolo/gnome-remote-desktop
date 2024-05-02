/*
 * Copyright (C) 2024 SUSE Software Solutions Germany GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Written by:
 *     Joan Torres <joan.torres@suse.com>
 */

#include "config.h"

#include <gio/gio.h>
#include <glib-unix.h>
#include <glib.h>

#include "grd-dbus-remote-desktop.h"
#include "grd-private.h"
#include "grd-settings-system.h"

#define GRD_CTL_DBUS_TIMEOUT 10000

struct _GrdCtlDbus
{
  GApplication parent;

  GrdSettingsSystem *settings;

  GrdDBusRemoteDesktopConfigureRdpServer *configure_rdp_server;
  unsigned int own_name_source_id;

  unsigned int timeout_source_id;
  unsigned int sigint_source_id;
  unsigned int sigterm_source_id;
};

#define GRD_TYPE_CTL_DBUS (grd_ctl_dbus_get_type ())
G_DECLARE_FINAL_TYPE (GrdCtlDbus,
                      grd_ctl_dbus,
                      GRD, CTL_DBUS,
                      GApplication)

G_DEFINE_TYPE (GrdCtlDbus, grd_ctl_dbus, G_TYPE_APPLICATION)

static void
grd_ctl_dbus_init (GrdCtlDbus *app)
{
}

static void
on_bus_acquired (GDBusConnection *connection,
                 const char      *name,
                 gpointer         user_data)
{
  GrdCtlDbus *ctl_dbus = user_data;

  g_debug ("Now on system bus");

  g_dbus_interface_skeleton_export (
    G_DBUS_INTERFACE_SKELETON (ctl_dbus->configure_rdp_server),
    connection,
    REMOTE_DESKTOP_CONFIGURE_OBJECT_PATH,
    NULL);
}

static void
on_name_acquired (GDBusConnection *connection,
                  const char      *name,
                  gpointer         user_data)
{
  g_debug ("Owned %s name", name);
}

static void
on_name_lost (GDBusConnection *connection,
              const char      *name,
              gpointer         user_data)
{
  g_debug ("Lost owned %s name", name);
}

static gboolean
terminate (gpointer user_data)
{
  GrdCtlDbus *ctl_dbus = user_data;

  g_application_release (G_APPLICATION (ctl_dbus));

  g_clear_handle_id (&ctl_dbus->timeout_source_id, g_source_remove);
  g_clear_handle_id (&ctl_dbus->sigint_source_id, g_source_remove);
  g_clear_handle_id (&ctl_dbus->sigterm_source_id, g_source_remove);

  return G_SOURCE_REMOVE;
}

static void
register_signals (GrdCtlDbus *ctl_dbus)
{
  ctl_dbus->timeout_source_id = g_timeout_add (GRD_CTL_DBUS_TIMEOUT, terminate, ctl_dbus);
  ctl_dbus->sigint_source_id = g_unix_signal_add (SIGINT, terminate, ctl_dbus);
  ctl_dbus->sigterm_source_id = g_unix_signal_add (SIGTERM, terminate, ctl_dbus);
}

static void
grd_ctl_dbus_startup (GApplication *application)
{
  GrdCtlDbus *ctl_dbus = GRD_CTL_DBUS (application);

  ctl_dbus->settings = grd_settings_system_new ();

  ctl_dbus->configure_rdp_server =
    grd_dbus_remote_desktop_configure_rdp_server_skeleton_new ();

  ctl_dbus->own_name_source_id =
    g_bus_own_name (G_BUS_TYPE_SYSTEM,
                    REMOTE_DESKTOP_CONFIGURE_BUS_NAME,
                    G_BUS_NAME_OWNER_FLAGS_NONE,
                    on_bus_acquired,
                    on_name_acquired,
                    on_name_lost,
                    ctl_dbus, NULL);

  register_signals (ctl_dbus);

  g_application_hold (application);

  G_APPLICATION_CLASS (grd_ctl_dbus_parent_class)->startup (application);
}

static void
grd_ctl_dbus_shutdown (GApplication *application)
{
  GrdCtlDbus *ctl_dbus = GRD_CTL_DBUS (application);

  g_clear_object (&ctl_dbus->settings);

  g_dbus_interface_skeleton_unexport (
    G_DBUS_INTERFACE_SKELETON (ctl_dbus->configure_rdp_server));
  g_clear_object (&ctl_dbus->configure_rdp_server);

  g_clear_handle_id (&ctl_dbus->own_name_source_id, g_bus_unown_name);

  g_clear_handle_id (&ctl_dbus->timeout_source_id, g_source_remove);
  g_clear_handle_id (&ctl_dbus->sigint_source_id, g_source_remove);
  g_clear_handle_id (&ctl_dbus->sigterm_source_id, g_source_remove);

  G_APPLICATION_CLASS (grd_ctl_dbus_parent_class)->shutdown (application);
}

static void
grd_ctl_dbus_class_init (GrdCtlDbusClass *klass)
{
  GApplicationClass *g_application_class = G_APPLICATION_CLASS (klass);

  g_application_class->startup = grd_ctl_dbus_startup;
  g_application_class->shutdown = grd_ctl_dbus_shutdown;
}

int
main (int argc, char **argv)
{
  g_autoptr (GApplication) app = NULL;

  app = g_object_new (grd_ctl_dbus_get_type (),
                       "application-id", REMOTE_DESKTOP_CONFIGURE_BUS_NAME,
                       "flags", G_APPLICATION_IS_SERVICE,
                       NULL);

  return g_application_run (app, argc, argv);
}
