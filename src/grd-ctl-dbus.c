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

#ifdef HAVE_RDP
#include <freerdp/freerdp.h>
#endif

#include <gio/gio.h>
#include <glib-unix.h>
#include <glib.h>
#include <polkit/polkit.h>

#include "grd-dbus-remote-desktop.h"
#include "grd-private.h"
#include "grd-settings-system.h"
#include "grd-utils.h"

#define GRD_CTL_DBUS_TIMEOUT 10000
#define GRD_SYSTEMD_SERVICE "gnome-remote-desktop.service"
#define GRD_SERVER_USER_CERT_SUBDIR "certificates"
#define GRD_CONFIGURE_SYSTEM_DAEMON_POLKIT_ACTION "org.gnome.remotedesktop.configure-system-daemon"

struct _GrdCtlDbus
{
  GApplication parent;

  PolkitAuthority *authority;

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

#ifdef HAVE_RDP
G_DEFINE_AUTOPTR_CLEANUP_FUNC (rdpCertificate, freerdp_certificate_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (rdpPrivateKey, freerdp_key_free)
#endif

static void
grd_ctl_dbus_init (GrdCtlDbus *app)
{
}

static gboolean
transform_enabled (GBinding     *binding,
                   const GValue *from_value,
                   GValue       *to_value,
                   gpointer      user_data)
{
  gboolean enabled;
  gboolean unit_active;
  g_autoptr (GError) error = NULL;

  enabled = g_value_get_boolean (from_value);

  unit_active = systemd_unit_is_active (G_BUS_TYPE_SYSTEM,
                                        GRD_SYSTEMD_SERVICE,
                                        &error);
  if (error)
    {
      g_warning ("Failed checking unit state: %s", error->message);
      return FALSE;
    }

  g_value_set_boolean (to_value, enabled && unit_active);

  return TRUE;
}

static gboolean
on_handle_enable (GrdDBusRemoteDesktopConfigureRdpServer *configure_rdp_server,
                  GDBusMethodInvocation                  *invocation,
                  GrdCtlDbus                             *ctl_dbus)
{
  g_autoptr (GError) error = NULL;

  if (!enable_systemd_unit (G_BUS_TYPE_SYSTEM, GRD_SYSTEMD_SERVICE, &error))
    {
      g_dbus_method_invocation_return_error (invocation, G_DBUS_ERROR,
                                             G_DBUS_ERROR_FAILED,
                                             "Failed enabling %s: %s",
                                             GRD_SYSTEMD_SERVICE,
                                             error->message);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  g_object_set (G_OBJECT (ctl_dbus->settings), "rdp-enabled", TRUE, NULL);

  grd_dbus_remote_desktop_configure_rdp_server_complete_enable (
    configure_rdp_server,
    invocation);

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
on_handle_disable (GrdDBusRemoteDesktopConfigureRdpServer *configure_rdp_server,
                   GDBusMethodInvocation                  *invocation,
                   GrdCtlDbus                             *ctl_dbus)
{
  g_autoptr (GError) error = NULL;

  if (!disable_systemd_unit (G_BUS_TYPE_SYSTEM, GRD_SYSTEMD_SERVICE, &error))
    {
      g_dbus_method_invocation_return_error (invocation, G_DBUS_ERROR,
                                             G_DBUS_ERROR_FAILED,
                                             "Failed disabling %s: %s",
                                             GRD_SYSTEMD_SERVICE,
                                             error->message);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  g_object_set (G_OBJECT (ctl_dbus->settings), "rdp-enabled", FALSE, NULL);

  grd_dbus_remote_desktop_configure_rdp_server_complete_disable (
    configure_rdp_server,
    invocation);

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
on_handle_get_credentials (GrdDBusRemoteDesktopConfigureRdpServer *configure_rdp_server,
                           GDBusMethodInvocation                  *invocation,
                           GrdCtlDbus                             *ctl_dbus)
{
  g_autofree char *username = NULL;
  g_autofree char *password = NULL;
  g_autoptr (GError) error = NULL;
  GVariantBuilder credentials;

  g_variant_builder_init (&credentials, G_VARIANT_TYPE ("a{sv}"));

  grd_settings_get_rdp_credentials (GRD_SETTINGS (ctl_dbus->settings),
                                    &username, &password,
                                    &error);
  if (error)
    g_warning ("Failed to get credentials: %s", error->message);

  if (!username)
    username = g_strdup ("");

  if (!password)
    password = g_strdup ("");

  g_variant_builder_add (&credentials, "{sv}", "username",
                         g_variant_new_string (username));
  g_variant_builder_add (&credentials, "{sv}", "password",
                         g_variant_new_string (password));

  grd_dbus_remote_desktop_configure_rdp_server_complete_get_credentials (
    configure_rdp_server,
    invocation,
    g_variant_builder_end (&credentials));

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
on_handle_set_credentials (GrdDBusRemoteDesktopConfigureRdpServer *configure_rdp_server,
                           GDBusMethodInvocation                  *invocation,
                           GVariant                               *credentials,
                           GrdCtlDbus                             *ctl_dbus)
{
  g_autofree char *old_username = NULL;
  g_autofree char *old_password = NULL;
  g_autofree char *username = NULL;
  g_autofree char *password = NULL;
  g_autoptr (GError) error = NULL;

  g_variant_lookup (credentials, "username", "s", &username);
  g_variant_lookup (credentials, "password", "s", &password);

  if (!username && !password)
    {
      g_dbus_method_invocation_return_error (invocation, G_DBUS_ERROR,
                                             G_DBUS_ERROR_INVALID_ARGS,
                                             "Username or password expected "
                                             "in credentials");
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  if (!username || !password)
    {
      grd_settings_get_rdp_credentials (GRD_SETTINGS (ctl_dbus->settings),
                                        &old_username, &old_password,
                                        NULL);
    }

  if (!username)
    username = g_steal_pointer (&old_username);

  if (!password)
    password = g_steal_pointer (&old_password);

  if (!grd_settings_set_rdp_credentials (GRD_SETTINGS (ctl_dbus->settings), 
                                         username, password,
                                         &error))
    {
      g_dbus_method_invocation_return_error (invocation, G_DBUS_ERROR,
                                             G_DBUS_ERROR_FAILED,
                                             "Failed to set credentials: %s",
                                             error->message);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  grd_dbus_remote_desktop_configure_rdp_server_complete_set_credentials (
    configure_rdp_server,
    invocation);

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
on_handle_import_certificate (GrdDBusRemoteDesktopConfigureRdpServer *configure_rdp_server,
                              GDBusMethodInvocation                  *invocation,
                              GUnixFDList                            *fd_list,
                              GVariant                               *certificate,
                              GVariant                               *private_key,
                              GrdCtlDbus                             *ctl_dbus)
{
  g_autoptr (rdpCertificate) rdp_certificate = NULL;
  g_autoptr (rdpPrivateKey) rdp_private_key = NULL;
  g_autofree char *certificate_filename = NULL;
  g_autofree char *key_filename = NULL;
  g_autoptr (GError) error = NULL;
  g_autofd int certificate_fd = -1;
  g_autofd int key_fd = -1;
  int certificate_fd_index;
  int key_fd_index;

  g_variant_get (certificate, "(sh)", &certificate_filename,
                 &certificate_fd_index);
  g_variant_get (private_key, "(sh)", &key_filename,
                 &key_fd_index);

  certificate_fd = g_unix_fd_list_get (fd_list, certificate_fd_index, &error);
  if (certificate_fd == -1)
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  key_fd = g_unix_fd_list_get (fd_list, key_fd_index, &error);
  if (key_fd == -1)
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  grd_rewrite_path_to_user_data_dir (&certificate_filename,
                                     GRD_SERVER_USER_CERT_SUBDIR,
                                     "rdp-tls.crt");
  if (!grd_write_fd_to_file (certificate_fd, certificate_filename,
                             NULL, &error))
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  rdp_certificate = freerdp_certificate_new_from_file (certificate_filename);

  if (!rdp_certificate)
    {
      g_dbus_method_invocation_return_error (invocation,
                                             G_IO_ERROR,
                                             G_IO_ERROR_INVALID_DATA,
                                             "Invalid certificate");
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  grd_rewrite_path_to_user_data_dir (&key_filename,
                                     GRD_SERVER_USER_CERT_SUBDIR,
                                     "rdp-tls.key");
  if (!grd_write_fd_to_file (key_fd, key_filename, NULL, &error))
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  rdp_private_key = freerdp_key_new_from_file (key_filename);

  if (!rdp_private_key)
    {
      g_dbus_method_invocation_return_error (invocation,
                                             G_IO_ERROR,
                                             G_IO_ERROR_INVALID_DATA,
                                             "Invalid private key");
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  g_object_set (ctl_dbus->settings,
                "rdp-server-cert-path", certificate_filename,
                "rdp-server-key-path", key_filename,
                NULL);

  grd_dbus_remote_desktop_configure_rdp_server_complete_import_certificate (
    configure_rdp_server,
    invocation,
    fd_list);

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
on_authorize_method (GrdDBusRemoteDesktopConfigureRdpServer *configure_rdp_server,
                     GDBusMethodInvocation                  *invocation,
                     GrdCtlDbus                             *ctl_dbus)
{
  g_autoptr (PolkitAuthorizationResult) result = NULL;
  g_autoptr (PolkitSubject) subject = NULL;
  PolkitCheckAuthorizationFlags flags;
  g_autoptr (GError) error = NULL;
  const char *sender = NULL;
  const char *action = NULL;

  if (!ctl_dbus->authority)
    {
      g_dbus_method_invocation_return_error (invocation, G_DBUS_ERROR,
                                             G_DBUS_ERROR_ACCESS_DENIED,
                                             "Couldn't get polkit authority");
      return FALSE;
    }

  sender = g_dbus_method_invocation_get_sender (invocation);
  subject = polkit_system_bus_name_new (sender);
  action = GRD_CONFIGURE_SYSTEM_DAEMON_POLKIT_ACTION;
  flags = POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION;
  result = polkit_authority_check_authorization_sync (ctl_dbus->authority,
                                                      subject, action,
                                                      NULL, flags, NULL,
                                                      &error);
  if (!result)
    {
      g_dbus_method_invocation_return_error (invocation, G_DBUS_ERROR,
                                             G_DBUS_ERROR_FAILED,
                                             "Failed to check authorization: %s",
                                             error->message);
      return FALSE;
    }

  if (!polkit_authorization_result_get_is_authorized (result))
    {
      g_dbus_method_invocation_return_error (invocation, G_DBUS_ERROR,
                                             G_DBUS_ERROR_ACCESS_DENIED,
                                             "Not authorized for action %s",
                                             action);
      return FALSE;
    }

  return TRUE;
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
  g_autoptr (GError) error = NULL;

  ctl_dbus->authority = polkit_authority_get_sync (NULL, &error);
  if (!ctl_dbus->authority)
    {
      g_critical ("Error getting polkit authority: %s", error->message);
      g_clear_error (&error);
    }

  ctl_dbus->settings = grd_settings_system_new ();

  ctl_dbus->configure_rdp_server =
    grd_dbus_remote_desktop_configure_rdp_server_skeleton_new ();

  g_object_bind_property_full (ctl_dbus->settings, "rdp-enabled",
                               ctl_dbus->configure_rdp_server, "enabled",
                               G_BINDING_SYNC_CREATE,
                               transform_enabled,
                               NULL,
                               NULL,
                               NULL);
  g_object_bind_property (ctl_dbus->settings, "rdp-port",
                          ctl_dbus->configure_rdp_server, "port",
                          G_BINDING_SYNC_CREATE);
  g_object_bind_property (ctl_dbus->settings, "rdp-server-cert-path",
                          ctl_dbus->configure_rdp_server, "tls-cert",
                          G_BINDING_SYNC_CREATE);
  g_object_bind_property (ctl_dbus->settings, "rdp-server-fingerprint",
                          ctl_dbus->configure_rdp_server, "tls-fingerprint",
                          G_BINDING_SYNC_CREATE);
  g_object_bind_property (ctl_dbus->settings, "rdp-server-key-path",
                          ctl_dbus->configure_rdp_server, "tls-key",
                          G_BINDING_SYNC_CREATE);
  g_signal_connect_object (ctl_dbus->configure_rdp_server, "handle-enable",
                           G_CALLBACK (on_handle_enable),
                           ctl_dbus, 0);
  g_signal_connect_object (ctl_dbus->configure_rdp_server, "handle-disable",
                           G_CALLBACK (on_handle_disable),
                           ctl_dbus, 0);
  g_signal_connect_object (ctl_dbus->configure_rdp_server, "handle-get-credentials",
                           G_CALLBACK (on_handle_get_credentials),
                           ctl_dbus, 0);
  g_signal_connect_object (ctl_dbus->configure_rdp_server, "handle-set-credentials",
                           G_CALLBACK (on_handle_set_credentials),
                           ctl_dbus, 0);
  g_signal_connect_object (ctl_dbus->configure_rdp_server, "handle-import-certificate",
                           G_CALLBACK (on_handle_import_certificate),
                           ctl_dbus, 0);
  g_signal_connect_object (ctl_dbus->configure_rdp_server, "g-authorize-method",
                           G_CALLBACK (on_authorize_method),
                           ctl_dbus, 0);

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

  g_clear_object (&ctl_dbus->authority);

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
