/*
 * Copyright © 2018 Red Hat, Inc
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *       Matthias Clasen <mclasen@redhat.com>
 */

#include "config.h"

#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <gio/gio.h>
#include <gio/gunixfdlist.h>

#include "secrets.h"
#include "request.h"
#include "documents.h"
#include "xdp-dbus.h"
#include "xdp-impl-dbus.h"
#include "xdp-utils.h"

typedef struct _Secrets Secrets;
typedef struct _SecretsClass SecretsClass;

struct _Secrets
{
  XdpSecretsSkeleton parent_instance;
};

struct _SecretsClass
{
  XdpSecretsSkeletonClass parent_class;
};

static GDBusConnection *impl_connection;
static Secrets *secrets;

GType secrets_get_type (void) G_GNUC_CONST;
static void secrets_iface_init (XdpSecretsIface *iface);

G_DEFINE_TYPE_WITH_CODE (Secrets, secrets, XDP_TYPE_SECRETS_SKELETON,
                         G_IMPLEMENT_INTERFACE (XDP_TYPE_SECRETS, secrets_iface_init));

static void
send_response_in_thread_func (GTask        *task,
                              gpointer      source_object,
                              gpointer      task_data,
                              GCancellable *cancellable)
{
  Request *request = task_data;
  guint response;
  GVariant *results;
  GVariantBuilder new_results;
  g_autoptr(GVariant) namev = NULL;

  g_variant_builder_init (&new_results, G_VARIANT_TYPE_VARDICT);

  REQUEST_AUTOLOCK (request);

  response = GPOINTER_TO_INT (g_object_get_data (G_OBJECT (request), "response"));
  results = (GVariant *)g_object_get_data (G_OBJECT (request), "results");

  if (response != 0)
    goto out;

  namev = g_variant_lookup_value (results, "name", G_VARIANT_TYPE_STRING);

  g_variant_builder_add (&new_results, "{sv}", "name", namev);

out:
  if (request->exported)
    {
      xdp_request_emit_response (XDP_REQUEST (request),
                                 response,
                                 g_variant_builder_end (&new_results));
      request_unexport (request);
    }
}

static void
get_service_done (GObject *source,
		  GAsyncResult *result,
		  gpointer data)
{
  g_autoptr(Request) request = data;
  guint response = 2;
  g_autoptr(GVariant) results = NULL;
  g_autoptr(GError) error = NULL;
  g_autoptr(GTask) task = NULL;

  results = g_dbus_connection_call_finish (impl_connection, result, &error);
  if (!results)
    g_warning ("Backend call failed: %s", error->message);

  g_object_set_data (G_OBJECT (request), "response", GINT_TO_POINTER (response));
  g_object_set_data_full (G_OBJECT (request), "results", g_variant_ref (results), (GDestroyNotify)g_variant_unref);

  task = g_task_new (NULL, NULL, NULL, NULL);
  g_task_set_task_data (task, g_object_ref (request), g_object_unref);
  g_task_run_in_thread (task, send_response_in_thread_func);
}

static XdpOptionKey open_file_options[] = {
  { "reason", G_VARIANT_TYPE_STRING },
};

static gboolean
handle_get_service (XdpSecrets *object,
		    GDBusMethodInvocation *invocation,
		    const gchar *arg_parent_window,
		    GVariant *arg_options)
{
  Request *request = request_from_invocation (invocation);
  const char *app_id = xdp_app_info_get_id (request->app_info);
  g_autoptr(GError) error = NULL;
  g_autoptr(XdpImplRequest) impl_request = NULL;
  GVariantBuilder options;

  REQUEST_AUTOLOCK (request);

  impl_request = xdp_impl_request_proxy_new_sync (impl_connection,
                                                  G_DBUS_PROXY_FLAGS_NONE,
                                                  g_dbus_connection_get_unique_name (impl_connection),
                                                  request->id,
                                                  NULL, &error);
  if (!impl_request)
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      return TRUE;
    }

  request_set_impl_request (request, impl_request);
  request_export (request, g_dbus_method_invocation_get_connection (invocation));

  g_variant_builder_init (&options, G_VARIANT_TYPE_VARDICT);
  xdp_filter_options (arg_options, &options,
                      open_file_options, G_N_ELEMENTS (open_file_options));

  g_dbus_connection_call (impl_connection,
			  "org.gnome.keyring",
			  "/org/gnome/keyring/daemon",
			  "org.gnome.keyring.Daemon",
			  "GetSecretService",
			  g_variant_new ("(s)", app_id),
			  G_VARIANT_TYPE ("(s)"),
			  G_DBUS_CALL_FLAGS_NONE,
			  G_MAXINT,
			  NULL,
			  get_service_done,
			  g_object_ref (request));

  xdp_secrets_complete_get_service (object, invocation, request->id);

  return TRUE;
}

static void
secrets_iface_init (XdpSecretsIface *iface)
{
  iface->handle_get_service = handle_get_service;
}

static void
secrets_init (Secrets *secrets)
{
  xdp_secrets_set_version (XDP_SECRETS (secrets), 1);
}

static void
secrets_class_init (SecretsClass *klass)
{
}

GDBusInterfaceSkeleton *
secrets_create (GDBusConnection *connection)
{
  g_autoptr(GError) error = NULL;

  impl_connection = connection;
  secrets = g_object_new (secrets_get_type (), NULL);

  return G_DBUS_INTERFACE_SKELETON (secrets);
}
