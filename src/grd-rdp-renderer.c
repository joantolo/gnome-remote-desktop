/*
 * Copyright (C) 2023 Pascal Nowack
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
 */

#include "config.h"

#include "grd-rdp-renderer.h"

#include "grd-hwaccel-nvidia.h"
#include "grd-rdp-graphics-pipeline.h"
#include "grd-rdp-surface.h"
#include "grd-rdp-surface-renderer.h"

struct _GrdRdpRenderer
{
  GObject parent;

  gboolean in_shutdown;

  GrdSessionRdp *session_rdp;
  GrdHwAccelNvidia *hwaccel_nvidia;

  GrdRdpGraphicsPipeline *graphics_pipeline;
  rdpContext *rdp_context;

  GThread *graphics_thread;
  GMainContext *graphics_context;

  gboolean output_suppressed;

  gboolean pending_gfx_init;
  gboolean pending_gfx_graphics_reset;

  GMutex surface_renderers_mutex;
  GHashTable *surface_renderer_table;

  GSource *surface_disposal_source;
  GAsyncQueue *disposal_queue;
};

G_DEFINE_TYPE (GrdRdpRenderer, grd_rdp_renderer, G_TYPE_OBJECT)

GMainContext *
grd_rdp_renderer_get_graphics_context (GrdRdpRenderer *renderer)
{
  return renderer->graphics_context;
}

gboolean
grd_rdp_renderer_is_output_suppressed (GrdRdpRenderer *renderer)
{
  return renderer->output_suppressed;
}

gboolean
grd_rdp_renderer_has_pending_graphics_pipeline_reset (GrdRdpRenderer *renderer)
{
  return renderer->pending_gfx_init;
}

static void
trigger_render_sources (GrdRdpRenderer *renderer)
{
  GrdRdpSurfaceRenderer *surface_renderer = NULL;
  g_autoptr (GMutexLocker) locker = NULL;
  GHashTableIter iter;

  locker = g_mutex_locker_new (&renderer->surface_renderers_mutex);
  g_hash_table_iter_init (&iter, renderer->surface_renderer_table);
  while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &surface_renderer))
    grd_rdp_surface_renderer_trigger_render_source (surface_renderer);
}

void
grd_rdp_renderer_update_output_suppression_state (GrdRdpRenderer *renderer,
                                                  gboolean        suppress_output)
{
  renderer->output_suppressed = suppress_output;

  if (!renderer->output_suppressed)
    trigger_render_sources (renderer);
}

void
grd_rdp_renderer_invoke_shutdown (GrdRdpRenderer *renderer)
{
  g_assert (renderer->graphics_context);
  g_assert (renderer->graphics_thread);

  renderer->in_shutdown = TRUE;

  g_main_context_wakeup (renderer->graphics_context);
  g_clear_pointer (&renderer->graphics_thread, g_thread_join);
}

void
grd_rdp_renderer_notify_session_started (GrdRdpRenderer         *renderer,
                                         GrdRdpGraphicsPipeline *graphics_pipeline,
                                         rdpContext             *rdp_context)
{
  renderer->graphics_pipeline = graphics_pipeline;
  renderer->rdp_context = rdp_context;
}

void
grd_rdp_renderer_notify_new_desktop_layout (GrdRdpRenderer *renderer,
                                            uint32_t        desktop_width,
                                            uint32_t        desktop_height)
{
  rdpContext *rdp_context = renderer->rdp_context;
  rdpSettings *rdp_settings = rdp_context->settings;
  uint32_t current_desktop_width =
    freerdp_settings_get_uint32 (rdp_settings, FreeRDP_DesktopWidth);
  uint32_t current_desktop_height =
    freerdp_settings_get_uint32 (rdp_settings, FreeRDP_DesktopHeight);

  if (renderer->graphics_pipeline)
    renderer->pending_gfx_graphics_reset = TRUE;

  if (current_desktop_width == desktop_width &&
      current_desktop_height == desktop_height)
    return;

  freerdp_settings_set_uint32 (rdp_settings, FreeRDP_DesktopWidth,
                               desktop_width);
  freerdp_settings_set_uint32 (rdp_settings, FreeRDP_DesktopHeight,
                               desktop_height);
  if (!renderer->graphics_pipeline)
    rdp_context->update->DesktopResize (rdp_context);
}

static void
invalidate_surfaces (GrdRdpRenderer *renderer)
{
  GrdRdpSurface *rdp_surface = NULL;
  g_autoptr (GMutexLocker) locker = NULL;
  GHashTableIter iter;

  locker = g_mutex_locker_new (&renderer->surface_renderers_mutex);
  g_hash_table_iter_init (&iter, renderer->surface_renderer_table);
  while (g_hash_table_iter_next (&iter, (gpointer *) &rdp_surface, NULL))
    grd_rdp_surface_invalidate_surface (rdp_surface);
}

void
grd_rdp_renderer_notify_graphics_pipeline_ready (GrdRdpRenderer *renderer)
{
  renderer->pending_gfx_graphics_reset = TRUE;
  renderer->pending_gfx_init = FALSE;

  invalidate_surfaces (renderer);
  trigger_render_sources (renderer);
}

void
grd_rdp_renderer_notify_graphics_pipeline_reset (GrdRdpRenderer *renderer)
{
  renderer->pending_gfx_init = TRUE;
}

void
grd_rdp_renderer_maybe_reset_graphics (GrdRdpRenderer *renderer)
{
  rdpContext *rdp_context = renderer->rdp_context;
  rdpSettings *rdp_settings = rdp_context->settings;
  uint32_t desktop_width =
    freerdp_settings_get_uint32 (rdp_settings, FreeRDP_DesktopWidth);
  uint32_t desktop_height =
    freerdp_settings_get_uint32 (rdp_settings, FreeRDP_DesktopHeight);
  g_autofree MONITOR_DEF *monitor_defs = NULL;
  uint32_t n_monitors;
  uint32_t i;

  if (!renderer->pending_gfx_graphics_reset)
    return;

  n_monitors = freerdp_settings_get_uint32 (rdp_settings, FreeRDP_MonitorCount);
  g_assert (n_monitors > 0);

  monitor_defs = g_new0 (MONITOR_DEF, n_monitors);

  for (i = 0; i < n_monitors; ++i)
    {
      const rdpMonitor *monitor =
        freerdp_settings_get_pointer_array (rdp_settings,
                                            FreeRDP_MonitorDefArray, i);
      MONITOR_DEF *monitor_def = &monitor_defs[i];

      monitor_def->left = monitor->x;
      monitor_def->top = monitor->y;
      monitor_def->right = monitor_def->left + monitor->width - 1;
      monitor_def->bottom = monitor_def->top + monitor->height - 1;

      if (monitor->is_primary)
        monitor_def->flags = MONITOR_PRIMARY;
    }

  grd_rdp_graphics_pipeline_reset_graphics (renderer->graphics_pipeline,
                                            desktop_width, desktop_height,
                                            monitor_defs, n_monitors);
  renderer->pending_gfx_graphics_reset = FALSE;
}

GrdRdpSurface *
grd_rdp_renderer_try_acquire_surface (GrdRdpRenderer *renderer,
                                      uint32_t        refresh_rate)
{
  GrdRdpSurface *rdp_surface;
  GrdRdpSurfaceRenderer *surface_renderer;

  rdp_surface = grd_rdp_surface_new (renderer->hwaccel_nvidia);
  if (!rdp_surface)
    return NULL;

  surface_renderer = grd_rdp_surface_renderer_new (rdp_surface, renderer,
                                                   renderer->session_rdp,
                                                   refresh_rate);
  grd_rdp_surface_attach_surface_renderer (rdp_surface, surface_renderer);

  g_mutex_lock (&renderer->surface_renderers_mutex);
  g_hash_table_insert (renderer->surface_renderer_table,
                       rdp_surface, surface_renderer);
  g_mutex_unlock (&renderer->surface_renderers_mutex);

  return rdp_surface;
}

void
grd_rdp_renderer_release_surface (GrdRdpRenderer *renderer,
                                  GrdRdpSurface  *rdp_surface)
{
  g_assert (rdp_surface);

  g_async_queue_push (renderer->disposal_queue, rdp_surface);
  g_source_set_ready_time (renderer->surface_disposal_source, 0);
}

static gpointer
graphics_thread_func (gpointer data)
{
  GrdRdpRenderer *renderer = data;

  if (renderer->hwaccel_nvidia)
    grd_hwaccel_nvidia_push_cuda_context (renderer->hwaccel_nvidia);

  while (!renderer->in_shutdown)
    g_main_context_iteration (renderer->graphics_context, TRUE);

  if (renderer->hwaccel_nvidia)
    grd_hwaccel_nvidia_pop_cuda_context (renderer->hwaccel_nvidia);

  return NULL;
}

GrdRdpRenderer *
grd_rdp_renderer_new (GrdSessionRdp    *session_rdp,
                      GrdHwAccelNvidia *hwaccel_nvidia)
{
  GrdRdpRenderer *renderer;

  renderer = g_object_new (GRD_TYPE_RDP_RENDERER, NULL);
  renderer->session_rdp = session_rdp;
  renderer->hwaccel_nvidia = hwaccel_nvidia;

  renderer->graphics_thread = g_thread_new ("RDP graphics thread",
                                            graphics_thread_func,
                                            renderer);

  return renderer;
}

static gboolean
dispose_surfaces (gpointer user_data)
{
  GrdRdpRenderer *renderer = user_data;
  GrdRdpSurface *rdp_surface;

  while ((rdp_surface = g_async_queue_try_pop (renderer->disposal_queue)))
    {
      g_mutex_lock (&renderer->surface_renderers_mutex);
      g_hash_table_remove (renderer->surface_renderer_table, rdp_surface);
      g_mutex_unlock (&renderer->surface_renderers_mutex);

      g_clear_object (&rdp_surface->gfx_surface);
      grd_rdp_surface_free (rdp_surface);
    }

  return G_SOURCE_CONTINUE;
}

static void
grd_rdp_renderer_dispose (GObject *object)
{
  GrdRdpRenderer *renderer = GRD_RDP_RENDERER (object);

  if (renderer->graphics_thread)
    grd_rdp_renderer_invoke_shutdown (renderer);

  if (renderer->surface_disposal_source)
    {
      g_source_destroy (renderer->surface_disposal_source);
      g_clear_pointer (&renderer->surface_disposal_source, g_source_unref);
    }

  g_clear_pointer (&renderer->graphics_context, g_main_context_unref);

  dispose_surfaces (renderer);
  g_clear_pointer (&renderer->disposal_queue, g_async_queue_unref);

  g_assert (g_hash_table_size (renderer->surface_renderer_table) == 0);

  G_OBJECT_CLASS (grd_rdp_renderer_parent_class)->dispose (object);
}

static void
grd_rdp_renderer_finalize (GObject *object)
{
  GrdRdpRenderer *renderer = GRD_RDP_RENDERER (object);

  g_mutex_clear (&renderer->surface_renderers_mutex);

  g_clear_pointer (&renderer->surface_renderer_table, g_hash_table_unref);

  G_OBJECT_CLASS (grd_rdp_renderer_parent_class)->finalize (object);
}

static gboolean
source_dispatch (GSource     *source,
                 GSourceFunc  callback,
                 gpointer     user_data)
{
  g_source_set_ready_time (source, -1);

  return callback (user_data);
}

static GSourceFuncs source_funcs =
{
  .dispatch = source_dispatch,
};

static void
grd_rdp_renderer_init (GrdRdpRenderer *renderer)
{
  GSource *surface_disposal_source;

  renderer->surface_renderer_table = g_hash_table_new (NULL, NULL);
  renderer->disposal_queue = g_async_queue_new ();

  g_mutex_init (&renderer->surface_renderers_mutex);

  renderer->graphics_context = g_main_context_new ();

  surface_disposal_source = g_source_new (&source_funcs, sizeof (GSource));
  g_source_set_callback (surface_disposal_source, dispose_surfaces,
                         renderer, NULL);
  g_source_set_ready_time (surface_disposal_source, -1);
  g_source_attach (surface_disposal_source, renderer->graphics_context);
  renderer->surface_disposal_source = surface_disposal_source;
}

static void
grd_rdp_renderer_class_init (GrdRdpRendererClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = grd_rdp_renderer_dispose;
  object_class->finalize = grd_rdp_renderer_finalize;
}