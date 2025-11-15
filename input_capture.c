#include "input_capture.h"

#include "xdpw.h"
#include "logger.h"

#include "wlr-layer-shell-unstable-v1-client-protocol.h"
#include "pointer-constraints-unstable-v1-client-protocol.h"
#include "keyboard-shortcuts-inhibit-unstable-v1-client-protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stddef.h>
#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/mman.h>

#define SD_BUS_TYPE_ARRAY "a"
#define SD_BUS_TYPE_DICT_ENTRY_BEGIN "{"
#define SD_BUS_TYPE_DICT_ENTRY_END "}"
#define SD_BUS_TYPE_STRING "s"
#define SD_BUS_TYPE_VARIANT "v"
#define SD_BUS_TYPE_OBJECT_PATH "o"
#define SD_BUS_TYPE_UINT32 "u"
#define SD_BUS_TYPE_UNIX_FD "h"

#define VOID_RETURN ""

static const char *INPUTCAPTURE_INTERFACE_NAME = "org.freedesktop.portal.InputCapture";
static const char *REQUEST_INTERFACE_NAME = "org.freedesktop.impl.portal.Request";
static const char *SESSION_INTERFACE_NAME = "org.freedesktop.impl.portal.Session";
static const char *OBJECT_PATH_NAME = "/org/freedesktop/portal/desktop";

/* --- static global data --- */

static struct InputCaptureData interface_data = {
  .capabilities = 1 | 2 ,   // Keyboard | Pointer | Touchscreen (4), not implemented yet
  .version = 1,
  .bus = NULL,
  .eis_context = NULL,
  .session_list_head = NULL,
  .wl_display = NULL,
  .wl_registry = NULL,
  .wl_compositor = NULL,
  .wl_layer_shell = NULL,
  .wl_seat = NULL,
  .wl_pointer_constraints = NULL,
  .wl_keyboard_shortcuts_manager = NULL,
  .xkb_context = NULL,
  .active_session = NULL
};

/* --- forward declarations --- */
static int dbus_property_SupportedCapabilities(sd_bus *, const char *, const char *, const char *, sd_bus_message *, void *, sd_bus_error *);
static int dbus_property_version(sd_bus *, const char *, const char *, const char *, sd_bus_message *, void *, sd_bus_error *);
static int dbus_method_CreateSession(sd_bus_message *, void *, sd_bus_error *);
static int dbus_method_GetZones(sd_bus_message *, void *, sd_bus_error *);
static int dbus_method_SetPointerBarriers(sd_bus_message *, void *, sd_bus_error *);
static int dbus_method_Enable(sd_bus_message *, void *, sd_bus_error *);
static int dbus_method_Disable(sd_bus_message *, void *, sd_bus_error *);
static int dbus_method_Release(sd_bus_message *, void *, sd_bus_error *);
static int dbus_method_ConnectToEIS(sd_bus_message *, void *, sd_bus_error *);
static int dbus_signal_Disabled(sd_bus *, const char *) __attribute__((unused));
static int dbus_signal_Activated(sd_bus *, const char *);
static int dbus_signal_Deactivated(sd_bus *, const char *);
static int dbus_signal_ZonesChanged(sd_bus *, const char *);
static char *dbus_helper_get_sender(const char *);
static int dbus_helper_drain_dict(sd_bus_message *);
static int dbus_helper_parse_CreateSession_options(sd_bus_message *, const char **, const char **, uint32_t *);
static int dbus_helper_generate_path(char **, const char *, const char *, const char *);
static int dbus_helper_emit_signal(sd_bus *, const char *, const char *);
static struct SessionContext* eis_helper_find_session(const char *);
static void eis_helper_handle_event(struct eis_event *);
static int dbus_method_Close(sd_bus_message *, void *, sd_bus_error *);
static void wayland_registry_global(void *, struct wl_registry *, uint32_t, const char *, uint32_t);
static void wayland_registry_global_remove(void *, struct wl_registry *, uint32_t);
static void cleanup_session_wayland(struct SessionContext *);
static void sc_free(struct SessionContext *);

static void output_handle_geometry(void *, struct wl_output *, int32_t, int32_t, int32_t, int32_t, int32_t, const char *, const char *, int32_t);
static void output_handle_mode(void *, struct wl_output *, uint32_t, int32_t, int32_t, int32_t);
static void output_handle_done(void *, struct wl_output *);
static void output_handle_scale(void *, struct wl_output *, int32_t);

/* --- dbus vtable --- */
static const sd_bus_vtable input_capture_vtable[] = {
  SD_BUS_VTABLE_START(0),
  SD_BUS_PROPERTY("SupportedCapabilities", SD_BUS_TYPE_UINT32, dbus_property_SupportedCapabilities, offsetof(struct InputCaptureData, capabilities), SD_BUS_VTABLE_PROPERTY_CONST),
  SD_BUS_PROPERTY("version", SD_BUS_TYPE_UINT32, dbus_property_version, offsetof(struct InputCaptureData, version), SD_BUS_VTABLE_PROPERTY_CONST),
  SD_BUS_METHOD("CreateSession", SD_BUS_TYPE_STRING SD_BUS_TYPE_ARRAY SD_BUS_TYPE_DICT_ENTRY_BEGIN SD_BUS_TYPE_STRING SD_BUS_TYPE_VARIANT SD_BUS_TYPE_DICT_ENTRY_END, SD_BUS_TYPE_OBJECT_PATH, dbus_method_CreateSession, SD_BUS_VTABLE_UNPRIVILEGED),
  SD_BUS_METHOD("GetZones", SD_BUS_TYPE_OBJECT_PATH SD_BUS_TYPE_ARRAY SD_BUS_TYPE_DICT_ENTRY_BEGIN SD_BUS_TYPE_STRING SD_BUS_TYPE_VARIANT SD_BUS_TYPE_DICT_ENTRY_END, SD_BUS_TYPE_OBJECT_PATH, dbus_method_GetZones, SD_BUS_VTABLE_UNPRIVILEGED),
  SD_BUS_METHOD("SetPointerBarriers", SD_BUS_TYPE_OBJECT_PATH SD_BUS_TYPE_ARRAY SD_BUS_TYPE_DICT_ENTRY_BEGIN SD_BUS_TYPE_STRING SD_BUS_TYPE_VARIANT SD_BUS_TYPE_DICT_ENTRY_END SD_BUS_TYPE_ARRAY SD_BUS_TYPE_ARRAY SD_BUS_TYPE_DICT_ENTRY_BEGIN SD_BUS_TYPE_STRING SD_BUS_TYPE_VARIANT SD_BUS_TYPE_DICT_ENTRY_END SD_BUS_TYPE_UINT32, SD_BUS_TYPE_OBJECT_PATH, dbus_method_SetPointerBarriers, SD_BUS_VTABLE_UNPRIVILEGED),
  SD_BUS_METHOD("Enable", SD_BUS_TYPE_OBJECT_PATH SD_BUS_TYPE_ARRAY SD_BUS_TYPE_DICT_ENTRY_BEGIN SD_BUS_TYPE_STRING SD_BUS_TYPE_VARIANT SD_BUS_TYPE_DICT_ENTRY_END, VOID_RETURN, dbus_method_Enable, SD_BUS_VTABLE_UNPRIVILEGED),
  SD_BUS_METHOD("Disable", SD_BUS_TYPE_OBJECT_PATH SD_BUS_TYPE_ARRAY SD_BUS_TYPE_DICT_ENTRY_BEGIN SD_BUS_TYPE_STRING SD_BUS_TYPE_VARIANT SD_BUS_TYPE_DICT_ENTRY_END, VOID_RETURN, dbus_method_Disable, SD_BUS_VTABLE_UNPRIVILEGED),
  SD_BUS_METHOD("Release", SD_BUS_TYPE_OBJECT_PATH SD_BUS_TYPE_ARRAY SD_BUS_TYPE_DICT_ENTRY_BEGIN SD_BUS_TYPE_STRING SD_BUS_TYPE_VARIANT SD_BUS_TYPE_DICT_ENTRY_END, VOID_RETURN, dbus_method_Release, SD_BUS_VTABLE_UNPRIVILEGED),
  SD_BUS_METHOD("ConnectToEIS", SD_BUS_TYPE_OBJECT_PATH SD_BUS_TYPE_ARRAY SD_BUS_TYPE_DICT_ENTRY_BEGIN SD_BUS_TYPE_STRING SD_BUS_TYPE_VARIANT SD_BUS_TYPE_DICT_ENTRY_END, SD_BUS_TYPE_UNIX_FD, dbus_method_ConnectToEIS, SD_BUS_VTABLE_UNPRIVILEGED),
  SD_BUS_SIGNAL("Disabled", SD_BUS_TYPE_OBJECT_PATH SD_BUS_TYPE_ARRAY SD_BUS_TYPE_DICT_ENTRY_BEGIN SD_BUS_TYPE_STRING SD_BUS_TYPE_VARIANT SD_BUS_TYPE_DICT_ENTRY_END, 0),
  SD_BUS_SIGNAL("Activated", SD_BUS_TYPE_OBJECT_PATH SD_BUS_TYPE_ARRAY SD_BUS_TYPE_DICT_ENTRY_BEGIN SD_BUS_TYPE_STRING SD_BUS_TYPE_VARIANT SD_BUS_TYPE_DICT_ENTRY_END, 0),
  SD_BUS_SIGNAL("Deactivated", SD_BUS_TYPE_OBJECT_PATH SD_BUS_TYPE_ARRAY SD_BUS_TYPE_DICT_ENTRY_BEGIN SD_BUS_TYPE_STRING SD_BUS_TYPE_VARIANT SD_BUS_TYPE_DICT_ENTRY_END, 0),
  SD_BUS_SIGNAL("ZonesChanged", SD_BUS_TYPE_OBJECT_PATH SD_BUS_TYPE_ARRAY SD_BUS_TYPE_DICT_ENTRY_BEGIN SD_BUS_TYPE_STRING SD_BUS_TYPE_VARIANT SD_BUS_TYPE_DICT_ENTRY_END, 0),
  SD_BUS_VTABLE_END,
};

static const sd_bus_vtable session_vtable[] = {
  SD_BUS_VTABLE_START(0),
  SD_BUS_METHOD("Close", "", "", dbus_method_Close, SD_BUS_VTABLE_UNPRIVILEGED),
  SD_BUS_VTABLE_END,
};

/* --- Wayland listeners --- */
static void wayland_handle_layer_surface_configure(void *, struct zwlr_layer_surface_v1 *, uint32_t, uint32_t, uint32_t);
static void wayland_handle_layer_surface_closed(void *, struct zwlr_layer_surface_v1 *);
static const struct zwlr_layer_surface_v1_listener layer_surface_listener = {
  .configure = wayland_handle_layer_surface_configure,
  .closed = wayland_handle_layer_surface_closed
};

static const struct wl_registry_listener registry_listener = {
  .global = wayland_registry_global,
  .global_remove = wayland_registry_global_remove
};

static void wayland_handle_pointer_enter(void *, struct wl_pointer *, uint32_t, struct wl_surface *, wl_fixed_t, wl_fixed_t);
static void wayland_handle_pointer_leave(void *, struct wl_pointer *, uint32_t, struct wl_surface *);
static void wayland_handle_pointer_motion(void *, struct wl_pointer *, uint32_t, wl_fixed_t, wl_fixed_t);
static void wayland_handle_pointer_button(void *, struct wl_pointer *, uint32_t, uint32_t, uint32_t, uint32_t);
static void wayland_handle_pointer_axis(void *, struct wl_pointer *, uint32_t, uint32_t, wl_fixed_t);
static const struct wl_pointer_listener pointer_listener = {
  .enter = wayland_handle_pointer_enter,
  .leave = wayland_handle_pointer_leave,
  .motion = wayland_handle_pointer_motion,
  .button = wayland_handle_pointer_button,
  .axis = wayland_handle_pointer_axis
};

static void wayland_handle_keyboard_keymap(void *, struct wl_keyboard *, uint32_t, int32_t, uint32_t);
static void wayland_handle_keyboard_enter(void *, struct wl_keyboard *, uint32_t, struct wl_surface *, struct wl_array *);
static void wayland_handle_keyboard_leave(void *, struct wl_keyboard *, uint32_t, struct wl_surface *);
static void wayland_handle_keyboard_key(void *, struct wl_keyboard *, uint32_t, uint32_t, uint32_t, uint32_t);
static void wayland_handle_keyboard_modifiers(void *, struct wl_keyboard *, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
static void wayland_handle_keyboard_repeat(void *, struct wl_keyboard *, int32_t, int32_t);
static const struct wl_keyboard_listener keyboard_listener = {
  .keymap = wayland_handle_keyboard_keymap,
  .enter = wayland_handle_keyboard_enter,
  .leave = wayland_handle_keyboard_leave,
  .key = wayland_handle_keyboard_key,
  .modifiers = wayland_handle_keyboard_modifiers,
  .repeat_info = wayland_handle_keyboard_repeat
};

static void wayland_handle_seat_capabilities(void *, struct wl_seat *, uint32_t);
static void wayland_handle_seat_name(void *, struct wl_seat *, const char *);
static const struct wl_seat_listener seat_listener = {
  .capabilities = wayland_handle_seat_capabilities,
  .name = wayland_handle_seat_name
};

static void wayland_handle_inhibitor_active(void *, struct zwp_keyboard_shortcuts_inhibitor_v1 *);
static void wayland_handle_inhibitor_inactive(void *, struct zwp_keyboard_shortcuts_inhibitor_v1 *);
static const struct zwp_keyboard_shortcuts_inhibitor_v1_listener inhibitor_listener = {
  .active = wayland_handle_inhibitor_active,
  .inactive = wayland_handle_inhibitor_inactive
};

static void wayland_handle_locked_pointer_locked(void *data, struct zwp_locked_pointer_v1 *locked_pointer) {
  logprint(DEBUG, "Wayland: Pointer locked");
}
static void wayland_handle_locked_pointer_unlocked(void *data, struct zwp_locked_pointer_v1 *locked_pointer) {
  logprint(DEBUG, "Wayland: Pointer unlocked");
}
static const struct zwp_locked_pointer_v1_listener locked_pointer_listener = {
  .locked = wayland_handle_locked_pointer_locked,
  .unlocked = wayland_handle_locked_pointer_unlocked
};

static const struct wl_output_listener output_listener = {
  .geometry = output_handle_geometry,
  .mode = output_handle_mode,
  .done = output_handle_done,
  .scale = output_handle_scale
};

static void free_barrier_list(struct Barrier *list) {
  struct Barrier *b = list;
  while (b) {
    struct Barrier *next = b->next;
    free(b);
    b = next;
  }
}

static void sc_free(struct SessionContext *sc) {
  if (!sc) return;
  if (sc->session_path) free(sc->session_path);
  if (sc->parent_window) free(sc->parent_window);
  if (sc->handle_token) free(sc->handle_token);
  if (sc->session_handle_token) free(sc->session_handle_token);
  free_barrier_list(sc->barriers);
  free(sc);
}

static struct SessionContext *sc_create(const char *session_path, const char *parent_window, const char *handle_token, const char *session_handle_token, uint32_t capabilities) {
  struct SessionContext *context = (struct SessionContext*)calloc(1, sizeof(struct SessionContext));
  if (!context) return NULL;
  
  context->session_path = strdup(session_path);
  context->parent_window = strdup(parent_window);
  context->handle_token = strdup(handle_token);
  context->session_handle_token = strdup(session_handle_token);
  context->capabilities = capabilities;

  if (!context->session_path ||!context->parent_window || !context->handle_token || !context->session_handle_token) {
    sc_free(context);
    return NULL;
  }
  return context;
}

static int dbus_method_Close(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
  (void)ret_error;
  struct SessionContext *context = (struct SessionContext *)userdata;
  logprint(DEBUG, "Closing session (handle: %s)", context->handle_token ? context->handle_token : "UNDEFINED");

  struct SessionContext **p = &interface_data.session_list_head;
  while (*p) {
    if (*p == context) {
      *p = context->next;
      break;
    }
    p = &(*p)->next;
  }

  if (context->enabled) {
    cleanup_session_wayland(context);
    interface_data.active_session = NULL;
  }

  sd_bus_slot_unref(context->slot); 
  sc_free(context);

  return sd_bus_reply_method_return(m, NULL);
}

/*--------------------------------------------- Properties ------------------------------------------------------------*/
static int dbus_property_SupportedCapabilities(sd_bus *bus, const char *path, const char *interface, 
                                           const char *member, sd_bus_message *reply, 
                                           void *userdata, sd_bus_error *ret_error) {
  (void)bus;
  (void)path;
  (void)interface;
  (void)member;
  (void)userdata;
  (void)ret_error;
  return sd_bus_message_append(reply, SD_BUS_TYPE_UINT32, interface_data.capabilities);
}

static int dbus_property_version(sd_bus *bus, const char *path, const char *interface, 
                                           const char *member, sd_bus_message *reply, 
                                           void *userdata, sd_bus_error *ret_error) {
  (void)bus;
  (void)path;
  (void)interface;
  (void)member;
  (void)userdata;
  (void)ret_error;
  return sd_bus_message_append(reply, SD_BUS_TYPE_UINT32, interface_data.version);
}

static int dbus_helper_drain_dict(sd_bus_message *m) {
  int r = sd_bus_message_enter_container(m, 'a', "{sv}");
  if (r < 0) {
    logprint(ERROR, "Error entering container: %s", strerror(-r));
    return r;
  }
  while (1) {
    r = sd_bus_message_skip(m, "{sv}");
    if (r < 0) {
      logprint(ERROR, "Error skipping key-value pair in dictionary: %s", strerror(-r));
      return r;
    }
    if (r == 0) break;
  }
  return sd_bus_message_exit_container(m);
}

static int dbus_helper_parse_CreateSession_options(sd_bus_message *m, const char **handle_token, const char **session_handle_token, uint32_t *capabilities) {
  int r;

  r = sd_bus_message_enter_container(m, 'a', "{sv}");
  if (r < 0) {
    logprint(ERROR, "Error entering container: %s", strerror(-r));
    return r;
  }

  while (sd_bus_message_at_end(m, 0) == 0) {
    const char *key;

    r = sd_bus_message_enter_container(m, 'e', "sv");
    if (r < 0) {
      logprint(ERROR, "Failed to enter dict entry: %s", strerror(-r));
      return r;
    }

    r = sd_bus_message_read(m, "s", &key);
    if (r < 0) {
      logprint(ERROR, "Failed to read dict key: %s", strerror(-r));
      return r;
    }

    if (strcmp(key, "handle_token") == 0) {
      r = sd_bus_message_read(m, "v", "s", handle_token);
      if (r < 0) {
        logprint(ERROR, "Failed to read handle_token's value: %s", strerror(-r));
        return r;
      }
    } 
    else if (strcmp(key, "session_handle_token") == 0) {
      r = sd_bus_message_read(m, "v", "s", session_handle_token);
      if (r < 0) {
        logprint(ERROR, "Failed to read session_handle_token's value: %s", strerror(-r));
        return r;
      }
    }
    else if (strcmp(key, "capabilities") == 0) {
      r = sd_bus_message_read(m, "v", "u", capabilities);
      if (r < 0) {
        logprint(ERROR, "Failed to read capabilities's value: %s", strerror(-r));
        return r;
      }
    }
    else {
      logprint(DEBUG, "Skipping unknown option: %s", key);
      sd_bus_message_skip(m, "v");
      if (r < 0) {
        logprint(ERROR, "Failed to skip variant for key '%s': %s", key, strerror(-r));
        return r;
      }
    }

    r = sd_bus_message_exit_container(m);
    if (r < 0) {
      logprint(ERROR, "Failed to exit entry: %s", strerror(-r));
      return r;
    }
  }

  r = sd_bus_message_exit_container(m);
  if (r < 0) {
    logprint(ERROR, "Failed to exit container: %s", strerror(-r));
    return r;
  }

  return 0;
}

static char *dbus_helper_get_sender(const char *str) {
  size_t len = strlen(str);
  char *out = (char *)malloc(len + 1);
  if (!out) return NULL;

  size_t j = 0;
  for (size_t i = 0; i < len; i++) {
      if (str[i] == ':') {
          continue;
      } else if (str[i] == '.') {
          out[j++] = '_';
      } else {
          out[j++] = str[i];
      }
  }

  out[j] = '\0';
  return out;
}

static int dbus_helper_generate_path(char **path, const char *type, const char *sender, const char *token) {
  int size_needed = snprintf(NULL, 0, "%s/%s/%s/%s", OBJECT_PATH_NAME, type, sender, token);

  if (size_needed < 0) return -EINVAL;

  *path = (char *)malloc(size_needed + 1);
  if (!path) return -ENOMEM;

  snprintf(*path, size_needed + 1, "%s/%s/%s/%s", OBJECT_PATH_NAME, type, sender, token);
  return 0;
}

static int dbus_method_CreateSession(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
  (void)userdata;
  (void)ret_error;

  int r;
  const char *parent_window = NULL;
  const char *handle_token = NULL;
  const char *session_handle_token = NULL;
  uint32_t capabilities = 0;

  char *session_path = NULL;
  char *request_path = NULL;
  char *sender = NULL;
  struct SessionContext *context = NULL;

  r = sd_bus_message_read(m, SD_BUS_TYPE_STRING, &parent_window);
  if (r < 0) return r;

  r = dbus_helper_parse_CreateSession_options(m, &handle_token, &session_handle_token, &capabilities);
  if (r < 0) return r;

  if ((capabilities & ~interface_data.capabilities) != 0 || capabilities == 0) return -EINVAL;

  // 2. generate session objects

  sender = dbus_helper_get_sender(sd_bus_message_get_sender(m));
  if (!sender) return -ENOMEM;

  r = dbus_helper_generate_path(&session_path, "session", sender, session_handle_token);
  if (r < 0) goto cleanup_paths;

  r = dbus_helper_generate_path(&request_path, "request", sender, handle_token);
  if (r < 0) goto cleanup_paths;

  context = sc_create(session_path, parent_window, handle_token, session_handle_token, capabilities);
  if (!context) { r = -ENOMEM; goto cleanup_paths; }

  r = sd_bus_add_object_vtable(
    sd_bus_message_get_bus(m),
    &context->slot,
    context->session_path,
    SESSION_INTERFACE_NAME,
    session_vtable,
    context
  );
  if (r < 0) {
    logprint(ERROR, "Error adding new object to session_vtable: %s", strerror(-r));
    sc_free(context);
    goto cleanup_paths;
  }

  context->next = interface_data.session_list_head;
  interface_data.session_list_head = context;

  logprint(DEBUG, "CreateSession call: created new session: %s", context->session_path);

  r = sd_bus_reply_method_return(m, SD_BUS_TYPE_OBJECT_PATH, request_path);
  if (r < 0) {
    sd_bus_slot_unref(context->slot);
    sc_free(context);
    goto cleanup_paths;
  }
  
  sd_bus_message *reply;
  sd_bus *bus = sd_bus_message_get_bus(m);

  r = sd_bus_message_new_signal(bus, &reply, request_path, REQUEST_INTERFACE_NAME, "Response");
  if (r < 0) goto response_finish;
  
  r = sd_bus_message_append(reply, SD_BUS_TYPE_UINT32, 0U);
  if (r < 0) goto unref_reply;

  r = sd_bus_message_open_container(reply, 'a', "{sv}");
  if (r < 0) goto unref_reply;

  r = sd_bus_message_open_container(reply, 'e', "sv");
  if (r < 0) goto unref_reply;
  r = sd_bus_message_append(reply, SD_BUS_TYPE_STRING, "session_handle");
  if (r < 0) goto unref_reply;
  r = sd_bus_message_append(reply, "v", SD_BUS_TYPE_OBJECT_PATH, context->session_path);
  if (r < 0) goto unref_reply;
  r = sd_bus_message_close_container(reply);

  r = sd_bus_message_open_container(reply, 'e', "sv");
  if (r < 0) goto unref_reply;
  r = sd_bus_message_append(reply, SD_BUS_TYPE_STRING, "capabilities");
  if (r < 0) goto unref_reply;
  r = sd_bus_message_append(reply, "v", SD_BUS_TYPE_UINT32, context->capabilities);
  if (r < 0) goto unref_reply;
  r = sd_bus_message_close_container(reply);
  
  r = sd_bus_message_close_container(reply);

  r = sd_bus_send(bus, reply, NULL);
  if (r < 0) {
    logprint(ERROR, "Error sending CreateSession Response signal: %s", strerror(-r));
  }
  else logprint(DEBUG, "Sent Request::Response signal for CreateSession to handle: %s", request_path);

unref_reply:
  sd_bus_message_unref(reply);
response_finish:
  free(sender);
  free(session_path);
  free(request_path);
  return r;
cleanup_paths:
  if (sender) free(sender);
  if (session_path) free(session_path);
  if (request_path) free(request_path);
  return r;
}

static int dbus_helper_parse_GetZones_options(sd_bus_message *m, const char **handle_token) {
  int r;
  r = sd_bus_message_enter_container(m, 'a', "{sv}");
  if (r < 0) {
    logprint(ERROR, "Error entering container: %s", strerror(-r));
    return r;
  }

  while (sd_bus_message_at_end(m, 0) == 0) {
    const char *key;
    r = sd_bus_message_enter_container(m, 'e', "sv");
    if (r < 0) {
      logprint(ERROR, "Failed to enter dict entry: %s", strerror(-r));
      return r;
    }

    r = sd_bus_message_read(m, "s", &key);
    if (r < 0) {
      logprint(ERROR, "Failed to read dict key: %s", strerror(-r));
      return r;
    }

    if (strcmp(key, "handle_token") == 0) {
      r = sd_bus_message_read(m, "v", "s", handle_token);
      if (r < 0) {
        logprint(ERROR, "Failed to read handle_token's value: %s", strerror(-r));
        return r;
      }
    } 
    else {
      logprint(DEBUG, "Skipping unknown option: %s", key);
      sd_bus_message_skip(m, "v");
      if (r < 0) {
        logprint(ERROR, "Failed to skip variant for key '%s': %s", key, strerror(-r));
        return r;
      }
    }

    r = sd_bus_message_exit_container(m);
    if (r < 0) {
      logprint(ERROR, "Failed to exit entry: %s", strerror(-r));
      return r;
    }
  }

  r = sd_bus_message_exit_container(m);
  if (r < 0) {
    logprint(ERROR, "Failed to exit container: %s", strerror(-r));
    return r;
  }

  return 0;
}

static int dbus_method_GetZones(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
  int r;
  const char *session_handle = NULL;
  const char *handle_token = NULL;
  char *request_path = NULL;
  char *sender = NULL;
  struct SessionContext *context = NULL;
  sd_bus *bus = sd_bus_message_get_bus(m);
  sd_bus_message *reply = NULL;

  r = sd_bus_message_read(m, SD_BUS_TYPE_OBJECT_PATH, &session_handle);
  if (r < 0) return r;

  context = eis_helper_find_session(session_handle);
  if (!context) {
    sd_bus_error_setf(ret_error, "org.freedesktop.portal.Error.NotFound", "session_handle %s not found", session_handle);
    return -ENOENT;
  }

  r = dbus_helper_parse_GetZones_options(m, &handle_token);
  if (r < 0) {
    sd_bus_error_setf(ret_error, SD_BUS_ERROR_INVALID_ARGS, "Failed to parse options: %s", strerror(-r));
    return r;
  }

  sender = dbus_helper_get_sender(sd_bus_message_get_sender(m));
  if (!sender) { r = -ENOMEM; goto cleanup; }

  r = dbus_helper_generate_path(&request_path, "request", sender, handle_token);
  if (r < 0) {
    logprint(ERROR, "GetZones: failde to reply with request_path: %s", strerror(-r));
    goto cleanup;
  }

  logprint(DEBUG, "GetZones: sending async response to %s", request_path);
  r = sd_bus_reply_method_return(m, SD_BUS_TYPE_OBJECT_PATH, request_path);

  context->zone_set_id += 1;
  if (context->zone_set_id == 0) context->zone_set_id = 1;

  r = sd_bus_message_new_signal(bus, &reply, request_path, REQUEST_INTERFACE_NAME, "Response");
  if (r < 0) goto cleanup_signal;
  
  r = sd_bus_message_append(reply, SD_BUS_TYPE_UINT32, 0U);
  if (r < 0) goto cleanup_signal;

  r = sd_bus_message_open_container(reply, 'a', "{sv}");
  if (r < 0) goto cleanup_signal;

  r = sd_bus_message_open_container(reply, 'e', "sv");
  if (r < 0) goto cleanup_signal;
  r = sd_bus_message_append(reply, SD_BUS_TYPE_STRING, "zone_set");
  if (r < 0) goto cleanup_signal;
  r = sd_bus_message_append(reply, "v", SD_BUS_TYPE_UINT32, context->zone_set_id);
  if (r < 0) goto cleanup_signal;
  r = sd_bus_message_close_container(reply);
  if (r < 0) goto cleanup_signal;

  r = sd_bus_message_open_container(reply, 'e', "sv");
  if (r < 0) goto cleanup_signal;
  r = sd_bus_message_append(reply, SD_BUS_TYPE_STRING, "zones");
  if (r < 0) goto cleanup_signal;
  
  r = sd_bus_message_open_container(reply, 'v', "a(uuii)");
  if (r < 0) goto cleanup_signal;
  
  r = sd_bus_message_open_container(reply, 'a', "(uuii)");
  if (r < 0) goto cleanup_signal;

  struct Output *iter;
  wl_list_for_each(iter, &interface_data.output_list, link) {
    if (iter->ready) {
      r = sd_bus_message_append(
        reply, 
        "(uuii)",
        iter->width,
        iter->height,
        iter->x,
        iter->y
      );
      if (r < 0) {
        logprint(ERROR, "GetZones: Failed to append zone: %s", strerror(-r));
        goto cleanup_signal;
      }
    }
  }

  r = sd_bus_message_close_container(reply);
  if (r < 0) goto cleanup_signal;
  r = sd_bus_message_close_container(reply);
  if (r < 0) goto cleanup_signal;
  r = sd_bus_message_close_container(reply);
  if (r < 0) goto cleanup_signal;

  r = sd_bus_message_close_container(reply);
  if (r < 0) goto cleanup_signal;

  r = sd_bus_send(bus, reply, NULL);
  if (r < 0) {
    logprint(ERROR, "GetZones: Error sending Response signal: %s", strerror(-r));
  } else {
    logprint(DEBUG, "GetZones: Sent Request::Response signal for handle: %s", request_path);
  }

cleanup_signal:
  sd_bus_message_unref(reply);
cleanup:
  if (sender) free(sender);
  if (request_path) free(request_path);
  return r;
}

static int parse_and_store_barriers(sd_bus_message *m, struct SessionContext *context, struct Barrier **out_failed_barriers_head) {
  int r;
  struct Barrier *new_barriers_head = NULL;
  struct Barrier *failed_barriers_head = NULL;

  free_barrier_list(context->barriers);
  context->barriers = NULL;

  r = sd_bus_message_enter_container(m, 'a', "a{sv}");
  if (r < 0) return r;

  while ((r = sd_bus_message_enter_container(m, 'a', "{sv}")) > 0) {
    uint32_t barrier_id = 0;
    int32_t x1 = 0, y1 = 0, x2 = 0, y2 = 0;
    bool pos_found = false;
    bool id_found = false;

    while ((r = sd_bus_message_enter_container(m, 'e', "sv")) > 0) {
      const char *key;
      r = sd_bus_message_read(m, "s", &key);
      if (r < 0) break;

      if (strcmp(key, "barrier_id") == 0) {
        sd_bus_message_read(m, "v", "u", &barrier_id);
        id_found = true;
      } else if (strcmp(key, "position") == 0) {
        sd_bus_message_enter_container(m, 'v', "(iiii)");
        sd_bus_message_enter_container(m, 'r', "iiii");
        sd_bus_message_read(m, "i", &x1);
        sd_bus_message_read(m, "i", &y1);
        sd_bus_message_read(m, "i", &x2);
        sd_bus_message_read(m, "i", &y2);
        sd_bus_message_exit_container(m);
        sd_bus_message_exit_container(m);
        pos_found = true;
      } else {
        sd_bus_message_skip(m, "v");
      }
      sd_bus_message_exit_container(m);
    }
    if (r < 0) break; 

    bool failed = false;
    if (!id_found || barrier_id == 0 || !pos_found) {
      failed = true;
    }
    if (x1 != x2 && y1 != y2) {
      failed = true;
    }

    if (failed) {
      struct Barrier *fail_node = (struct Barrier *)malloc(sizeof(struct Barrier));
      fail_node->id = barrier_id;
      fail_node->next = failed_barriers_head;
      failed_barriers_head = fail_node;
    } else {
      struct Barrier *new_node = (struct Barrier *)malloc(sizeof(struct Barrier));
      new_node->id = barrier_id;
      new_node->x1 = x1; new_node->y1 = y1;
      new_node->x2 = x2; new_node->y2 = y2;
      new_node->next = new_barriers_head;
      new_barriers_head = new_node;
      logprint(DEBUG, "  -> Stored valid barrier ID %u (%i, %i to %i, %i)", barrier_id, x1, y1, x2, y2);
    }
    sd_bus_message_exit_container(m);
  }

  if (r < 0) {
    free_barrier_list(new_barriers_head);
    free_barrier_list(failed_barriers_head);
    return r;
  }

  sd_bus_message_exit_container(m);
  context->barriers = new_barriers_head;
  *out_failed_barriers_head = failed_barriers_head;
  return 0;
}

static int dbus_method_SetPointerBarriers(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
  const char *session_handle = NULL;
  const char *handle_token = NULL;
  uint32_t client_zone_set_id = 0;
  char *request_path = NULL;
  char *sender = NULL;
  struct SessionContext *context = NULL;
  sd_bus *bus = sd_bus_message_get_bus(m);
  sd_bus_message *reply= NULL;
  struct Barrier *failed_barriers_list = NULL;
  int r;

  r = sd_bus_message_read(m, SD_BUS_TYPE_OBJECT_PATH, &session_handle);
  if (r < 0) return r;

  context = eis_helper_find_session(session_handle);
  if (!context) {
    sd_bus_error_setf(ret_error, "org.freedesktop.portal.Error.NotFound", "session_handle %s not found", session_handle);
    return -ENOENT;
  }

  r = dbus_helper_parse_GetZones_options(m, &handle_token);
  if (r < 0) return r;

  r = parse_and_store_barriers(m, context, &failed_barriers_list);
  if (r < 0) {
    sd_bus_error_setf(ret_error, SD_BUS_ERROR_INVALID_ARGS, "Failed to parse barriers array: %s", strerror(-r));
    return r;
  }

  r = sd_bus_message_read(m, SD_BUS_TYPE_UINT32, &client_zone_set_id);
  if (r < 0) return r;

  if (client_zone_set_id != context->zone_set_id) {
    logprint(WARN, "SetPointerbarriers: zone set id mismatch (client: %u, server: %u)", client_zone_set_id, context->zone_set_id);
    sd_bus_error_setf(ret_error, "org.freedesktop.portal.Error.NotFound", "Zone set id mismatch (client: %u, server: %u)", client_zone_set_id, context->zone_set_id);
    free_barrier_list(context->barriers);
    context->barriers = NULL;
    free_barrier_list(failed_barriers_list);
    return -EINVAL;
  }

  logprint(DEBUG, "SetPointerBarriers: Sucessfully set barriers for zone set %u", client_zone_set_id);

  sender = dbus_helper_get_sender(sd_bus_message_get_sender(m));
  if (!sender) { r = -ENOMEM; goto cleanup; }
  r = dbus_helper_generate_path(&request_path, "request", sender, handle_token);
  if (r < 0) goto cleanup;

  r = sd_bus_reply_method_return(m, SD_BUS_TYPE_OBJECT_PATH, request_path);
  if (r < 0) {
    goto cleanup;
  }

  r = sd_bus_message_new_signal(bus, &reply, request_path, REQUEST_INTERFACE_NAME, "Response");
  if (r < 0) goto cleanup;
  r = sd_bus_message_append(reply, SD_BUS_TYPE_UINT32, 0U);
  if (r < 0) goto cleanup_signal;

  r = sd_bus_message_open_container(reply, 'a', "{sv}");
  if (r < 0) goto cleanup_signal;

  r = sd_bus_message_open_container(reply, 'e', "sv");
  if (r < 0) goto cleanup_signal;
  r = sd_bus_message_append(reply, SD_BUS_TYPE_STRING, "failed_barriers");
  if (r < 0) goto cleanup_signal;
  r = sd_bus_message_open_container(reply, 'v', "au");
  if (r < 0) goto cleanup_signal;
  r = sd_bus_message_open_container(reply, 'a', "u");
  if (r < 0) goto cleanup_signal;

  struct Barrier *b = failed_barriers_list;
  while (b) {
    sd_bus_message_append(reply, "u", b->id);
    b = b->next;
  }

  r = sd_bus_message_close_container(reply);
  if (r < 0) goto cleanup_signal;
  r = sd_bus_message_close_container(reply);
  if (r < 0) goto cleanup_signal;
  r = sd_bus_message_close_container(reply);
  if (r < 0) goto cleanup_signal;
  r = sd_bus_message_close_container(reply); 
  if (r < 0) goto cleanup_signal;

  r = sd_bus_send(bus, reply, NULL);
  logprint(DEBUG, "SetPointerBarriers: Sent Response signal to %s", request_path);

cleanup_signal:
  sd_bus_message_unref(reply);
cleanup:
  if (sender) free(sender);
  if (request_path) free(request_path);
  free_barrier_list(failed_barriers_list);
  return r;
}

static int dbus_method_Enable(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
  const char *session_handle;
  int r;
  r = sd_bus_message_read(m, SD_BUS_TYPE_OBJECT_PATH, &session_handle);
  if (r < 0) return r;

  r = dbus_helper_drain_dict(m);
  if (r < 0) return r;

  struct SessionContext *context = eis_helper_find_session(session_handle);
  if (!context) {
    sd_bus_error_setf(ret_error, "org.freedesktop.portal.Error.NotFound", "session_handle %s not found", session_handle);
    return -ENOENT;
  }

  logprint(DEBUG, "Enable call with session_handle %s", session_handle);

  if (context->enabled) {
    return sd_bus_reply_method_return(m, VOID_RETURN);
  }
  
  if (interface_data.active_session) {
    sd_bus_error_setf(ret_error, "org.freedesktop.portal.Error.Failed", "Another session is already active");
    return -EBUSY;
  }
  
  if (!interface_data.wl_compositor || !interface_data.wl_layer_shell ||
      !interface_data.wl_seat || !interface_data.wl_pointer_constraints ||
      !interface_data.wl_keyboard_shortcuts_manager) {
    sd_bus_error_setf(ret_error, "org.freedesktop.portal.Error.NotSupported", "Compositor is missing required wayland protocols");
    return -EOPNOTSUPP;
  }

  if (context->capabilities & 2) {
    context->wl_pointer = wl_seat_get_pointer(interface_data.wl_seat);
    if (!context->wl_pointer) {
      sd_bus_error_setf(ret_error, "org.freedesktop.portal.Error.Failed", "Failed to get wl_pointer");
      r = -EIO;
      goto cleanup_fail;
    }
    wl_pointer_add_listener(context->wl_pointer, &pointer_listener, context);
  }
  if (context->capabilities & 1) {
    context->wl_keyboard = wl_seat_get_keyboard(interface_data.wl_seat);
    if (!context->wl_keyboard) {
      sd_bus_error_setf(ret_error, "org.freedesktop.portal.Error.Failed", "Failed to get wl_keyboard");
      r = -EIO;
      goto cleanup_fail;
    }
    wl_keyboard_add_listener(context->wl_keyboard, &keyboard_listener, context);
  }
  
  context->wl_surface = wl_compositor_create_surface(interface_data.wl_compositor);
  if (!context->wl_surface) {
    sd_bus_error_setf(ret_error, "org.freedesktop.portal.Error.Failed", "Failed to create wl_surface");
    r = -EIO;
    goto cleanup_fail;
  }
  
  context->wl_layer_surface = zwlr_layer_shell_v1_get_layer_surface(
    interface_data.wl_layer_shell,
    context->wl_surface,
    NULL, // no output, global
    ZWLR_LAYER_SHELL_V1_LAYER_OVERLAY,
    "input-capture-portal"
  );
  if (!context->wl_layer_surface) {
    sd_bus_error_setf(ret_error, "org.freedesktop.portal.Error.Failed", "Failed to create wl_layer_surface");
    r = -EIO;
    goto cleanup_fail;
  }

  zwlr_layer_surface_v1_add_listener(context->wl_layer_surface, &layer_surface_listener, context);
  zwlr_layer_surface_v1_set_anchor(context->wl_layer_surface, ZWLR_LAYER_SURFACE_V1_ANCHOR_TOP | ZWLR_LAYER_SURFACE_V1_ANCHOR_LEFT | ZWLR_LAYER_SURFACE_V1_ANCHOR_RIGHT | ZWLR_LAYER_SURFACE_V1_ANCHOR_BOTTOM);
  zwlr_layer_surface_v1_set_size(context->wl_layer_surface, 0, 0);
  wl_surface_set_input_region(context->wl_surface, NULL);
  
  if (context->capabilities & 1) {
    zwlr_layer_surface_v1_set_keyboard_interactivity(context->wl_layer_surface, 1);
  }
  
  wl_surface_commit(context->wl_surface);

  if (context->capabilities & 1) {
    context->wl_keyboard_inhibitor = zwp_keyboard_shortcuts_inhibit_manager_v1_inhibit_shortcuts(
      interface_data.wl_keyboard_shortcuts_manager,
      context->wl_surface,
      interface_data.wl_seat
    );
    if (!context->wl_keyboard_inhibitor) {
      sd_bus_error_setf(ret_error, "org.freedesktop.portal.Error.Failed", "Failed to create keyboard inhibitor");
      r = -EIO;
      goto cleanup_fail;
    }
    zwp_keyboard_shortcuts_inhibitor_v1_add_listener(
      context->wl_keyboard_inhibitor,
      &inhibitor_listener,
      context
    );
  }
  
  wl_display_roundtrip(interface_data.wl_display);
  
  context->enabled = true;
  interface_data.active_session = context;
  
  return sd_bus_reply_method_return(m, VOID_RETURN);

cleanup_fail:
  cleanup_session_wayland(context);
  return r;
}

static void cleanup_session_wayland(struct SessionContext *context) {
  if (!context) return;

  logprint(DEBUG, "cleaning up wayland resources for session %s", context->session_path);

  if (context->wl_keyboard_inhibitor) {
    zwp_keyboard_shortcuts_inhibitor_v1_destroy(context->wl_keyboard_inhibitor);
    context->wl_keyboard_inhibitor = NULL;
  }
  if (context->wl_locked_pointer) {
    zwp_locked_pointer_v1_destroy(context->wl_locked_pointer);
    context->wl_locked_pointer = NULL;
  }
  if (context->wl_layer_surface) {
    zwlr_layer_surface_v1_destroy(context->wl_layer_surface);
    context->wl_layer_surface = NULL;
  }
  if (context->wl_surface) {
    wl_surface_destroy(context->wl_surface);
    context->wl_surface = NULL;
  }
  if (context->wl_pointer) {
    wl_pointer_destroy(context->wl_pointer);
    context->wl_pointer = NULL;
  }
  if (context->wl_keyboard) {
    wl_keyboard_destroy(context->wl_keyboard);
    context->wl_keyboard = NULL;
  }
  if (context->xkb_state) {
    xkb_state_unref(context->xkb_state);
    context->xkb_state = NULL;
  }
  if(context->xkb_keymap) {
    xkb_keymap_unref(context->xkb_keymap);
    context->xkb_keymap = NULL;
  }
  if (interface_data.wl_display) {
    wl_display_flush(interface_data.wl_display);
  }
}

static int dbus_method_Disable(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
  const char *session_handle;
  int r;
  r = sd_bus_message_read(m, SD_BUS_TYPE_OBJECT_PATH, &session_handle);
  if (r < 0) return r;

  r = dbus_helper_drain_dict(m);
  if (r < 0) return r;

  struct SessionContext *context = eis_helper_find_session(session_handle);
  if (!context) {
    sd_bus_error_setf(ret_error, "org.freedesktop.portal.Error.NotFound", "session_handle %s not found", session_handle);
    return -ENOENT;
  }

  logprint(DEBUG, "Disable call with session_handle %s", session_handle);
  if (!context->enabled) {
    return sd_bus_reply_method_return(m, VOID_RETURN);
  }

  cleanup_session_wayland(context);

  interface_data.active_session = NULL;
  context->enabled = false;

  dbus_signal_Deactivated(interface_data.bus, context->session_path);

  return sd_bus_reply_method_return(m, VOID_RETURN);
}

static int dbus_method_Release(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
  (void)userdata;
  (void)ret_error;

  const char *session_handle;
  int r;
  r = sd_bus_message_read(m, SD_BUS_TYPE_OBJECT_PATH, &session_handle);
  if (r < 0) {
    logprint(ERROR, "Error reading object path: %s", strerror(-r));
    return r;
  }

  r = dbus_helper_drain_dict(m);
  if (r < 0) {
    logprint(ERROR, "Error draining dictionary: %s", strerror(-r));
    return r;
  }

  struct SessionContext *context = eis_helper_find_session(session_handle);
  if (!context) {
    sd_bus_error_setf(ret_error, "org.freedesktop.portal.Error.NotFound", "%s session_handle not found", session_handle);
    return -ENOENT;
  }

  logprint(DEBUG, "Release call with session_handle %s", session_handle);

  struct SessionContext **p = &interface_data.session_list_head;
  while (*p) {
    if (*p == context) {
      *p = context->next;
      break;
    }
    p = &(*p)->next;
  }

  if (context->enabled) {
    cleanup_session_wayland(context);
    interface_data.active_session = NULL;
  }

  if (context->device) eis_device_stop_emulating(context->device);

  sd_bus_slot_unref(context->slot);
  sc_free(context);

  return sd_bus_reply_method_return(m, VOID_RETURN);
}

static int dbus_method_ConnectToEIS(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
  const char *session_handle;
  int r;

  r = sd_bus_message_read(m, SD_BUS_TYPE_OBJECT_PATH, &session_handle);
  if (r < 0) return r;

  r = dbus_helper_drain_dict(m);
  if (r < 0) return r;

  struct SessionContext *context = eis_helper_find_session(session_handle);
  if (!context) {
    logprint(ERROR, "Could not find session at %s session_handle", session_handle);
    sd_bus_error_setf(ret_error, "org.freedesktop.portal.Error.NotFound", "Session handle '%s' not found", session_handle);
    return -ENOENT;
  }

  logprint(DEBUG, "ConnectToEIS call with session_handle %s", session_handle);

  int eis_fd = eis_get_fd(interface_data.eis_context);
  if (eis_fd < 0) {
    logprint(ERROR, "Could not get eis file descriptor for %s session_handle", session_handle);
    sd_bus_error_setf(ret_error, SD_BUS_ERROR_FAILED, "Eis context is not valid");
    return -EBADF;
  }

  int client_fd = dup(eis_fd);
  if (client_fd < 0) {
    sd_bus_error_setf(ret_error, SD_BUS_ERROR_FAILED, "Failed to dup EIS fd: %s", strerror(errno));
  }

  return sd_bus_reply_method_return(m, SD_BUS_TYPE_UNIX_FD, client_fd);
}


static int dbus_helper_emit_signal(sd_bus *bus, const char *signal_name, const char *session_handle) {
  int r;
  sd_bus_message *m;

  r = sd_bus_message_new_signal(bus, &m, OBJECT_PATH_NAME, INPUTCAPTURE_INTERFACE_NAME, signal_name);
  if (r < 0) {
    logprint(ERROR, "Error creating %s signal message: %s", signal_name, strerror(-r));
    return r;
  }

  r = sd_bus_message_append(m, SD_BUS_TYPE_OBJECT_PATH, session_handle);
  if (r < 0) {
    logprint(ERROR, "Error appending session_handle %s to %s signal message: %s", session_handle, signal_name, strerror(-r));
    goto finish;
  }

  r = sd_bus_message_append(m, SD_BUS_TYPE_ARRAY SD_BUS_TYPE_DICT_ENTRY_BEGIN SD_BUS_TYPE_STRING SD_BUS_TYPE_VARIANT SD_BUS_TYPE_DICT_ENTRY_END, 0); // Passing 0 indicates an empty container
  if (r < 0) {
    logprint(ERROR, "Error appending empty dictionary to %s signal message: %s", signal_name, strerror(-r));
    goto finish;
  }

  r = sd_bus_send(bus, m, NULL);
finish:
  sd_bus_message_unref(m);
  return r;
}

static int dbus_signal_Disabled(sd_bus *bus, const char *session_handle)
{
  logprint(DEBUG, "Emitting Disabled signal");
  return dbus_helper_emit_signal(bus, "Disabled", session_handle);
}

static int dbus_signal_Activated(sd_bus *bus, const char *session_handle)
{
  logprint(DEBUG, "Emitting Activated signal");
  return dbus_helper_emit_signal(bus, "Activated", session_handle);
}

static int dbus_signal_Deactivated(sd_bus *bus, const char *session_handle)
{
  logprint(DEBUG, "Emitting Deactivated signal");
  return dbus_helper_emit_signal(bus, "Deactivated", session_handle);
}

static int dbus_signal_ZonesChanged(sd_bus *bus, const char *session_handle)
{
  logprint(DEBUG, "Emitting ZonesChanged signal");
  return dbus_helper_emit_signal(bus, "ZonesChanged", session_handle);
}

static struct SessionContext* eis_helper_find_session(const char *session_path) {
  struct SessionContext *iter = interface_data.session_list_head;
  while (iter) {
    if (strcmp(iter->session_path, session_path) == 0) {
      return iter;
    }
    iter = iter->next;
  }
  return NULL;
}

static void eis_helper_handle_event(struct eis_event *event) {
  struct eis_client *client;
  struct eis_seat *seat;
  struct SessionContext *context;

  logprint(DEBUG, "EIS Event: %s", eis_event_type_to_string(eis_event_get_type(event)));

  switch (eis_event_get_type(event)) {
    case EIS_EVENT_CLIENT_CONNECT: {
      client = eis_event_get_client(event);
      logprint(DEBUG, "New EIS client connected");
      eis_client_connect(client);
      break;
    }
    case EIS_EVENT_CLIENT_DISCONNECT: {
      client = eis_event_get_client(event);
      context = (struct SessionContext *)eis_client_get_user_data(client);
      if (context) {
        logprint(DEBUG, "EIS client disconnected (session_path: %s)", context->session_path);
        eis_client_set_user_data(client, NULL);
      }
      else {
        logprint(DEBUG, "EIS client disconnected (no session_path)");
      }
      break;
    }
    case EIS_EVENT_SEAT_BIND: {
      seat = eis_event_get_seat(event);
      client = eis_seat_get_client(seat);

      const char *seat_name = eis_seat_get_name(seat);
      logprint(DEBUG, "EIS client bound seat: %s", seat_name);

      context = eis_helper_find_session(seat_name);
      if (!context) {
        logprint(ERROR, "EIS Error: unknown session_path used as seat name: %s", seat_name);
        eis_client_disconnect(client);
      }
      else {
        logprint(DEBUG, "Linking EIS client to session %s", context->session_path);
        eis_client_set_user_data(client, context);

        if (context->capabilities & 1) eis_seat_configure_capability(seat, EIS_DEVICE_CAP_KEYBOARD);
        if (context->capabilities & 2) eis_seat_configure_capability(seat, EIS_DEVICE_CAP_POINTER);
        if (context->capabilities & 4) eis_seat_configure_capability(seat, EIS_DEVICE_CAP_TOUCH);
        eis_seat_add(seat);

        logprint(DEBUG, "Creating new virtual device for session %s", context->session_path);
        struct eis_device *device = eis_seat_new_device(seat);
        context->device = device;

        eis_device_configure_name(device, "Portal Virtual Input");
        eis_device_configure_type(device, EIS_DEVICE_TYPE_VIRTUAL);
        
        if (context->capabilities & 1) eis_device_configure_capability(device, EIS_DEVICE_CAP_KEYBOARD);
        if (context->capabilities & 2) eis_device_configure_capability(device, EIS_DEVICE_CAP_POINTER);
        if (context->capabilities & 4) eis_device_configure_capability(device, EIS_DEVICE_CAP_TOUCH);

        eis_device_add(device);
      }

      break;
    }
    default: 
      logprint(TRACE, "EIS event not handled: %s", eis_event_type_to_string(eis_event_get_type(event)));
      break;
  }
}

// static int eis_helper_dispatch_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
//   (void)s; (void)fd; (void)revents;
//   struct eis *eis = (struct eis*)userdata;

//   // dispatch all pending libeis events
//   eis_dispatch(eis);

//   // process all events in the queue
//   struct eis_event *event;
//   while ((event = eis_get_event(eis))) {
//     eis_helper_handle_event(event);
//     eis_event_unref(event);
//   }

//   return 0;
// }

// static int wayland_dispatch_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
//   struct InputCaptureData *data = (struct InputCaptureData *)userdata;

//   if (revents & (EPOLLERR | EPOLLHUP)) {
//     logprint(ERROR, "Wayland connection error. Shutting down\n");
//     sd_event_exit(data->event_loop, -EIO);
//     return 0;
//   }

//   if (revents & EPOLLIN) {
//     int r = wl_display_dispatch(data->wl_display);
//     if (r < 0) {
//       logprint(ERROR, "Wayland dispatch error. Shutting down\n");
//       sd_event_exit(data->event_loop, -EIO);
//       return 0;
//     }
//   }

//   // try to flush any pending requests
//   if (wl_display_flush(data->wl_display) < 0) {
//     if (errno != EAGAIN) {  // EAGAIN is file, just means buffer is full
//       logprint(ERROR, "Wayland flush error. Shutting down\n");
//       sd_event_exit(data->event_loop, -EIO);
//       return 0;
//     }
//   }

//   return 0;
// }

static void wayland_registry_global(void *data, struct wl_registry *registry,
                                    uint32_t name, const char *interface, uint32_t version) {
  struct InputCaptureData *d = (struct InputCaptureData *)data;

  if (strcmp(interface, wl_compositor_interface.name) == 0) {
    d->wl_compositor = wl_registry_bind(registry, name, &wl_compositor_interface, 4);
    logprint(DEBUG, "Wayland: bound wl_compositor");
  } else if (strcmp(interface, zwlr_layer_shell_v1_interface.name) == 0) {
    d->wl_layer_shell = wl_registry_bind(registry, name, &zwlr_layer_shell_v1_interface, 1);
    logprint(DEBUG, "Wayland: bound zwlr_layer_shell_v1");
  } else if (strcmp(interface, wl_seat_interface.name) == 0) {
    d->wl_seat = wl_registry_bind(registry, name, &wl_seat_interface, 7);
    wl_seat_add_listener(d->wl_seat, &seat_listener, d);
    logprint(DEBUG, "Wayland: bound wl_seat");
  } else if (strcmp(interface, zwp_pointer_constraints_v1_interface.name) == 0) {
    d->wl_pointer_constraints = wl_registry_bind(registry, name, &zwp_pointer_constraints_v1_interface, 1);
    logprint(DEBUG, "Wayland: boudn zwp_pointer_constraints_v1");
  } else if (strcmp(interface, zwp_keyboard_shortcuts_inhibit_manager_v1_interface.name) == 0) {
    d->wl_keyboard_shortcuts_manager = wl_registry_bind(registry, name, &zwp_keyboard_shortcuts_inhibit_manager_v1_interface, 1);
    logprint(DEBUG, "Wayland: bound zwp_keyboard_shortcuts_inhibit_manager_v1");
  } else if (strcmp(interface, wl_output_interface.name) == 0) {
    struct Output *output = calloc(1, sizeof(struct Output));
    if (!output) return;
    output->data = d;
    output->name = name;
    output->wl_output = wl_registry_bind(registry, name, &wl_output_interface, 3);
    wl_output_add_listener(output->wl_output, &output_listener, output);
    wl_list_insert(&d->output_list, &output->link);
    logprint(DEBUG, "Wayland: bound wl_output %u", name);
  }
}

static void wayland_registry_global_remove(void *data, struct wl_registry *registry, uint32_t name) {
  struct InputCaptureData *d = (struct InputCaptureData *)data;
  struct Output *iter, *tmp;

  wl_list_for_each_safe(iter, tmp, &d->output_list, link) {
    if (iter->name == name) {
      wl_list_remove(&iter->link);
      wl_output_destroy(iter->wl_output);
      free(iter);
      logprint(DEBUG, "Wayland: output %u removed", name);
      return;
    }
  }

}

static void wayland_handle_seat_capabilities(void *data, struct wl_seat *seat, uint32_t capabilities) {
  logprint(DEBUG, "Wayland: Seat capabilities changed");
}

static void wayland_handle_seat_name(void *data, struct wl_seat *seat, const char *name) {
  logprint(DEBUG, "Wayland: Seat name changed");
}

static void wayland_handle_inhibitor_active(void *data, struct zwp_keyboard_shortcuts_inhibitor_v1 *inhibitor) {
  struct SessionContext *context = (struct SessionContext *)data;
  logprint(DEBUG, "Wayland: Keyboard inhibitor ACTIVE");
  dbus_signal_Activated(interface_data.bus, context->session_path);
}

static void wayland_handle_inhibitor_inactive(void *data, struct zwp_keyboard_shortcuts_inhibitor_v1 *inhibitor) {
  struct SessionContext *context = (struct SessionContext *)data;
  logprint(DEBUG, "Wayland: keyboard inhibitor INACTIVE");
  dbus_signal_Deactivated(interface_data.bus, context->session_path);
}

static void wayland_handle_layer_surface_configure(void *data, struct zwlr_layer_surface_v1 *surface, uint32_t serial, uint32_t w, uint32_t h) {
  struct SessionContext *state = (struct SessionContext *)data;
  logprint(DEBUG, "Wayland: layer surface configured: %ux%u", w, h);
  zwlr_layer_surface_v1_ack_configure(surface, serial);
  wl_surface_commit(state->wl_surface);
}

static void wayland_handle_layer_surface_closed(void *data, struct zwlr_layer_surface_v1 *surface) {
  struct SessionContext *state = (struct SessionContext *)data;
  logprint(WARN, "Wayland: Layer surface closed unexpectedly! Disabling session ");
  cleanup_session_wayland(state);
  state->enabled = false;
  interface_data.active_session = NULL;
  dbus_signal_Deactivated(interface_data.bus, state->session_path);
}

static void wayland_handle_pointer_enter(void *data, struct wl_pointer *ptr, uint32_t serial,
                                        struct wl_surface *surface, wl_fixed_t sx, wl_fixed_t sy) {
  struct SessionContext *context = (struct SessionContext *)data;
  logprint(DEBUG, "Wayland pointer entered surface");

  if (interface_data.wl_pointer_constraints && !context->wl_locked_pointer) {
    context->wl_locked_pointer = zwp_pointer_constraints_v1_lock_pointer(
      interface_data.wl_pointer_constraints,
      surface,
      context->wl_pointer,
      NULL,
      ZWP_POINTER_CONSTRAINTS_V1_LIFETIME_PERSISTENT
    );
    zwp_locked_pointer_v1_add_listener(context->wl_locked_pointer, &locked_pointer_listener, context);
  }

  // store initial position for delta calculation
  context->last_pointer_x = sx;
  context->last_pointer_y = sy;
}

static void wayland_handle_pointer_leave(void *data, struct wl_pointer *ptr, uint32_t serial, struct wl_surface *surface) {
  logprint(DEBUG, "Wayland: pointer left surface");
}

static void wayland_handle_pointer_motion(void *data, struct wl_pointer *ptr, uint32_t time, wl_fixed_t sx, wl_fixed_t sy) {
  struct SessionContext *context = (struct SessionContext *)data;
  if (!context->device) return;

  // calculate delta from last position
  wl_fixed_t dx = sx - context->last_pointer_x;
  wl_fixed_t dy = sy - context->last_pointer_y;

  eis_device_pointer_motion(context->device, wl_fixed_to_double(dx), wl_fixed_to_double(dy));

  context->last_pointer_x = sx;
  context->last_pointer_y = sy;
}

static void wayland_handle_pointer_button(void *data, struct wl_pointer *ptr, uint32_t serial, uint32_t time, uint32_t button, uint32_t state) {
  struct SessionContext *context = (struct SessionContext *)data;
  if (!context->device) return;

  eis_device_button_button(context->device, button, (state == WL_POINTER_BUTTON_STATE_PRESSED));
}

static void wayland_handle_pointer_axis(void *data, struct wl_pointer *ptr, uint32_t time, uint32_t axis, wl_fixed_t value) {
  struct SessionContext *context = (struct SessionContext *)data;
  if (!context->device) return;

  double dx = 0.0;
  double dy = 0.0;

  if (axis == WL_POINTER_AXIS_VERTICAL_SCROLL) {
    dy = wl_fixed_to_double(value);
  } else if (axis == WL_POINTER_AXIS_HORIZONTAL_SCROLL) {
    dx = wl_fixed_to_double(value);
  } else {
    return;
  }
  eis_device_scroll_delta(context->device, dx, dy);
}

static void wayland_handle_keyboard_keymap(void *data, struct wl_keyboard *kbd, uint32_t format, int32_t fd, uint32_t size) {
  struct SessionContext *context = (struct SessionContext *)data;
  if (format != WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1) {
    close(fd);
    return;
  }
  logprint(DEBUG, "Wayland: Got keymap (fd: %d, size %u)", fd, size);

  int eis_fd = -1;
  if (context->device) {
    eis_fd = dup(fd);
    if (eis_fd < 0) {
      logprint(ERROR, "Wayland: failed to dup keymap fd: %s", strerror(errno));
    }
  }

  char *map_shm = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
  if (map_shm == MAP_FAILED) {
    logprint(ERROR, "Wayland: mmap failed for keymap: %s", strerror(errno));
    close(fd);
    if (eis_fd >= 0) close(eis_fd);
    return;
  }

  if (context->xkb_keymap) xkb_keymap_unref(context->xkb_keymap);
  if (context->xkb_state) xkb_state_unref(context->xkb_state);

  context->xkb_keymap = xkb_keymap_new_from_string(
    interface_data.xkb_context,
    map_shm,
    XKB_KEYMAP_FORMAT_TEXT_V1,
    XKB_KEYMAP_COMPILE_NO_FLAGS
  );
  munmap(map_shm, size);
  close(fd);

  if (!context->xkb_keymap) {
    logprint(ERROR, "Wayland: failed to create xkb_keymap from string");
    if (eis_fd >= 0) close(eis_fd);
    return;
  }

  context->xkb_state = xkb_state_new(context->xkb_keymap);
  if (!context->xkb_state) {
    logprint(ERROR, "Wayland: failed to create xkb_state");
  }

  if (context->device && eis_fd >= 0) {
    logprint(DEBUG, "EIS: forwarding keymap fd %d", eis_fd);
    struct eis_keymap *keymap = eis_device_new_keymap(context->device, EIS_KEYMAP_TYPE_XKB, eis_fd, size);
    if (keymap) {
      eis_keymap_add(keymap);
      eis_keymap_unref(keymap);
    } else {
      logprint(ERROR, "EIS: failed to create new keymap");
      close(eis_fd);
    }
  } else if (eis_fd >= 0) {
    close(eis_fd);
  }
}

static void wayland_handle_keyboard_enter(void *data, struct wl_keyboard *kbd, uint32_t serial, struct wl_surface *surface, struct wl_array *keys) {
  logprint(DEBUG, "Wayland: keyboard focus acquired");
}

static void wayland_handle_keyboard_leave(void *data, struct wl_keyboard *kbd, uint32_t serial, struct wl_surface *surface) {
  logprint(DEBUG, "Wayland: keyboard focus lost");
}

static void wayland_handle_keyboard_key(void *data, struct wl_keyboard *kbd, uint32_t serial, uint32_t time, uint32_t key, uint32_t state) {
  struct SessionContext *context = (struct SessionContext *)data;
  if (!context->device) return;
  eis_device_keyboard_key(context->device, key, (state == WL_KEYBOARD_KEY_STATE_PRESSED));
}

static void wayland_handle_keyboard_modifiers(void *data, struct wl_keyboard *kbd, uint32_t serial, uint32_t mods_depressed, uint32_t mods_latched, uint32_t mods_locked, uint32_t group) {
  struct SessionContext *context = (struct SessionContext *)data;
  if (!context->device) return;
  if (context->xkb_state) {
    xkb_state_update_mask(context->xkb_state, mods_depressed, mods_latched, mods_locked, 0, 0, group);
  }
  eis_device_keyboard_send_xkb_modifiers(context->device, mods_depressed, mods_latched, mods_locked, group);
}

static void wayland_handle_keyboard_repeat(void *data, struct wl_keyboard *kbd, int32_t, int32_t) {
  // wayland handles repeats by sending multiple .key events
}

static void output_handle_geometry(void *data, struct wl_output *wl_output, int32_t x, int32_t y, int32_t phys_w, int32_t phys_h, int32_t subpixel, const char *make, const char *model, int32_t transform) {
  struct Output *output = (struct Output *)data;
  output->x = x;
  output->y = y;
}

static void output_handle_mode(void * data, struct wl_output *wl_output, uint32_t flags, int32_t width, int32_t height, int32_t refresh) {
  struct Output *output = (struct Output *)data;
  if (flags & WL_OUTPUT_MODE_CURRENT) {
    output->width = width;
    output->height = height;
  }
}

static void output_handle_done(void *data, struct wl_output *wl_output) {
  struct Output *output = (struct Output *)data;
  output->ready = true;
  logprint(DEBUG, "Wayland: output %u is ready (%dx%d @ %d,%d)", output->name, output->width, output->height, output->x, output->y);

  struct SessionContext *iter = output->data->session_list_head;
  while (iter) {
    if (iter->enabled) {
      // invalidate the clients current zone_set_id and notify them
      // the spec says to increment by a "sensible amount"
      iter->zone_set_id += 1;
      dbus_signal_ZonesChanged(output->data->bus, iter->session_path);
    }
    iter = iter->next;
  }
}

static void output_handle_scale(void *data, struct wl_output *wl_output, int32_t factor) {
  // Not needed for this portal
}

/* --- public api functions --- */
int xdpw_input_capture_init(struct xdpw_state *state) {
  int r;
  struct eis *eis_context = NULL;

  wl_list_init(&interface_data.output_list);

  // use the existing bus and display from the main state
  interface_data.bus = state->bus;
  interface_data.wl_display = state->wl_display;

  interface_data.xkb_context = xkb_context_new(XKB_CONTEXT_NO_FLAGS);
  if (!interface_data.xkb_context) {
    logprint(ERROR, "Failed to create xkb_context");
    r = -EIO;
    goto cleanup_wayland;
  }

  interface_data.wl_registry = wl_display_get_registry(interface_data.wl_display);
  wl_registry_add_listener(interface_data.wl_registry, &registry_listener, &interface_data);
  wl_display_roundtrip(interface_data.wl_display);

  // check if we got essential globals
  if ( !interface_data.wl_compositor || !interface_data.wl_layer_shell ||
    !interface_data.wl_seat || !interface_data.wl_pointer_constraints ||
    !interface_data.wl_keyboard_shortcuts_manager ) {
    logprint(ERROR, "Compositor is missing required wayland protocols:");
    if (!interface_data.wl_compositor) logprint(ERROR, "  - wl_compositor is missing");
    if (!interface_data.wl_layer_shell) logprint(ERROR, " - zwlr_layer_shell_v1 is missing (are you on sway/hyprland?)");
    if (!interface_data.wl_seat) logprint(ERROR, "  - wl_seat is missing");
    if (!interface_data.wl_pointer_constraints) logprint(ERROR, " - zwp_pointer_constraints_v1 is missing");
    if (!interface_data.wl_keyboard_shortcuts_manager) logprint(ERROR, "  - zwp_keyboard_shortcuts_inhibit_manager_v1 is missing");
    r = -EPROTONOSUPPORT;
    goto cleanup_wayland;
  }

  eis_context = eis_new(&interface_data);
  if (!eis_context) {
    logprint(ERROR, "Failed to create EIS context");
    r = -ENOMEM;
    goto cleanup_wayland;
  }

  // generate socket_path for eis
  const char *xdg_runtime_dir = getenv("XDG_RUNTIME_DIR");
  if (!xdg_runtime_dir) {
    logprint(ERROR, "XDG_RUNTIME_DIR environment variable is not set. Cannot create socket");
    r = -ENXIO;
    goto cleanup_eis;
  }

  int size_needed = snprintf(NULL, 0, "%s/eis-0", xdg_runtime_dir);
  char *socket_path = (char *)malloc(size_needed + 1);
  if (size_needed < 0 || !socket_path) {
    logprint(ERROR, "Failed to allocate socket path");
    r = -ENOMEM;
    goto cleanup_eis;
  }
  snprintf(socket_path, size_needed + 1, "%s/eis-0", xdg_runtime_dir);

  r = eis_setup_backend_socket(eis_context, socket_path);
  if (r < 0) {
    logprint(ERROR, "Failed to create EIS socket: %s", strerror(-r));
    free(socket_path);
    goto cleanup_eis;
  }
  logprint(INFO, "Eis server listening at: %s", socket_path);
  free(socket_path);

  int eis_fd = eis_get_fd(eis_context);
  if (eis_fd < 0) {
    logprint(ERROR, "Failed to get EIS fd, got: %d", eis_fd);
    r = EINVAL;
    goto cleanup_eis;
  }

  r = sd_bus_add_object_vtable(
    interface_data.bus,
    NULL,
    OBJECT_PATH_NAME,
    INPUTCAPTURE_INTERFACE_NAME,
    input_capture_vtable,
    &interface_data
  );

  if (r < 0) {
    logprint(ERROR, "Failed to add D-BUS vtable: %s", strerror(-r));
    goto cleanup_eis;
  }

	interface_data.eis_context = eis_context;
  state->input_capture.libei_fd = eis_fd;

  return 0;
cleanup_eis:
  eis_unref(eis_context);
cleanup_wayland:
  if (interface_data.xkb_context) xkb_context_unref(interface_data.xkb_context);
  if (interface_data.wl_seat) wl_seat_destroy(interface_data.wl_seat);
  if (interface_data.wl_pointer_constraints) zwp_pointer_constraints_v1_destroy(interface_data.wl_pointer_constraints);
  if (interface_data.wl_keyboard_shortcuts_manager) zwp_keyboard_shortcuts_inhibit_manager_v1_destroy(interface_data.wl_keyboard_shortcuts_manager);
  if (interface_data.wl_layer_shell) zwlr_layer_shell_v1_destroy(interface_data.wl_layer_shell);
  if (interface_data.wl_compositor) wl_compositor_destroy(interface_data.wl_compositor);
  if (interface_data.wl_registry) wl_registry_destroy(interface_data.wl_registry);

  return r;
}

void xdpw_input_capture_destroy(void) {
  if (!interface_data.bus) return;

  logprint(DEBUG, "InputCapture portal shutting down");

  while (interface_data.session_list_head) {
    struct SessionContext *context = interface_data.session_list_head;
    interface_data.session_list_head = context->next;

    if (context->enabled) {
      cleanup_session_wayland(context);
    }
    sd_bus_slot_unref(context->slot);
    sc_free(context);
  }

  struct Output *iter, *tmp;
  wl_list_for_each_safe(iter, tmp, &interface_data.output_list, link) {
    wl_list_remove(&iter->link);
    wl_output_destroy(iter->wl_output);
    free(iter);
  }

  if (interface_data.eis_context) eis_unref(interface_data.eis_context);
  if (interface_data.xkb_context) xkb_context_unref(interface_data.xkb_context);
  if (interface_data.wl_seat) wl_seat_destroy(interface_data.wl_seat);
  if (interface_data.wl_pointer_constraints) zwp_pointer_constraints_v1_destroy(interface_data.wl_pointer_constraints);
  if (interface_data.wl_keyboard_shortcuts_manager) zwp_keyboard_shortcuts_inhibit_manager_v1_destroy(interface_data.wl_keyboard_shortcuts_manager);
  if (interface_data.wl_layer_shell) zwlr_layer_shell_v1_destroy(interface_data.wl_layer_shell);
  if (interface_data.wl_compositor) wl_compositor_destroy(interface_data.wl_compositor);
  if (interface_data.wl_registry) wl_registry_destroy(interface_data.wl_registry);
}

void xdpw_input_capture_dispatch_eis(struct xdpw_state *state) {
  struct eis *eis = interface_data.eis_context;
  if (!eis) return;

  eis_dispatch(eis);
  struct eis_event *event;
  while ((event = eis_get_event(eis))) {
    eis_helper_handle_event(event);
    eis_event_unref(event);
  }
}
