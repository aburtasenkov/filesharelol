#pragma once

#include "xdpw.h"

#include <systemd/sd-bus.h>
#include <libei-1.0/libeis.h>
#include <wayland-client.h>
#include <wayland-util.h>
#include <xkbcommon/xkbcommon.h>

#include "wlr-layer-shell-unstable-v1-client.h"
#include "pointer-constraints-unstable-v1-client.h"
#include "keyboard-shortcuts-inhibit-unstable-v1-client.h"

#include <stdbool.h>

struct Barrier {
  uint32_t id;
  int32_t x1, y1, x2, y2;
  struct Barrier *next;
};

struct Output {
  struct wl_list link;
  struct InputCaptureData *data;
  uint32_t name;
  struct wl_output *wl_output;
  int32_t x, y, width, height;
  bool ready;
};

struct InputCaptureData {
  uint32_t capabilities;
  uint32_t version;
  sd_bus *bus;
  struct eis *eis_context;
  struct SessionContext *session_list_head; // pointer pointing to head of a single sided linked list

  struct wl_display *wl_display;
  struct wl_registry *wl_registry;
  struct wl_compositor *wl_compositor;
  struct zwlr_layer_shell_v1 *wl_layer_shell;

  struct wl_seat* wl_seat;
  struct zwp_pointer_constraints_v1 *wl_pointer_constraints;
  struct zwp_keyboard_shortcuts_inhibit_manager_v1 *wl_keyboard_shortcuts_manager;
  
  struct xkb_context *xkb_context;  // global XKB context

  struct SessionContext *active_session;  // pointer to the currently capturing session

  struct wl_list output_list;
};

struct SessionContext {
  sd_bus_slot *slot;
  char *session_path;
  char *parent_window;
  char *handle_token;
  char *session_handle_token;
  uint32_t capabilities;
  struct SessionContext *next;  // pointer to next SessionContext object
  bool enabled;
  struct eis_device *device;
  
  uint32_t zone_set_id;
  struct Barrier *barriers; // Linked list of active barriers

  struct wl_surface *wl_surface;
  struct zwlr_layer_surface_v1 *wl_layer_surface; 

  struct wl_pointer *wl_pointer;
  struct wl_keyboard *wl_keyboard;
  struct zwp_locked_pointer_v1 *wl_locked_pointer;
  struct zwp_keyboard_shortcuts_inhibitor_v1 *wl_keyboard_inhibitor;

  // for manual pointer delta calculation
  wl_fixed_t last_pointer_x;
  wl_fixed_t last_pointer_y;

  // for keyboard state
  struct xkb_keymap *xkb_keymap;
  struct xkb_state *xkb_state;
};

int xdpw_input_capture_init(struct xdpw_state *);