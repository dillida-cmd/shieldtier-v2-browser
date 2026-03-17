#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void shieldtier_mac_init(void);
void* shieldtier_mac_get_content_view(void);
void shieldtier_mac_get_content_bounds(int* width, int* height);
void shieldtier_mac_set_view_frame(void* view, int css_x, int css_y, int w, int h);
void shieldtier_mac_set_view_hidden(void* view, bool hidden);
void shieldtier_mac_set_view_autoresizing(void* view);
void shieldtier_mac_set_view_fixed(void* view);

/// Create a clipping container NSView as a child of the window's content view.
/// The content browser's NSView will be placed inside this container.
/// Returns the container view (caller uses it as parent for SetAsChild).
void* shieldtier_mac_create_content_container(void);

/// Set the content container's frame (CSS top-left origin).
void shieldtier_mac_set_container_frame(void* container, int x, int y, int w, int h);

/// Show a native NSOpenPanel file dialog. Returns strdup'd path or nullptr if cancelled.
/// file_types is a comma-separated list of extensions (e.g. "eml,msg,txt"), or empty for all files.
/// Caller must free the returned string with shieldtier_mac_free_string().
char* shieldtier_mac_open_file_dialog(const char* title, const char* file_types);

/// Show a native NSSavePanel. Returns strdup'd chosen path or nullptr if cancelled.
/// default_name is the suggested filename (e.g. "report.html").
/// extension is the required file extension (e.g. "html"), or empty for any.
char* shieldtier_mac_save_file_dialog(const char* title, const char* default_name, const char* extension);

void shieldtier_mac_free_string(char* str);

#ifdef __cplusplus
}
#endif
