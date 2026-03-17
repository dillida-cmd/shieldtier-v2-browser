#import <Cocoa/Cocoa.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

#include "app/app_mac.h"
#include "include/cef_app.h"
#include "include/cef_application_mac.h"

// NSApplication subclass implementing CefAppProtocol.
// Required by CEF on macOS for correct event loop integration.
@interface ShieldTierApplication : NSApplication <CefAppProtocol> {
    BOOL handlingSendEvent_;
}
@end

@implementation ShieldTierApplication

- (BOOL)isHandlingSendEvent {
    return handlingSendEvent_;
}

- (void)setHandlingSendEvent:(BOOL)handlingSendEvent {
    handlingSendEvent_ = handlingSendEvent;
}

- (void)sendEvent:(NSEvent*)event {
    CefScopedSendingEvent sendingEventScoper;
    [super sendEvent:event];
}

@end

@interface ShieldTierWindowDelegate : NSObject <NSWindowDelegate>
@end

@implementation ShieldTierWindowDelegate

- (void)windowWillClose:(NSNotification*)notification {
    CefQuitMessageLoop();
}

@end

static NSWindow* g_main_window = nil;
static ShieldTierWindowDelegate* g_window_delegate = nil;

void shieldtier_mac_init(void) {
    [ShieldTierApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];

    NSMenu* mainMenu = [[NSMenu alloc] init];
    NSMenuItem* appMenuItem = [[NSMenuItem alloc] init];
    [mainMenu addItem:appMenuItem];

    NSMenu* appMenu = [[NSMenu alloc] initWithTitle:@"ShieldTier"];
    [appMenuItem setSubmenu:appMenu];
    [appMenu addItemWithTitle:@"Quit ShieldTier"
                       action:@selector(terminate:)
                keyEquivalent:@"q"];
    [NSApp setMainMenu:mainMenu];

    NSRect frame = NSMakeRect(200, 200, 1280, 800);
    NSUInteger styleMask = NSWindowStyleMaskTitled |
                           NSWindowStyleMaskClosable |
                           NSWindowStyleMaskMiniaturizable |
                           NSWindowStyleMaskResizable;

    g_main_window = [[NSWindow alloc] initWithContentRect:frame
                                                styleMask:styleMask
                                                  backing:NSBackingStoreBuffered
                                                    defer:NO];
    [g_main_window setTitle:@"ShieldTier"];
    [g_main_window setMinSize:NSMakeSize(800, 600)];

    g_window_delegate = [[ShieldTierWindowDelegate alloc] init];
    [g_main_window setDelegate:g_window_delegate];

    [g_main_window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}

void* shieldtier_mac_get_content_view(void) {
    if (g_main_window) {
        return (__bridge void*)[g_main_window contentView];
    }
    return nullptr;
}

void shieldtier_mac_get_content_bounds(int* width, int* height) {
    if (g_main_window && width && height) {
        NSRect bounds = [[g_main_window contentView] bounds];
        *width = (int)bounds.size.width;
        *height = (int)bounds.size.height;
    }
}

void shieldtier_mac_set_view_frame(void* view, int css_x, int css_y, int w, int h) {
    if (!view || !g_main_window) return;
    NSView* ns_view = (__bridge NSView*)view;
    NSView* parent = [ns_view superview];
    if (!parent) return;

    // Account for Retina scaling: getBoundingClientRect returns CSS pixels,
    // but NSView frames are in points. On Retina, CSS pixels == points (CEF
    // handles the 2x internally), so no scaling needed. But ensure the parent
    // clips children to prevent overflow.
    if (parent.layer && !parent.layer.masksToBounds) {
        parent.layer.masksToBounds = YES;
    }

    CGFloat parent_height = parent.bounds.size.height;
    // CSS top-left origin -> NSView bottom-left origin
    CGFloat ns_y = parent_height - css_y - h;
    [ns_view setFrame:NSMakeRect(css_x, ns_y, w, h)];
}

void shieldtier_mac_set_view_hidden(void* view, bool hidden) {
    if (!view) return;
    NSView* ns_view = (__bridge NSView*)view;
    [ns_view setHidden:hidden ? YES : NO];
}

void shieldtier_mac_set_view_autoresizing(void* view) {
    if (!view) return;
    NSView* ns_view = (__bridge NSView*)view;
    [ns_view setAutoresizingMask:NSViewWidthSizable | NSViewHeightSizable];
    // Also snap to current parent bounds so it fills the content view now
    NSView* parent = [ns_view superview];
    if (parent) {
        [ns_view setFrame:parent.bounds];
    }
}

void shieldtier_mac_set_view_fixed(void* view) {
    if (!view) return;
    NSView* ns_view = (__bridge NSView*)view;
    // Disable autoresizing — this view's frame is managed manually via set_view_frame
    [ns_view setAutoresizingMask:0];
}

void* shieldtier_mac_create_content_container(void) {
    if (!g_main_window) return nullptr;
    NSView* parent = [g_main_window contentView];
    // Create a container view that clips its children (the content browser)
    NSView* container = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, 1, 1)];
    container.wantsLayer = YES;
    container.layer.masksToBounds = YES;
    [container setAutoresizingMask:0];  // manually positioned
    [parent addSubview:container];
    return (__bridge void*)container;
}

void shieldtier_mac_set_container_frame(void* container, int css_x, int css_y, int w, int h) {
    if (!container || !g_main_window) return;
    NSView* ns_container = (__bridge NSView*)container;
    NSView* parent = [ns_container superview];
    if (!parent) return;
    CGFloat parent_height = parent.bounds.size.height;
    CGFloat ns_y = parent_height - css_y - h;
    [ns_container setFrame:NSMakeRect(css_x, ns_y, w, h)];

    // Also resize the content browser's NSView (first subview) to fill the container
    for (NSView* child in ns_container.subviews) {
        [child setFrame:NSMakeRect(0, 0, w, h)];
        break;
    }
}

char* shieldtier_mac_open_file_dialog(const char* title, const char* file_types) {
    __block char* result = nullptr;

    // NSOpenPanel must run on the main thread
    void (^block)(void) = ^{
        NSOpenPanel* panel = [NSOpenPanel openPanel];
        [panel setCanChooseFiles:YES];
        [panel setCanChooseDirectories:NO];
        [panel setAllowsMultipleSelection:NO];
        if (title) {
            [panel setTitle:[NSString stringWithUTF8String:title]];
        }

        // Parse comma-separated file extensions into UTTypes
        if (file_types && file_types[0] != '\0') {
            NSString* typesStr = [NSString stringWithUTF8String:file_types];
            NSArray<NSString*>* exts = [typesStr componentsSeparatedByString:@","];
            NSMutableArray<UTType*>* types = [NSMutableArray array];
            for (NSString* ext in exts) {
                NSString* trimmed = [ext stringByTrimmingCharactersInSet:
                    [NSCharacterSet whitespaceCharacterSet]];
                if (trimmed.length > 0) {
                    UTType* type = [UTType typeWithFilenameExtension:trimmed];
                    if (type) {
                        [types addObject:type];
                    }
                }
            }
            if (types.count > 0) {
                [panel setAllowedContentTypes:types];
            }
        }

        NSModalResponse response = [panel runModal];
        if (response == NSModalResponseOK) {
            NSURL* url = [[panel URLs] firstObject];
            if (url) {
                const char* path = [[url path] UTF8String];
                if (path) {
                    result = strdup(path);
                }
            }
        }
    };

    if ([NSThread isMainThread]) {
        block();
    } else {
        dispatch_sync(dispatch_get_main_queue(), block);
    }

    return result;
}

char* shieldtier_mac_save_file_dialog(const char* title, const char* default_name, const char* extension) {
    __block char* result = nullptr;

    void (^block)(void) = ^{
        NSSavePanel* panel = [NSSavePanel savePanel];
        if (title) {
            [panel setTitle:[NSString stringWithUTF8String:title]];
        }
        if (default_name) {
            [panel setNameFieldStringValue:[NSString stringWithUTF8String:default_name]];
        }
        if (extension && extension[0] != '\0') {
            UTType* type = [UTType typeWithFilenameExtension:
                [NSString stringWithUTF8String:extension]];
            if (type) {
                [panel setAllowedContentTypes:@[type]];
            }
        }
        [panel setCanCreateDirectories:YES];

        NSModalResponse response = [panel runModal];
        if (response == NSModalResponseOK) {
            NSURL* url = [panel URL];
            if (url) {
                const char* path = [[url path] UTF8String];
                if (path) {
                    result = strdup(path);
                }
            }
        }
    };

    if ([NSThread isMainThread]) {
        block();
    } else {
        dispatch_sync(dispatch_get_main_queue(), block);
    }

    return result;
}

void shieldtier_mac_free_string(char* str) {
    free(str);
}
