#import <Cocoa/Cocoa.h>
#include "_cgo_export.h"

@interface PulseTrayTarget : NSObject
@end

@implementation PulseTrayTarget
- (void)showAll:(id)sender {
    PulseDarwinTrayAction(1);
}

- (void)hidePulse:(id)sender {
    PulseDarwinTrayAction(2);
}

- (void)quitPulse:(id)sender {
    PulseDarwinTrayAction(3);
}
@end

static NSStatusItem *pulseStatusItem = nil;
static PulseTrayTarget *pulseTrayTarget = nil;

static void PulseCreateTray(void) {
    if (pulseStatusItem != nil) {
        return;
    }

    pulseTrayTarget = [PulseTrayTarget new];
    pulseStatusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSSquareStatusItemLength];
    if (pulseStatusItem.button != nil) {
        pulseStatusItem.button.title = @"P";
        pulseStatusItem.button.toolTip = @"Pulse";
    }

    NSMenu *menu = [[NSMenu alloc] initWithTitle:@"Pulse"];
    NSMenuItem *titleItem = [[NSMenuItem alloc] initWithTitle:@"Options" action:nil keyEquivalent:@""];
    [titleItem setEnabled:NO];
    [menu addItem:titleItem];
    [menu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *showItem = [[NSMenuItem alloc] initWithTitle:@"Show All Windows" action:@selector(showAll:) keyEquivalent:@""];
    [showItem setTarget:pulseTrayTarget];
    [menu addItem:showItem];

    NSMenuItem *hideItem = [[NSMenuItem alloc] initWithTitle:@"Hide" action:@selector(hidePulse:) keyEquivalent:@""];
    [hideItem setTarget:pulseTrayTarget];
    [menu addItem:hideItem];

    [menu addItem:[NSMenuItem separatorItem]];
    NSMenuItem *quitItem = [[NSMenuItem alloc] initWithTitle:@"Quit" action:@selector(quitPulse:) keyEquivalent:@""];
    [quitItem setTarget:pulseTrayTarget];
    [menu addItem:quitItem];

    pulseStatusItem.menu = menu;
}

void PulseInstallDarwinTray(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        PulseCreateTray();
    });
}

void PulseRemoveDarwinTray(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (pulseStatusItem != nil) {
            [[NSStatusBar systemStatusBar] removeStatusItem:pulseStatusItem];
            pulseStatusItem = nil;
        }
        pulseTrayTarget = nil;
    });
}
