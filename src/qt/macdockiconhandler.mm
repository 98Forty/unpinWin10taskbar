#include "macdockiconhandler.h"

#include <QImageWriter>
#include <QMenu>
#include <QTemporaryFile>
#include <QWidget>

#undef slots
#include <Cocoa/Cocoa.h>

#if QT_VERSION < 0x050000
extern void qt_mac_set_dock_menu(QMenu *);
#endif

@interface DockIconClickEventHandler : NSObject
{
    MacDockIconHandler* dockIconHandler;
}

@end

@implementation DockIconClickEventHandler

- (id)initWithDockIc