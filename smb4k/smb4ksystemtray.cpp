/*
    smb4ksystemtray  -  This is the system tray window class of Smb4K.

    SPDX-FileCopyrightText: 2007-2022 Alexander Reinholdt <alexander.reinholdt@kdemail.net>
    SPDX-License-Identifier: GPL-2.0-or-later
*/

// application specific includes
#include "smb4ksystemtray.h"
#include "core/smb4kclient.h"
#include "core/smb4kglobal.h"
#include "core/smb4kmounter.h"
#include "core/smb4kshare.h"
#include "core/smb4kworkgroup.h"
#include "smb4kbookmarkmenu.h"
#include "smb4kprofilesmenu.h"
#include "smb4ksharesmenu.h"

// Qt includes
#include <QDebug>
#include <QMenu>
#include <QPointer>

// KDE specific includes
#include <KConfigWidgets/KConfigDialog>
#include <KConfigWidgets/KStandardAction>
#include <KCoreAddons/KAboutData>
#include <KCoreAddons/KPluginFactory>
#include <KCoreAddons/KPluginLoader>
#include <KI18n/KLocalizedString>
#include <KIconThemes/KIconLoader>
#include <KWidgetsAddons/KMessageBox>
#include <KXmlGui/KActionCollection>

using namespace Smb4KGlobal;

Smb4KSystemTray::Smb4KSystemTray(QWidget *parent)
    : KStatusNotifierItem(QStringLiteral("smb4k_systemtray"), parent)
{
    //
    // Set the icon for the system tray
    //
    QString iconName;

    if (KIconLoader::global()->hasIcon(QStringLiteral("network-workgroup-symbolic"))) {
        iconName = QStringLiteral("network-workgroup-symbolic");
    } else {
        iconName = QStringLiteral("network-workgroup");
    }

    setIconByName(iconName);

    //
    // Set the tooltip text
    //
    setToolTip(iconName, i18n("Smb4K"), KAboutData::applicationData().shortDescription());

    //
    // Set the status of the icon. By default, it is active. It will become passive,
    // if the scanner could not find something and no shares were mounted.
    //
    setStatus(Active);

    //
    // Set the category
    //
    setCategory(ApplicationStatus);

    //
    // Add the actions to the action collection
    //
    QAction *mountAction = new QAction(KDE::icon(QStringLiteral("view-form"), QStringList(QStringLiteral("emblem-mounted"))), i18n("&Open Mount Dialog"), this);
    connect(mountAction, SIGNAL(triggered(bool)), SLOT(slotMountDialog()));

    addAction(QStringLiteral("shares_menu"), new Smb4KSharesMenu(this));
    addAction(QStringLiteral("bookmarks_menu"), new Smb4KBookmarkMenu(Smb4KBookmarkMenu::SystemTray, this));
    addAction(QStringLiteral("profiles_menu"), new Smb4KProfilesMenu(this));
    addAction(QStringLiteral("mount_action"), mountAction);
    addAction(QStringLiteral("config_action"), KStandardAction::preferences(this, SLOT(slotConfigDialog()), this));

    //
    // Set up the menu
    //
    contextMenu()->addAction(action(QStringLiteral("shares_menu")));
    contextMenu()->addAction(action(QStringLiteral("bookmarks_menu")));
    contextMenu()->addAction(action(QStringLiteral("profiles_menu")));
    contextMenu()->addSeparator();
    contextMenu()->addAction(action(QStringLiteral("mount_action")));
    contextMenu()->addAction(action(QStringLiteral("config_action")));

    //
    // Connections
    //
    connect(Smb4KMounter::self(), SIGNAL(mountedSharesListChanged()), SLOT(slotSetStatus()));
    connect(Smb4KClient::self(), SIGNAL(workgroups()), SLOT(slotSetStatus()));
}

Smb4KSystemTray::~Smb4KSystemTray()
{
}

void Smb4KSystemTray::loadSettings()
{
    //
    // Adjust the bookmarks menu
    //
    Smb4KBookmarkMenu *bookmarkMenu = static_cast<Smb4KBookmarkMenu *>(action(QStringLiteral("bookmarks_menu")));

    if (bookmarkMenu) {
        bookmarkMenu->refreshMenu();
    }

    //
    // Adjust the shares menu
    //
    Smb4KSharesMenu *sharesMenu = static_cast<Smb4KSharesMenu *>(action(QStringLiteral("shares_menu")));

    if (sharesMenu) {
        sharesMenu->refreshMenu();
    }

    //
    // Adjust the profiles menu
    //
    Smb4KProfilesMenu *profilesMenu = static_cast<Smb4KProfilesMenu *>(action(QStringLiteral("profiles_menu")));

    if (profilesMenu) {
        profilesMenu->refreshMenu();
    }
}

/////////////////////////////////////////////////////////////////////////////
// SLOT IMPLEMENTATIONS
/////////////////////////////////////////////////////////////////////////////

void Smb4KSystemTray::slotMountDialog()
{
    Smb4KMounter::self()->openMountDialog();
}

void Smb4KSystemTray::slotConfigDialog()
{
    //
    // Check if the configuration dialog exists and try to show it.
    //
    if (KConfigDialog::showDialog(QStringLiteral("ConfigDialog"))) {
        return;
    }

    //
    // If the dialog does not exist, load and show it:
    //
    KPluginLoader loader(QStringLiteral("smb4kconfigdialog"));
    KPluginFactory *configFactory = loader.factory();

    if (configFactory) {
        QPointer<KConfigDialog> dlg = nullptr;

        if (associatedWidget()) {
            dlg = configFactory->create<KConfigDialog>(associatedWidget());
        } else {
            dlg = configFactory->create<KConfigDialog>(contextMenu());
        }

        if (dlg) {
            connect(dlg, SIGNAL(settingsChanged(QString)), this, SLOT(slotSettingsChanged(QString)), Qt::UniqueConnection);
            connect(dlg, SIGNAL(settingsChanged(QString)), this, SIGNAL(settingsChanged(QString)), Qt::UniqueConnection);
            dlg->show();
        }
    } else {
        KMessageBox::error(nullptr, loader.errorString());
        return;
    }
}

void Smb4KSystemTray::slotSettingsChanged(const QString &)
{
    //
    // Execute loadSettings()
    //
    loadSettings();
}

void Smb4KSystemTray::slotSetStatus()
{
    //
    // Set the status of the system tray icon
    //
    if (!mountedSharesList().isEmpty() || !workgroupsList().isEmpty()) {
        setStatus(KStatusNotifierItem::Active);
    } else {
        setStatus(KStatusNotifierItem::Passive);
    }
}
