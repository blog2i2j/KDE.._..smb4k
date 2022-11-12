/*
    Private classes for the credentials manager of Smb4K

    SPDX-FileCopyrightText: 2022 Alexander Reinholdt <alexander.reinholdt@kdemail.net>
    SPDX-License-Identifier: GPL-2.0-or-later
*/

#ifndef SMB4KCREDENTIALSMANAGER_P_H
#define SMB4KCREDENTIALSMANAGER_P_H

// application specific includes
#include "smb4kglobal.h"
#include "smb4kcredentialsmanager.h"

// KDE includes
#include <KWidgetsAddons/KPasswordDialog>

// QtKeychain include
#include <qt5keychain/keychain.h>

class Smb4KPasswordDialog : public KPasswordDialog
{
    Q_OBJECT

public:
    Smb4KPasswordDialog(const NetworkItemPtr &networkItem, const QMap<QString, QString> &knownLogins, QWidget *parent = nullptr);
    virtual ~Smb4KPasswordDialog();

protected Q_SLOTS:
    void slotGotUsernameAndPassword(const QString &user, const QString &pass, bool keep);

private:
    NetworkItemPtr m_item;
};

class Smb4KCredentialsManagerStatic
{
public:
    Smb4KCredentialsManager instance;
};

class Smb4KCredentialsManagerPrivate
{
public:
    QKeychain::ReadPasswordJob *readPasswordJob;
    QKeychain::WritePasswordJob *writePasswordJob;
    QKeychain::DeletePasswordJob *deletePasswordJob;
};

#endif
