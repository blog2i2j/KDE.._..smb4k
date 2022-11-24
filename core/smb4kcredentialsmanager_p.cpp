/*
    Private classes for the credentials manager of Smb4K

    SPDX-FileCopyrightText: 2022 Alexander Reinholdt <alexander.reinholdt@kdemail.net>
    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "smb4kcredentialsmanager_p.h"

// application specific includes
#include "smb4khost.h"
#include "smb4kshare.h"

// KDE includes
#include <KLocalizedString>

using namespace Smb4KGlobal;

Smb4KPasswordDialog::Smb4KPasswordDialog(const NetworkItemPtr &networkItem, const QMap<QString, QString> &knownLogins, QWidget *parent)
    : KPasswordDialog(parent, KPasswordDialog::ShowUsernameLine)
{
    m_item = networkItem;

    switch (m_item->type()) {
    case Network: {
        setUsername(m_item->url().userName());
        setPassword(m_item->url().password());
        setPrompt(i18n("Please enter a username and password for the default login."));
        break;
    }
    case Host: {
        HostPtr host = m_item.staticCast<Smb4KHost>();

        if (host) {
            setUsername(host->userName());
            setPassword(host->password());
            setPrompt(i18n("Please enter a username and a password for the host <b>%1</b>.", host->hostName()));
        }

        break;
    }
    case Share: {
        SharePtr share = m_item.staticCast<Smb4KShare>();

        if (share) {
            // Enter authentication information into the dialog
            if (!knownLogins.isEmpty()) {
                setKnownLogins(knownLogins);
            } else {
                setUsername(share->userName());
                setPassword(share->password());
            }

            if (!share->isHomesShare()) {
                setPrompt(i18n("Please enter a username and a password for the share <b>%1</b>.", share->displayString()));
            } else {
                setPrompt(i18n("Please enter a username and a password for the share <b>%1</b>.", share->displayString(true)));
            }
        }

        break;
    }
    default: {
        break;
    }
    }

    connect(this, SIGNAL(gotUsernameAndPassword(QString, QString, bool)), SLOT(slotGotUsernameAndPassword(QString, QString, bool)));
}

Smb4KPasswordDialog::~Smb4KPasswordDialog()
{
}

void Smb4KPasswordDialog::slotGotUsernameAndPassword(const QString &user, const QString &pass, bool /*keep*/)
{
    QUrl url = m_item->url();
    url.setUserName(user);
    url.setPassword(pass);
    m_item->setUrl(url);
}
