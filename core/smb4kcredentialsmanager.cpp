/*
    This class provides the credentials manager used by Smb4K

    SPDX-FileCopyrightText: 2022 Alexander Reinholdt <alexander.reinholdt@kdemail.net>
    SPDX-License-Identifier: GPL-2.0-or-later
*/

// applications specific includes
#include "smb4kcredentialsmanager.h"
#include "smb4kcredentialsmanager_p.h"
#include "smb4kglobal.h"
#include "smb4khomesshareshandler.h"
#include "smb4kshare.h"

// Qt includes
#include <QApplication>
#include <QDebug>
#include <QEventLoop>
#include <QPointer>

// Includes for importing old credentials
#include "smb4ksettings.h"
#include <KConfigCore/KConfigGroup>
#include <KI18n/KLocalizedString>
#include <KWallet/KWallet>
#include <KWidgetsAddons/KGuiItem>
#include <KWidgetsAddons/KMessageBox>
#include <KWidgetsAddons/kwidgetsaddons_version.h>
#include <QStandardPaths>

using namespace Smb4KGlobal;

Q_GLOBAL_STATIC(Smb4KCredentialsManagerStatic, p);

Smb4KCredentialsManager::Smb4KCredentialsManager(QObject *parent)
    : QObject(parent)
    , d(new Smb4KCredentialsManagerPrivate)
{
    d->readPasswordJob = new QKeychain::ReadPasswordJob(QStringLiteral("org.kde.smb4k"));
    d->readPasswordJob->setAutoDelete(false);

    d->writePasswordJob = new QKeychain::WritePasswordJob(QStringLiteral("org.kde.smb4k"));
    d->writePasswordJob->setAutoDelete(false);

    d->deletePasswordJob = new QKeychain::DeletePasswordJob(QStringLiteral("org.kde.smb4k"));
    d->deletePasswordJob->setAutoDelete(false);
}

Smb4KCredentialsManager::~Smb4KCredentialsManager()
{
}

Smb4KCredentialsManager *Smb4KCredentialsManager::self()
{
    return &p->instance;
}

bool Smb4KCredentialsManager::readLoginCredentials(const NetworkItemPtr &networkItem)
{
    Q_ASSERT(networkItem);
    bool success = false;

    // For backward compatibility. Remove in the future again.
    // FIXME: Handle return value!?
    migrate();

    if (networkItem) {
        QString userInfo(QStringLiteral("guest"));

        switch (networkItem->type()) {
        case Network: {
            // The url should only contain "smb://"...
            QString key = networkItem->url().toString(QUrl::RemoveUserInfo | QUrl::RemovePort);
            success = (read(key, &userInfo) == QKeychain::NoError);
            break;
        }
        case Host: {
            QString key = networkItem->url().toString(QUrl::RemoveUserInfo | QUrl::RemovePort);

            int returnValue = read(key, &userInfo);

            if (returnValue == QKeychain::EntryNotFound) {
                key = QStringLiteral("smb://");
                returnValue = read(key, &userInfo);
            }

            success = (returnValue == QKeychain::NoError);

            break;
        }
        case Share: {
            SharePtr share = networkItem.staticCast<Smb4KShare>();
            QString key;

            if (!share->isHomesShare()) {
                key = share->url().toString(QUrl::RemoveUserInfo | QUrl::RemovePort);
            } else {
                key = share->homeUrl().toString(QUrl::RemoveUserInfo | QUrl::RemovePort);
            }

            int returnValue = read(key, &userInfo);

            if (returnValue == QKeychain::EntryNotFound) {
                key = share->url().adjusted(QUrl::RemovePath | QUrl::StripTrailingSlash).toString(QUrl::RemoveUserInfo | QUrl::RemovePort);

                returnValue = read(key, &userInfo);

                if (returnValue == QKeychain::EntryNotFound) {
                    key = QStringLiteral("smb://");
                    returnValue = read(key, &userInfo);
                }
            }

            success = (returnValue == QKeychain::NoError);

            break;
        }
        default: {
            qDebug() << "No credentials for this type of network item";
            break;
        }
        }

        QUrl url = networkItem->url();
        url.setUserInfo(userInfo);
        networkItem->setUrl(url);
    }

    return success;
}

bool Smb4KCredentialsManager::writeLoginCredentials(const NetworkItemPtr &networkItem)
{
    Q_ASSERT(networkItem);
    bool success = false;

    if (networkItem) {
        switch (networkItem->type()) {
        case Host: {
            QString key = networkItem->url().toString(QUrl::RemoveUserInfo | QUrl::RemovePort);
            success = (write(key, networkItem->url().userInfo()) == QKeychain::NoError);
            break;
        }
        case Share: {
            SharePtr share = networkItem.staticCast<Smb4KShare>();
            QString key;

            if (!share->isHomesShare()) {
                key = share->url().toString(QUrl::RemoveUserInfo | QUrl::RemovePort);
            } else {
                key = share->homeUrl().toString(QUrl::RemoveUserInfo | QUrl::RemovePort);
            }
            success = (write(key, share->url().userInfo()) == QKeychain::NoError);
            break;
        }
        default: {
            break;
        }
        }
    }

    return success;
}

bool Smb4KCredentialsManager::writeDefaultLoginCredentials(const QString &credentials)
{
    return (write(QStringLiteral("smb://"), credentials) == QKeychain::NoError);
}

bool Smb4KCredentialsManager::hasDefaultCredentials() const
{
    QString key = QStringLiteral("smb://");
    QString credentials;

    if (read(key, &credentials) == QKeychain::NoError) {
        return true;
    }

    return false;
}

bool Smb4KCredentialsManager::showPasswordDialog(const NetworkItemPtr &networkItem)
{
    Q_ASSERT(networkItem);

    // FIXME: Do not harass the user by dialogs if he/she already denied access to
    // the secure storage or the secure storage did not open due to another reason.

    bool success = false;

    if (networkItem) {
        QMap<QString, QString> knownLogins;

        switch (networkItem->type()) {
        case Share: {
            SharePtr share = networkItem.staticCast<Smb4KShare>();

            if (share->isHomesShare()) {
                QStringList usersList = Smb4KHomesSharesHandler::self()->homesUsers(share);

                for (const QString &user : qAsConst(usersList)) {
                    SharePtr tempShare = SharePtr(new Smb4KShare(*share.data()));
                    tempShare->setUserName(user);

                    readLoginCredentials(tempShare);
                    knownLogins.insert(tempShare->userName(), tempShare->password());

                    tempShare.clear();
                }
            } else {
                readLoginCredentials(networkItem);
            }
            break;
        }
        default: {
            readLoginCredentials(networkItem);
            break;
        }
        }

        QPointer<Smb4KPasswordDialog> dlg = new Smb4KPasswordDialog(networkItem, knownLogins, QApplication::activeWindow());

        if (dlg->exec() == Smb4KPasswordDialog::Accepted) {
            success = writeLoginCredentials(networkItem);
        }

        delete dlg;
    }

    return success;
}

int Smb4KCredentialsManager::read(const QString &key, QString *credentials) const
{
    int returnValue = QKeychain::NoError;

    QEventLoop loop;
    d->readPasswordJob->setKey(key);

    QObject::connect(d->readPasswordJob, &QKeychain::ReadPasswordJob::finished, [&]() {
        if (d->readPasswordJob->error()) {
            qDebug() << "Read error:" << d->readPasswordJob->errorString();
            returnValue = d->readPasswordJob->error();
        } else {
            *credentials = d->readPasswordJob->textData();
        }

        loop.exit(d->readPasswordJob->error());
    });

    d->readPasswordJob->start();

    loop.exec();

    return returnValue;
}

int Smb4KCredentialsManager::write(const QString &key, const QString &credentials) const
{
    int returnValue = QKeychain::NoError;
    QEventLoop loop;

    d->writePasswordJob->setKey(key);

    QObject::connect(d->writePasswordJob, &QKeychain::WritePasswordJob::finished, [&]() {
        if (d->writePasswordJob->error()) {
            qDebug() << "Write error:" << d->writePasswordJob->errorString();
            returnValue = d->readPasswordJob->error();
        }

        loop.exit(d->writePasswordJob->error());
    });

    d->writePasswordJob->setTextData(credentials);
    d->writePasswordJob->start();

    loop.exec();

    return returnValue;
}

int Smb4KCredentialsManager::remove(const QString &key)
{
    int returnValue = QKeychain::NoError;
    QEventLoop loop;
    d->deletePasswordJob->setKey(key);

    QObject::connect(d->deletePasswordJob, &QKeychain::WritePasswordJob::finished, [&]() {
        if (d->deletePasswordJob->error()) {
            qDebug() << "Delete error:" << d->deletePasswordJob->errorString();
            returnValue = d->deletePasswordJob->error();
        }

        loop.exit(d->deletePasswordJob->error());
    });

    d->deletePasswordJob->start();

    loop.exec();

    return returnValue;
}

int Smb4KCredentialsManager::migrate()
{
    int returnValue = QKeychain::NoError;

    // Only consider migrating login credentials if Smb4K was already installed and
    // no migration has been done before.
    QString configFile = QStandardPaths::locate(QStandardPaths::ConfigLocation, QStringLiteral("smb4krc"), QStandardPaths::LocateFile);
    KConfigGroup authenticationGroup(Smb4KSettings::self()->config(), QStringLiteral("Authentication"));

    if (!configFile.isEmpty()) {
        if (!authenticationGroup.hasKey(QStringLiteral("MigratedToKeychain"))) {
#if (KWIDGETSADDONS_VERSION >= QT_VERSION_CHECK(5, 100, 0))
            int buttonCode = KMessageBox::questionTwoActionsCancel(
                QApplication::activeWindow() ? QApplication::activeWindow() : nullptr,
                i18n("Smb4K now stores the credentials in the secure storage under <b>org.kde.smb4k</b>. Do you want to migrate your credentials?"),
                i18n("Migrate Credentials"),
                KGuiItem(i18n("Migrate"), KDE::icon("edit-duplicate")),
                KGuiItem(i18n("Don't migrate"), KDE::icon("edit-delete-remove")),
                KStandardGuiItem::cancel());

            if (buttonCode == KMessageBox::PrimaryAction) {
#else
            int buttonCode = KMessageBox::questionYesNoCancel(
                QApplication::activeWindow() ? QApplication::activeWindow() : nullptr,
                i18n("Smb4K now stores the credentials in the secure storage under <b>org.kde.smb4k</b>. Do you want to migrate your credentials?"),
                i18n("Migrate Credentials"),
                KGuiItem(i18n("Migrate"), KDE::icon("edit-duplicate")),
                KGuiItem(i18n("Don't migrate"), KDE::icon("edit-delete-remove")),
                KStandardGuiItem::cancel());

            if (buttonCode == KMessageBox::Yes) {
#endif

                KWallet::Wallet *wallet =
                    KWallet::Wallet::openWallet(KWallet::Wallet::NetworkWallet(), QApplication::activeWindow() ? QApplication::activeWindow()->winId() : 0);

                if (wallet && wallet->isOpen()) {
                    if (wallet->hasFolder(QStringLiteral("Smb4K"))) {
                        wallet->setFolder(QStringLiteral("Smb4K"));

                        bool ok = false;
                        QMap<QString, QMap<QString, QString>> allWalletEntries = wallet->mapList(&ok);

                        if (ok) {
                            QMapIterator<QString, QMap<QString, QString>> it(allWalletEntries);

                            while (it.hasNext()) {
                                it.next();

                                if (it.key() == QStringLiteral("DEFAULT_LOGIN")) {
                                    QUrl url;
                                    url.setUserName(it.value().value(QStringLiteral("Login")));
                                    url.setPassword(it.value().value(QStringLiteral("Password")));
                                    returnValue = write(QStringLiteral("smb://"), url.userInfo());
                                } else {
                                    QUrl url;
                                    url.setUrl(it.key(), QUrl::TolerantMode);
                                    url.setUserName(it.value().value(QStringLiteral("Login")));
                                    url.setPassword(it.value().value(QStringLiteral("Password")));
                                    returnValue = write(it.key(), url.userInfo());
                                }
                            }
                        }

                        // wallet->removeFolder(QStringLiteral("Smb4K"));

                        authenticationGroup.writeEntry(QStringLiteral("MigratedToKeychain"), true);
                        authenticationGroup.sync();
                    }
                }

                delete wallet;
#if (KWIDGETSADDONS_VERSION >= QT_VERSION_CHECK(5, 100, 0))
            } else if (buttonCode == KMessageBox::SecondaryAction) {
#else
            } else if (buttonCode == KMessageBox::No) {
#endif
                authenticationGroup.writeEntry(QStringLiteral("MigratedToKeychain"), false);
                authenticationGroup.sync();
            }
        }
    } else {
        authenticationGroup.writeEntry(QStringLiteral("MigratedToKeychain"), true);
        authenticationGroup.sync();
    }

    return returnValue;
}
