/*
    This class provides the credentials manager used by Smb4K

    SPDX-FileCopyrightText: 2022-2023 Alexander Reinholdt <alexander.reinholdt@kdemail.net>
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
#include <KConfigGroup>
#include <KGuiItem>
#include <KLocalizedString>
#include <KMessageBox>
#include <KWallet>
#include <QFile>
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
    (void)migrate();

    if (networkItem) {
        QString userInfo;

        switch (networkItem->type()) {
        case Network: {
            // The url should only contain "smb://"...
            QString key = networkItem->url().toString(QUrl::RemoveUserInfo | QUrl::RemovePort);
            success = (read(key, &userInfo) == QKeychain::NoError);
            break;
        }
        case Host: {
            QString key = networkItem->url().toString(QUrl::RemoveUserInfo | QUrl::RemovePort);

            int returnCode = read(key, &userInfo);

            if (returnCode == QKeychain::EntryNotFound) {
                key = QStringLiteral("smb://");
                returnCode = read(key, &userInfo);
            }

            success = (returnCode == QKeychain::NoError);

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

            int returnCode = read(key, &userInfo);

            if (returnCode == QKeychain::EntryNotFound) {
                key = share->url().adjusted(QUrl::RemovePath | QUrl::StripTrailingSlash).toString(QUrl::RemoveUserInfo | QUrl::RemovePort);

                returnCode = read(key, &userInfo);

                if (returnCode == QKeychain::EntryNotFound) {
                    key = QStringLiteral("smb://");
                    returnCode = read(key, &userInfo);
                }
            }

            success = (returnCode == QKeychain::NoError);

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
    QString credentials;

    if (read(QStringLiteral("smb://"), &credentials) == QKeychain::NoError) {
        return true;
    }

    return false;
}

bool Smb4KCredentialsManager::showPasswordDialog(const NetworkItemPtr &networkItem)
{
    Q_ASSERT(networkItem);

    // For backward compatibility. Remove in the future again.
    // FIXME: Handle return value!?
    (void)migrate();

    bool success = false;

    if (networkItem) {
        QMap<QString, QString> knownLogins;
        int returnCode = QKeychain::NoError;
        QString userInfo;

        switch (networkItem->type()) {
        case Share: {
            SharePtr share = networkItem.staticCast<Smb4KShare>();
            QString key;

            if (share->isHomesShare()) {
                QStringList usersList = Smb4KHomesSharesHandler::self()->homesUsers(share);

                for (const QString &user : qAsConst(usersList)) {
                    SharePtr tempShare = SharePtr(new Smb4KShare(*share.data()));
                    tempShare->setUserName(user);

                    // The credentials should be present, so we only look for this
                    // specific pair.
                    key = tempShare->homeUrl().toString(QUrl::RemoveUserInfo | QUrl::RemovePort);

                    if ((returnCode = read(key, &userInfo)) == QKeychain::NoError) {
                        knownLogins.insert(tempShare->userName(), tempShare->password());
                    }

                    tempShare.clear();
                }
            } else {
                key = share->url().toString(QUrl::RemoveUserInfo | QUrl::RemovePort);

                if ((returnCode = read(key, &userInfo)) == QKeychain::EntryNotFound) {
                    key = share->url().adjusted(QUrl::RemovePath | QUrl::StripTrailingSlash).toString(QUrl::RemoveUserInfo | QUrl::RemovePort);

                    if ((returnCode = read(key, &userInfo)) == QKeychain::EntryNotFound) {
                        key = QStringLiteral("smb://");
                        returnCode = read(key, &userInfo);
                    }
                }
            }
            break;
        }
        default: {
            QString key = networkItem->url().toString(QUrl::RemoveUserInfo | QUrl::RemovePort);

            if ((returnCode = read(key, &userInfo)) == QKeychain::EntryNotFound) {
                key = QStringLiteral("smb://");
                returnCode = read(key, &userInfo);
            }
            break;
        }
        }

        if (returnCode == QKeychain::NoError || returnCode == QKeychain::EntryNotFound) {
            QUrl url = networkItem->url();
            url.setUserInfo(userInfo);
            networkItem->setUrl(url);

            QPointer<Smb4KPasswordDialog> dlg = new Smb4KPasswordDialog(networkItem, knownLogins, QApplication::activeWindow());

            if (dlg->exec() == Smb4KPasswordDialog::Accepted) {
                success = writeLoginCredentials(networkItem);
            }

            delete dlg;
        }
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
    });

    QObject::connect(d->readPasswordJob, &QKeychain::ReadPasswordJob::finished, &loop, &QEventLoop::quit);

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
    });

    QObject::connect(d->writePasswordJob, &QKeychain::WritePasswordJob::finished, &loop, &QEventLoop::quit);

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
    });

    QObject::connect(d->deletePasswordJob, &QKeychain::DeletePasswordJob::finished, &loop, &QEventLoop::quit);

    d->deletePasswordJob->start();

    loop.exec();

    return returnValue;
}

int Smb4KCredentialsManager::migrate()
{
    int returnValue = QKeychain::NoError;

    // Only consider migrating login credentials if Smb4K was already installed and
    // no migration has been done before.
    QString configFile = QStandardPaths::locate(Smb4KSettings::self()->config()->locationType(), Smb4KSettings::self()->config()->mainConfigName());
    KConfigGroup authenticationGroup(Smb4KSettings::self()->config(), QStringLiteral("Authentication"));

    if (QFile::exists(configFile) && !authenticationGroup.hasKey(QStringLiteral("MigratedToKeychain"))) {
        int buttonCode = KMessageBox::questionTwoActions(QApplication::activeWindow() ? QApplication::activeWindow() : nullptr,
                                                         i18n("The way Smb4K stores the credentials changed.\n\n"
                                                              "Do you want to migrate your credentials?"),
                                                         i18n("Migrate Credentials"),
                                                         KGuiItem(i18n("Migrate"), KDE::icon(QStringLiteral("edit-duplicate"))),
                                                         KStandardGuiItem::cancel());

        if (buttonCode == KMessageBox::PrimaryAction) {
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

                            QString key, userInfo;

                            if (it.key() == QStringLiteral("DEFAULT_LOGIN")) {
                                QUrl url;
                                url.setUserName(it.value().value(QStringLiteral("Login")));
                                url.setPassword(it.value().value(QStringLiteral("Password")));

                                key = QStringLiteral("smb://");
                                userInfo = url.userInfo();
                            } else {
                                QUrl url;
                                url.setUrl(it.key(), QUrl::TolerantMode);
                                url.setUserName(it.value().value(QStringLiteral("Login")));
                                url.setPassword(it.value().value(QStringLiteral("Password")));

                                key = it.key();
                                userInfo = url.userInfo();
                            }

                            if ((returnValue = write(key, userInfo)) != QKeychain::NoError) {
                                break;
                            }
                        }
                    }

                    // wallet->removeFolder(QStringLiteral("Smb4K"));
                }
            }

            wallet->closeWallet(KWallet::Wallet::NetworkWallet(), false);
            delete wallet;

            if (returnValue == QKeychain::NoError) {
                authenticationGroup.writeEntry(QStringLiteral("MigratedToKeychain"), true);
                authenticationGroup.sync();
            } else {
                // FIXME: Report an error in case the migration failed.
            }

        } else if (buttonCode == KMessageBox::SecondaryAction) {
            authenticationGroup.writeEntry(QStringLiteral("MigratedToKeychain"), false);
            authenticationGroup.sync();
        }
    }

    return returnValue;
}
