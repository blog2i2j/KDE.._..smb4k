/*
    This class provides the credentials manager used by Smb4K

    SPDX-FileCopyrightText: 2022 Alexander Reinholdt <alexander.reinholdt@kdemail.net>
    SPDX-License-Identifier: GPL-2.0-or-later
*/

// applications specific includes
#include "smb4kcredentialsmanager.h"
#include "smb4kcredentialsmanager_p.h"
#include "smb4kglobal.h"
#include "smb4kshare.h"
#include "smb4khomesshareshandler.h"

// Qt includes
#include <QDebug>
#include <QEventLoop>
#include <QApplication>
#include <QPointer>

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

    if (networkItem) {
        QString userInfo;

        switch (networkItem->type()) {
        case Host: {
            QString key = networkItem->url().toString(QUrl::RemoveUserInfo | QUrl::RemovePort);

            if (!(success = read(key, &userInfo))) {
                key = QStringLiteral("DEFAULT_CREDENTIALS");
                success = read(key, &userInfo);
            }
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

            if (!(success = read(key, &userInfo))) {
                key = share->url().adjusted(QUrl::RemovePath | QUrl::StripTrailingSlash).toString(QUrl::RemoveUserInfo | QUrl::RemovePort);

                if (!(success = read(key, &userInfo))) {
                    key = QStringLiteral("DEFAULT_CREDENTIALS");
                    success = read(key, &userInfo);
                }
            }
            break;
        }
        case UnknownNetworkItem: {
            QString key = QStringLiteral("DEFAULT_CREDENTIALS");
            success = read(key, &userInfo);
            break;
        }
        default: {
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
                success = write(key, networkItem->url().userInfo());
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
                success = write(key, share->url().userInfo());
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
    return write(QStringLiteral("DEFAULT_CREDENTIALS"), credentials);
}

bool Smb4KCredentialsManager::hasDefaultCredentials() const
{
    QString key = QStringLiteral("DEFAULT_CREDENTIALS");
    QString credentials;

    if (read(key, &credentials)) {
        return true;
    }

    return false;
}

bool Smb4KCredentialsManager::showPasswordDialog(const NetworkItemPtr &networkItem)
{
    Q_ASSERT(networkItem);

    bool success = false;

    if (networkItem) {
        QMap<QString, QString> knownLogins;

        switch (networkItem->type())
        {
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

bool Smb4KCredentialsManager::read(const QString &key, QString *credentials) const
{
    bool returnValue = true;
    d->readPasswordJob->setKey(key);

    QEventLoop loop;
    QString loginCredentials;

    QObject::connect(d->readPasswordJob, &QKeychain::ReadPasswordJob::finished, [&]() {
        if (d->readPasswordJob->error()) {
            qDebug() << "Error:" << d->readPasswordJob->errorString();
            returnValue = false;
            return;
        }

        *credentials = d->readPasswordJob->textData();
    });

    d->readPasswordJob->start();

    loop.exec();

    return returnValue;
}

bool Smb4KCredentialsManager::write(const QString &key, const QString &credentials) const
{
    bool returnValue = true;
    d->writePasswordJob->setKey(key);

    QEventLoop loop;

    QObject::connect(d->writePasswordJob, &QKeychain::WritePasswordJob::finished, [&]() {
        if (d->writePasswordJob->error()) {
            qDebug() << "Error:" << d->writePasswordJob->errorString();
            returnValue = false;
            return;
        }
    });

    d->writePasswordJob->setTextData(credentials);
    d->writePasswordJob->start();

    loop.exec();

    return returnValue;
}

void Smb4KCredentialsManager::remove(const QString &key)
{
    d->deletePasswordJob->setKey(key);

    QEventLoop loop;

    QObject::connect(d->deletePasswordJob, &QKeychain::WritePasswordJob::finished, [&]() {
        if (d->deletePasswordJob->error()) {
            qDebug() << "Error:" << d->deletePasswordJob->errorString();
            return;
        }
    });

    d->deletePasswordJob->start();

    loop.exec();
}
