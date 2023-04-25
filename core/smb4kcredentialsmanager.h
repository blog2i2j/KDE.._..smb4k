/*
    This class provides the credentials manager used by Smb4K

    SPDX-FileCopyrightText: 2022-2023 Alexander Reinholdt <alexander.reinholdt@kdemail.net>
    SPDX-License-Identifier: GPL-2.0-or-later
*/

#ifndef SMB4KCREDENTIALSMANAGER_H
#define SMB4KCREDENTIALSMANAGER_H

// application specific includes
#include "smb4kbasicnetworkitem.h"
#include "smb4kglobal.h"

// Qt includes
#include <QScopedPointer>
#include <QUrl>

// forward declarations
class Smb4KCredentialsManagerPrivate;

/**
 * This class manages the access to the credentials
 *
 * @author Alexander Reinholdt <alexander.reinholdt@kdemail.net>
 * @since 3.2.0
 */

class Q_DECL_EXPORT Smb4KCredentialsManager : public QObject
{
    Q_OBJECT

public:
    /**
     * Constructor
     */
    explicit Smb4KCredentialsManager(QObject *parent = nullptr);

    /**
     * Destructor
     */
    ~Smb4KCredentialsManager();

    /**
     * This is a static pointer to this class.
     */
    static Smb4KCredentialsManager *self();

    /**
     * Read the login credentials for the given @p networkItem from
     * the secure storage.
     *
     * @param networkItem   The network item for which the login
     *                      credentials should be read.
     *
     * @returns TRUE if writing to the secure storage was successful.
     */
    bool readLoginCredentials(const NetworkItemPtr &networkItem);

    /**
     * Write the login credentials for the given @p networkItem to the
     * secure storage.
     *
     * @param networkItem   The network item for which the login
     *                      credentials should be saved.
     *
     * @returns TRUE if writing to the secure storage was successful.
     */
    bool writeLoginCredentials(const NetworkItemPtr &networkItem);

    /**
     * Write the default login @p credentials with the given @p key to
     * the secure storage.
     *
     * @param credentials   The defaultlogin credentials. They have to be
     *                      formatted as in a URL: USER:PASSWORD
     *
     * @returns TRUE if writing to the secure storage was successful.
     */
    bool writeDefaultLoginCredentials(const QString &credentials);

    /**
     * This function returns TRUE if default credentials are defined and
     * FALSE otherwise.
     *
     * @returns TRUE if default credentials are defined.
     */
    bool hasDefaultCredentials() const;

    /**
     * Show the password dialog for the network item @p networkItem.
     *
     * @param networkItem   The network item for which the login credentials
     *                      are requested.
     *
     * @returns TRUE if successful and FALSE otherwise.
     */
    bool showPasswordDialog(const NetworkItemPtr &networkItem);

private:
    /**
     * Read login credentials from the secure storage.
     *
     * @param key           The key for the credentials
     *
     * @param credentials   The string that will hold the credentials
     *
     * @returns TRUE if everything worked out fine.
     */
    int read(const QString &key, QString *credentials) const;

    /**
     * Write the login credentials to the secure storage.
     *
     * @param key           The key for the credentials
     *
     * @param credentials   The credentials string
     */
    int write(const QString &key, const QString &credentials) const;

    /**
     * Delete the login credentials from the secure storage.
     *
     * @param key           The key for the credentials
     */
    int remove(const QString &key);

    /**
     * This function migrates the old credentials.
     */
    int migrate();

    /**
     * Pointer to the Smb4KWalletManagerPrivate class
     */
    const QScopedPointer<Smb4KCredentialsManagerPrivate> d;
};

#endif
