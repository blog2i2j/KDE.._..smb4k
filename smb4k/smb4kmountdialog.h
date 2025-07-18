/*
 *  Mount dialog
 *
 *  SPDX-FileCopyrightText: 2023-2025 Alexander Reinholdt <alexander.reinholdt@kdemail.net>
 *  SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SMB4KMOUNTDIALOG_H
#define SMB4KMOUNTDIALOG_H

// application specific includes
#include "smb4kdialogs_export.h"

// Qt includes
#include <QCheckBox>
#include <QDialog>
#include <QPushButton>
#include <QResizeEvent>
#include <QSize>
#include <QUrl>

// KDE includes
#include <KComboBox>
#include <KLineEdit>

class SMB4KDIALOGS_EXPORT Smb4KMountDialog : public QDialog
{
    Q_OBJECT

public:
    /**
     * Constructor
     */
    explicit Smb4KMountDialog(QWidget *parent = nullptr);

    /**
     * Destructor
     */
    virtual ~Smb4KMountDialog();

protected Q_SLOTS:
    void slotEnableButtons(const QString &text);
    void slotBookmarkButtonClicked();
    void slotEnableBookmarkInputWidget();
    void slotLocationEntered();
    void slotIpAddressEntered();
    void slotWorkgroupEntered();
    void slotLabelEntered();
    void slotCategoryEntered();
    void slotAccepted();
    void slotRejected();

private:
    QUrl createUrl(const QString &text) const;
    bool isValidLocation(const QString &text);
    void adjustDialogSize();
    KLineEdit *m_locationInput;
    KLineEdit *m_ipAddressInput;
    KLineEdit *m_workgroupInput;
    QPushButton *m_okButton;
    QPushButton *m_cancelButton;
    QPushButton *m_bookmarkButton;
    QWidget *m_bookmarkWidget;
    QCheckBox *m_bookmarkShare;
    QWidget *m_bookmarkInputWidget;
    KLineEdit *m_bookmarkLabelInput;
    KComboBox *m_bookmarkCategoryInput;
};

#endif
