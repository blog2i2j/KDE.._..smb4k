/***************************************************************************
    The configuration dialog of Smb4K
                             -------------------
    begin                : Sa Apr 14 2007
    copyright            : (C) 2004-2018 by Alexander Reinholdt
    email                : alexander.reinholdt@kdemail.net
 ***************************************************************************/

/***************************************************************************
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful, but   *
 *   WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU     *
 *   General Public License for more details.                              *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc., 51 Franklin Street, Suite 500, Boston,*
 *   MA 02110-1335, USA                                                    *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

// application specific includes
#include "smb4kconfigdialog.h"
#include "smb4kconfigpageauthentication.h"
#include "smb4kconfigpagecustomoptions.h"
#include "smb4kconfigpagemounting.h"
#include "smb4kconfigpagenetwork.h"
#include "smb4kconfigpageprofiles.h"
#include "smb4kconfigpagesynchronization.h"
#include "smb4kconfigpageuserinterface.h"
#include "core/smb4ksettings.h"
#include "core/smb4kglobal.h"
#include "core/smb4kauthinfo.h"
#include "core/smb4kwalletmanager.h"
#include "core/smb4kcustomoptions.h"
#include "core/smb4kcustomoptionsmanager.h"
#include "core/smb4kprofilemanager.h"

#if defined(Q_OS_LINUX)
#include "smb4kmountsettings_linux.h"
#elif defined(Q_OS_FREEBSD) || defined(Q_OS_NETBSD)
#include "smb4kmountsettings_bsd.h"
#endif

// Qt includes
#include <QPointer>
#include <QPair>
#include <QList>
#include <QSize>
#include <QStandardPaths>
#include <QRadioButton>
#include <QCheckBox>
#include <QTreeWidget>
#include <QScrollArea>
#include <QShowEvent>
#include <QWindow>

// KDE includes
#include <KCoreAddons/KPluginFactory>
#include <KI18n/KLocalizedString>
#include <KConfigGui/KWindowConfig>
#include <KWidgetsAddons/KMessageBox>
#include <KWidgetsAddons/KPasswordDialog>
#include <KIOWidgets/KUrlRequester>

using namespace Smb4KGlobal;

K_PLUGIN_FACTORY(Smb4KConfigDialogFactory, registerPlugin<Smb4KConfigDialog>();)


Smb4KConfigDialog::Smb4KConfigDialog(QWidget *parent, const QList<QVariant> &/*args*/)
: KConfigDialog(parent, "ConfigDialog", Smb4KSettings::self())
{
  setupDialog();
}


Smb4KConfigDialog::~Smb4KConfigDialog()
{
}


void Smb4KConfigDialog::setupDialog()
{
  // FIXME: I guess, normally we would not need to close destructively,
  // but at the moment there are issues with the KURLRequester in file
  // mode. To work around those, we are closing the dialog destructively.
  // Maybe we can remove this if we moved to KDE4.
  setAttribute(Qt::WA_DeleteOnClose, true);

  // Add the pages:
  Smb4KConfigPageUserInterface *interface_options = new Smb4KConfigPageUserInterface(this);
  QScrollArea *interface_area = new QScrollArea(this);
  interface_area->setWidget(interface_options);
  interface_area->setWidgetResizable(true);
  interface_area->setFrameStyle(QFrame::NoFrame);

  Smb4KConfigPageNetwork *network_options = new Smb4KConfigPageNetwork(this);
  QScrollArea *network_area = new QScrollArea(this);
  network_area->setWidget(network_options);
  network_area->setWidgetResizable(true);
  network_area->setFrameStyle(QFrame::NoFrame);
  
#if !defined(SMB4K_UNSUPPORTED_PLATFORM)  
  Smb4KConfigPageMounting *mount_options = new Smb4KConfigPageMounting(this);
  QScrollArea *mount_area = new QScrollArea(this);
  mount_area->setWidget(mount_options);
  mount_area->setWidgetResizable(true);
  mount_area->setFrameStyle(QFrame::NoFrame);
#endif

  Smb4KConfigPageAuthentication *auth_options = new Smb4KConfigPageAuthentication(this);
  QScrollArea *auth_area = new QScrollArea(this);
  auth_area->setWidget(auth_options);
  auth_area->setWidgetResizable(true);
  auth_area->setFrameStyle(QFrame::NoFrame);

  Smb4KConfigPageSynchronization *rsync_options = new Smb4KConfigPageSynchronization(this);
  QScrollArea *rsync_area = new QScrollArea(this);
  rsync_area->setWidget(rsync_options);
  rsync_area->setWidgetResizable(true);
  rsync_area->setFrameStyle(QFrame::NoFrame);
  
  rsync_options->setEnabled(!QStandardPaths::findExecutable("rsync").isEmpty());

  Smb4KConfigPageCustomOptions *custom_options = new Smb4KConfigPageCustomOptions(this);
  QScrollArea *custom_area = new QScrollArea(this);
  custom_area->setWidget(custom_options);
  custom_area->setWidgetResizable(true);
  custom_area->setFrameStyle(QFrame::NoFrame);
  
  Smb4KConfigPageProfiles *profiles_page = new Smb4KConfigPageProfiles(this);
  QScrollArea *profiles_area = new QScrollArea(this);
  profiles_area->setWidget(profiles_page);
  profiles_area->setWidgetResizable(true);
  profiles_area->setFrameStyle(QFrame::NoFrame);

  // 
  // Pages to the configuration dialog
  // 
  m_user_interface  = addPage(interface_area, Smb4KSettings::self(), i18n("User Interface"), "preferences-desktop");
  m_network         = addPage(network_area, Smb4KSettings::self(), i18n("Network Neighborhood"), "network-workgroup");
#if !defined(SMB4K_UNSUPPORTED_PLATFORM)
  m_mounting        = addPage(mount_area, Smb4KMountSettings::self(), i18n("Mounting"), "system-run");
#endif
  m_authentication  = addPage(auth_area, Smb4KSettings::self(), i18n("Authentication"), "dialog-password");
  m_synchronization = addPage(rsync_area, Smb4KSettings::self(),i18n("Synchronization"), "folder-sync");
  m_custom_options  = addPage(custom_area, Smb4KSettings::self(), i18n("Custom Options"), "preferences-system-network");
  m_profiles        = addPage(profiles_area, Smb4KSettings::self(), i18n("Profiles"), "format-list-unordered");

  // 
  // Connections
  // 
  connect(custom_options, SIGNAL(customSettingsModified()), this, SLOT(slotEnableApplyButton()));

  connect(auth_options, SIGNAL(loadWalletEntries()), this, SLOT(slotLoadAuthenticationInformation()));
  connect(auth_options, SIGNAL(saveWalletEntries()), this, SLOT(slotSaveAuthenticationInformation()));
  connect(auth_options, SIGNAL(setDefaultLogin()), this, SLOT(slotSetDefaultLogin()));
  connect(auth_options, SIGNAL(walletEntriesModified()), this, SLOT(slotEnableApplyButton()));
  
  connect(this, SIGNAL(currentPageChanged(KPageWidgetItem*,KPageWidgetItem*)), this, SLOT(slotCheckPage(KPageWidgetItem*,KPageWidgetItem*)));
  
  //
  // Dialog size
  //
  create();
  windowHandle()->resize(QSize(800, 600));

  KConfigGroup group(Smb4KSettings::self()->config(), "ConfigDialog");
  KWindowConfig::restoreWindowSize(windowHandle(), group);
  resize(windowHandle()->size()); // workaround for QTBUG-40584
}


void Smb4KConfigDialog::loadCustomOptions()
{
  if (m_custom_options)
  {
    QList<OptionsPtr> options = Smb4KCustomOptionsManager::self()->customOptions();
    m_custom_options->widget()->findChild<Smb4KConfigPageCustomOptions *>()->insertCustomOptions(options);
  }
  else
  {
    // Do nothing
  }
}


void Smb4KConfigDialog::saveCustomOptions()
{
  if (m_custom_options)
  {
    QList<OptionsPtr> options = m_custom_options->widget()->findChild<Smb4KConfigPageCustomOptions *>()->getCustomOptions();
    Smb4KCustomOptionsManager::self()->replaceCustomOptions(options);
  }
  else
  {
    // Do nothing
  }
}


void Smb4KConfigDialog::propagateProfilesChanges()
{
  Smb4KConfigPageProfiles *profiles_page = m_profiles->widget()->findChild<Smb4KConfigPageProfiles *>();
  
  if (profiles_page)
  {
    // Remove the profiles.
    QStringList removed_profiles = profiles_page->removedProfiles();
    
    if (!removed_profiles.isEmpty())
    {
      Smb4KProfileManager::self()->removeProfiles(removed_profiles, this);
      profiles_page->clearRemovedProfiles();
    }
    else
    {
      // Do nothing
    }
    
    // Rename the profiles.
    QList< QPair<QString,QString> > renamed_profiles = profiles_page->renamedProfiles();
    
    if (!renamed_profiles.isEmpty())
    {
      Smb4KProfileManager::self()->migrateProfiles(renamed_profiles);
      profiles_page->clearRenamedProfiles();
    }
    else
    {
      // Do nothing
    }
    
    // Finally reload the custom options.
    if (!removed_profiles.isEmpty() || !renamed_profiles.isEmpty())
    {
      loadCustomOptions();
    }
    else
    {
      // Do nothing
    }
  }
  else
  {
    // Do nothing
  }
}


bool Smb4KConfigDialog::checkNetworkPage()
{
  QRadioButton *query_custom_master = m_network->widget()->findChild<QRadioButton *>("kcfg_QueryCustomMaster");
  KLineEdit *custom_master_input    = m_network->widget()->findChild<KLineEdit *>("kcfg_CustomMasterBrowser");
  
  QString msg = i18n("<qt>An incorrect setting has been found. You are now taken to the corresponding configuration page to fix it.</qt>");

  if ((query_custom_master && query_custom_master->isChecked()) &&
      (custom_master_input && custom_master_input->text().trimmed().isEmpty()))
  {
    KMessageBox::sorry(this, msg);
    setCurrentPage(m_network);
    custom_master_input->setFocus();
    return false;
  }
  else
  {
    // Do nothing
  }
  
  QRadioButton *scan_bcast_areas = m_network->widget()->findChild<QRadioButton *>("kcfg_ScanBroadcastAreas");
  KLineEdit *bcast_areas_input   = m_network->widget()->findChild<KLineEdit *>("kcfg_BroadcastAreas");
  
  if ((scan_bcast_areas && scan_bcast_areas->isChecked()) &&
      (bcast_areas_input && bcast_areas_input->text().trimmed().isEmpty()))
  {
    KMessageBox::sorry(this, msg);
    setCurrentPage(m_network);
    bcast_areas_input->setFocus();
    return false;
  }
  else
  {
    // Do nothing
  }  
  
  return true;
}


bool Smb4KConfigDialog::checkMountingPage()
{
#if !defined(SMB4K_UNSUPPORTED_PLATFORM)
  KUrlRequester *mount_prefix = m_mounting->widget()->findChild<KUrlRequester *>("kcfg_MountPrefix");
  
  QString msg = i18n("<qt>An incorrect setting has been found. You are now taken to the corresponding configuration page to fix it.</qt>");
  
  if (mount_prefix && mount_prefix->url().path().trimmed().isEmpty())
  {
    KMessageBox::sorry(this, msg);
    setCurrentPage(m_mounting);
    mount_prefix->setFocus();
    return false;
  }
  else
  {
    // Do nothing
  }
  
  KLineEdit *file_mask = m_mounting->widget()->findChild<KLineEdit *>("kcfg_FileMask");
  
  msg = i18n("<qt>An incorrect setting has been found. You are now taken to the corresponding configuration page to fix it.</qt>");
  
  if (file_mask && file_mask->text().trimmed().isEmpty())
  {
    KMessageBox::sorry(this, msg);
    setCurrentPage(m_mounting);
    file_mask->setFocus();
    return false;
  }
  else
  {
    // Do nothing
  }
  
  KLineEdit *directory_mask = m_mounting->widget()->findChild<KLineEdit *>("kcfg_DirectoryMask");
  
  if (directory_mask && directory_mask->text().trimmed().isEmpty())
  {
    KMessageBox::sorry(this, msg);
    setCurrentPage(m_mounting);
    directory_mask->setFocus();
    return false;
  }
  else
  {
    // Do nothing
  }
#endif
  
  return true;
}


bool Smb4KConfigDialog::checkSynchronizationPage()
{
  //
  // Get the config page 
  // Since the config page is embedded into a scroll area, use findChild() here.
  // 
  Smb4KConfigPageSynchronization *configPage = m_synchronization->widget()->findChild<Smb4KConfigPageSynchronization *>();
  
  if (configPage)
  {
    //
    // The error message
    // 
    QString errorMessage = i18n("<qt>An incorrect setting has been found. You are now taken to the corresponding configuration page to fix it.</qt>");
    
    // Find the tab number and the url requester
    for (int i = 0; i < configPage->count(); i++)
    {
      // Synchronization prefix
      KUrlRequester *syncPrefix = configPage->widget(i)->findChild<KUrlRequester *>("kcfg_RsyncPrefix");
      
      if (syncPrefix && (!syncPrefix->url().isValid() || syncPrefix->url().path().trimmed().isEmpty()))
      {
        KMessageBox::sorry(this, errorMessage);
        setCurrentPage(m_synchronization);
        configPage->setCurrentIndex(i);
        syncPrefix->setFocus();
        return false;
      }
      else
      {
        // Do nothing
      }
    
      // Backups
      QCheckBox *makeBackups = configPage->widget(i)->findChild<QCheckBox *>("kcfg_MakeBackups");
      QCheckBox *useBackupSuffix = configPage->widget(i)->findChild<QCheckBox *>("kcfg_UseBackupSuffix");
      KLineEdit *backupSuffix = configPage->widget(i)->findChild<KLineEdit *>("kcfg_BackupSuffix");
      QCheckBox *useBackupDir = configPage->widget(i)->findChild<QCheckBox *>("kcfg_UseBackupDirectory");
      KUrlRequester *backupDir = configPage->widget(i)->findChild<KUrlRequester *>("kcfg_BackupDirectory");
      
      if (makeBackups && makeBackups->isChecked())
      {
        if (useBackupSuffix && useBackupSuffix->isChecked())
        {
          if (backupSuffix && backupSuffix->text().trimmed().isEmpty())
          {
            KMessageBox::sorry(this, errorMessage);
            setCurrentPage(m_synchronization);
            configPage->setCurrentIndex(i);
            backupSuffix->setFocus();
            return false;
          }
          else
          {
            // Do nothing
          }
        }
        else
        {
          // Do nothing
        }
        
        if (useBackupDir && useBackupDir->isChecked())
        {
          if (backupDir && (!backupDir->url().isValid() || backupDir->url().path().trimmed().isEmpty()))
          {
            KMessageBox::sorry(this, errorMessage);
            setCurrentPage(m_synchronization);
            configPage->setCurrentIndex(i);
            backupDir->setFocus();
            return false;
          }
          else
          {
            // Do nothing
          }
        }
        else
        {
          // Do nothing
        }
      }
      else
      {
        // Do nothing
      }
      
      // Minimal transfer size
      QCheckBox *useMinTransferSize = configPage->widget(i)->findChild<QCheckBox *>("kcfg_UseMinimalTransferSize");
      QSpinBox *minTransferSize = configPage->widget(i)->findChild<QSpinBox *>("kcfg_MinimalTransferSize");
      
      if (useMinTransferSize && useMinTransferSize->isChecked())
      {
        if (minTransferSize && minTransferSize->value() == 0)
        {
          KMessageBox::sorry(this, errorMessage);
          setCurrentPage(m_synchronization);
          configPage->setCurrentIndex(i);
          minTransferSize->setFocus();
          return false;
        }
        else
        {
          // Do nothing
        }
      }
      else
      {
        // Do nothing
      }
      
      // Maximal transfer size
      QCheckBox *useMaxTransferSize = configPage->widget(i)->findChild<QCheckBox *>("kcfg_UseMaximalTransferSize");
      QSpinBox *maxTransferSize = configPage->widget(i)->findChild<QSpinBox *>("kcfg_MaximalTransferSize");
      
      if (useMaxTransferSize && useMaxTransferSize->isChecked())
      {
        if (maxTransferSize && maxTransferSize->value() == 0)
        {
          KMessageBox::sorry(this, errorMessage);
          setCurrentPage(m_synchronization);
          configPage->setCurrentIndex(i);
          maxTransferSize->setFocus();
          return false;
        }
        else
        {
          // Do nothing
        }
      }
      else
      {
        // Do nothing
      }
      
      // Partial directory
      QCheckBox *usePartialDirectory = configPage->widget(i)->findChild<QCheckBox *>("kcfg_UsePartialDirectory");
      KUrlRequester *partialDirectory = configPage->widget(i)->findChild<KUrlRequester *>("kcfg_PartialDirectory");
      
      if (usePartialDirectory && usePartialDirectory->isChecked())
      {
        if (partialDirectory && (!partialDirectory->url().isValid() || partialDirectory->url().path().trimmed().isEmpty()))
        {
          KMessageBox::sorry(this, errorMessage);
          setCurrentPage(m_synchronization);
          configPage->setCurrentIndex(i);
          partialDirectory->setFocus();
          return false;
        }
        else
        {
          // Do nothing
        }
      }
      else
      {
        // Do nothing
      }
      
      // Exclude exclude
      QCheckBox *useExcludePattern = configPage->widget(i)->findChild<QCheckBox *>("kcfg_UseExcludePattern");
      KLineEdit *excludePattern = configPage->widget(i)->findChild<KLineEdit *>("kcfg_ExcludePattern");
      
      if (useExcludePattern && useExcludePattern->isChecked())
      {
        if (excludePattern && excludePattern->text().trimmed().isEmpty())
        {
          KMessageBox::sorry(this, errorMessage);
          setCurrentPage(m_synchronization);
          configPage->setCurrentIndex(i);
          excludePattern->setFocus();
          return false;
        }
        else
        {
          // Do nothing
        }
      }
      else
      {
        // Do nothing
      }
      
      // Read exclude pattern from file
      QCheckBox *useExcludeFrom = configPage->widget(i)->findChild<QCheckBox *>("kcfg_UseExcludeFrom");
      KUrlRequester *excludeFrom = configPage->widget(i)->findChild<KUrlRequester *>("kcfg_ExcludeFrom");
      
      if (useExcludeFrom && useExcludeFrom->isChecked())
      {
        if (excludeFrom && (!excludeFrom->url().isValid() || excludeFrom->url().path().trimmed().isEmpty()))
        {
          KMessageBox::sorry(this, errorMessage);
          setCurrentPage(m_synchronization);
          configPage->setCurrentIndex(i);
          excludeFrom->setFocus();
          return false;
        }
        else
        {
          // Do nothing
        }
      }
      else
      {
        // Do nothing
      }
      
      // Exclude exclude
      QCheckBox *useIncludePattern = configPage->widget(i)->findChild<QCheckBox *>("kcfg_UseIncludePattern");
      KLineEdit *includePattern = configPage->widget(i)->findChild<KLineEdit *>("kcfg_IncludePattern");
      
      if (useIncludePattern && useIncludePattern->isChecked())
      {
        if (includePattern && includePattern->text().trimmed().isEmpty())
        {
          KMessageBox::sorry(this, errorMessage);
          setCurrentPage(m_synchronization);
          configPage->setCurrentIndex(i);
          includePattern->setFocus();
          return false;
        }
        else
        {
          // Do nothing
        }
      }
      else
      {
        // Do nothing
      }
      
      // Read exclude pattern from file
      QCheckBox *useIncludeFrom = configPage->widget(i)->findChild<QCheckBox *>("kcfg_UseIncludeFrom");
      KUrlRequester *includeFrom = configPage->widget(i)->findChild<KUrlRequester *>("kcfg_IncludeFrom");
      
      if (useIncludeFrom && useIncludeFrom->isChecked())
      {
        if (includeFrom && (!includeFrom->url().isValid() || includeFrom->url().path().trimmed().isEmpty()))
        {
          KMessageBox::sorry(this, errorMessage);
          setCurrentPage(m_synchronization);
          configPage->setCurrentIndex(i);
          includeFrom->setFocus();
          return false;
        }
        else
        {
          // Do nothing
        }
      }
      else
      {
        // Do nothing
      }
      
      // Block size
      QCheckBox *useFixedBlocksize = configPage->widget(i)->findChild<QCheckBox *>("kcfg_UseBlockSize");
      QSpinBox *fixedBlocksize = configPage->widget(i)->findChild<QSpinBox *>("kcfg_BlockSize");
      
      if (useFixedBlocksize && useFixedBlocksize->isChecked())
      {
        if (fixedBlocksize && fixedBlocksize->value() == 0)
        {
          KMessageBox::sorry(this, errorMessage);
          setCurrentPage(m_synchronization);
          configPage->setCurrentIndex(i);
          fixedBlocksize->setFocus();
          return false;
        }
        else
        {
          // Do nothing
        }
      }
      else
      {
        // Do nothing
      }
      
      // NOTE: The is no need to check the following settings, because they may be empty or 0:
      // - kcfg_UseCompressionLevel & kcfg_CompressionLevel
      // - kcfg_UseSkipCompression & kcfg_SkipCompression
      // - kcfg_UseBandwidthLimit & kcfg_BandwidthLimit
      // - kcfg_UseMaximumDelete & kcfg_MaximumDeleteValue
      // - kcfg_CustomFilteringRules
      // - kcfg_UseChecksumSeed & kcfg_ChecksumSeed
    }
  }
  else
  {
    // Do nothing
  }

  return true;
}



bool Smb4KConfigDialog::checkSettings()
{
  // Check Network page
  if (!checkNetworkPage())
  {
    return false;
  }
  else
  {
    // Do nothing
  }
  
  // Check Mounting page
  if (!checkMountingPage())
  {
    return false;
  }
  else
  {
    // Do nothing
  }
  
  // Check Synchronization page
  if (!checkSynchronizationPage())
  {
    return false;
  }
  else
  {
    // Do nothing
  }
  
  return true;
}


/////////////////////////////////////////////////////////////////////////////
// SLOT IMPLEMENTATIONS
/////////////////////////////////////////////////////////////////////////////


void Smb4KConfigDialog::updateSettings()
{
  saveCustomOptions();
  slotSaveAuthenticationInformation();
  propagateProfilesChanges();
  (void)checkSettings();
  
  KConfigGroup group(Smb4KSettings::self()->config(), "ConfigDialog");
  KWindowConfig::saveWindowSize(windowHandle(), group);
      
  KConfigDialog::updateSettings();
}


void Smb4KConfigDialog::updateWidgets()
{
  loadCustomOptions();
  
  KConfigDialog::updateWidgets();
}


void Smb4KConfigDialog::reject()
{
  Smb4KCustomOptionsManager::self()->resetCustomOptions();
  QDialog::reject();
}


void Smb4KConfigDialog::slotLoadAuthenticationInformation()
{
  Smb4KConfigPageAuthentication *auth_options = m_authentication->widget()->findChild<Smb4KConfigPageAuthentication *>();
  QList<Smb4KAuthInfo *> entries = Smb4KWalletManager::self()->walletEntries();
  auth_options->insertWalletEntries(entries);
  auth_options->displayWalletEntries();
}


void Smb4KConfigDialog::slotSaveAuthenticationInformation()
{
  Smb4KConfigPageAuthentication *auth_options = m_authentication->widget()->findChild<Smb4KConfigPageAuthentication *>();
  
  if (auth_options->walletEntriesDisplayed())
  {
    QList<Smb4KAuthInfo *> entries = auth_options->getWalletEntries();
    Smb4KWalletManager::self()->writeWalletEntries(entries);
  }
  else
  {
    // Do nothing
  }
}


void Smb4KConfigDialog::slotSetDefaultLogin()
{
  Smb4KConfigPageAuthentication *auth_options = m_authentication->widget()->findChild<Smb4KConfigPageAuthentication *>();
  
  if (!auth_options->undoRemoval())
  {
    Smb4KAuthInfo authInfo;
    // We do not need to call useDefaultAuthInfo(), because 
    // Smb4KWalletManager::readDefaultAuthInfo() will do this
    // for us.
    Smb4KWalletManager::self()->readDefaultAuthInfo(&authInfo);
    
    QPointer<KPasswordDialog> dlg = new KPasswordDialog(this, KPasswordDialog::ShowUsernameLine);
    dlg->setPrompt(i18n("Enter the default login information."));
    dlg->setUsername(authInfo.userName());
    dlg->setPassword(authInfo.password());
    
    if (dlg->exec() == KPasswordDialog::Accepted)
    {
      authInfo.setUserName(dlg->username());
      authInfo.setPassword(dlg->password());
      
      Smb4KWalletManager::self()->writeDefaultAuthInfo(&authInfo);
      
      if (auth_options->walletEntriesDisplayed())
      {
        slotLoadAuthenticationInformation();
      }
      else
      {
        // Do nothing
      }    
    }
    else
    {
      // Reset the checkbox.
      auth_options->findChild<QCheckBox *>("kcfg_UseDefaultLogin")->setChecked(false);
    }
    
    delete dlg;
  }
  else
  {
    // Do nothing
  }
}


void Smb4KConfigDialog::slotEnableApplyButton()
{
  // Check if we need to enable the Apply button.
  bool enable = false;
  
  // Check the wallet entries.
  Smb4KConfigPageAuthentication *auth_options = m_authentication->widget()->findChild<Smb4KConfigPageAuthentication *>();

  if (auth_options->walletEntriesMaybeChanged())
  {
    QList<Smb4KAuthInfo *> old_wallet_entries = Smb4KWalletManager::self()->walletEntries();
    QList<Smb4KAuthInfo *> new_wallet_entries = auth_options->getWalletEntries();
    
    for (int i = 0; i < old_wallet_entries.size(); ++i)
    {
      for (int j = 0; j < new_wallet_entries.size(); ++j)
      {
        if (QString::compare(old_wallet_entries.at(i)->unc(),
                               new_wallet_entries.at(j)->unc(),
                               Qt::CaseInsensitive) == 0 &&
             (QString::compare(old_wallet_entries.at(i)->workgroupName(),
                                new_wallet_entries.at(j)->workgroupName(),
                                Qt::CaseInsensitive) != 0 ||
              QString::compare(old_wallet_entries.at(i)->userName(),
                                new_wallet_entries.at(j)->userName(),
                                Qt::CaseInsensitive) != 0 ||
              QString::compare(old_wallet_entries.at(i)->password(),
                                new_wallet_entries.at(j)->password(),
                                Qt::CaseInsensitive) != 0))
        {
          enable = true;
          break;
        }
        else
        {
          continue;
        }
      }
      
      if (enable)
      {
        break;
      }
      else
      {
        continue;
      }
    }
  }
  else
  {
    // Do nothing
  }
  
  // Check the custom settings.
  Smb4KConfigPageCustomOptions *custom_options = m_custom_options->widget()->findChild<Smb4KConfigPageCustomOptions *>();
  
  if (!enable && custom_options && custom_options->customSettingsMaybeChanged())
  {
    QList<OptionsPtr> new_list = custom_options->getCustomOptions();
    QList<OptionsPtr> old_list = Smb4KCustomOptionsManager::self()->customOptions();
    
    if (new_list.size() == old_list.size())
    {
      for (const OptionsPtr &no : new_list)
      {
        for (const OptionsPtr &oo : old_list)
        {
          if (!no->equals(oo.data()))
          {
            enable = true;
            break;
          }
          else
          {
            // Do nothing
          }
        }
        
        if (enable)
        {
          break;
        }
        else
        {
          // Do nothing
        }
      }
    }
    else
    {
      enable = true;
    }
  }
  else
  {
    // Do nothing
  }

  QPushButton *applyButton = buttonBox()->button(QDialogButtonBox::Apply);
  
  if (applyButton)
  {
    applyButton->setEnabled(enable);
  }
  else
  {
    // Do nothing
  }
}


void Smb4KConfigDialog::slotCheckPage(KPageWidgetItem* /*current*/, KPageWidgetItem* before)
{
  if (before == m_user_interface)
  {
    // Nothing to do
  }
  else if (before == m_network)
  {
    (void)checkNetworkPage();
  }
#if !defined(SMB4K_UNSUPPORTED_PLATFORM)
  else if (before == m_mounting)
  {
    (void)checkMountingPage();
  }
#endif
  else if (before == m_authentication)
  {
    // Do nothing
  }
  else if (before == m_synchronization)
  {
    (void)checkSynchronizationPage();
  }
  else if (before == m_custom_options)
  {
    // Do nothing
  }
  else if (before == m_profiles)
  {
    // Do nothing
  }
  else
  {
    // Do nothing
  }
}

#include "smb4kconfigdialog.moc"
