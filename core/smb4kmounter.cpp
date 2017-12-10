/***************************************************************************
    The core class that mounts the shares.
                             -------------------
    begin                : Die Jun 10 2003
    copyright            : (C) 2003-2017 by Alexander Reinholdt
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

// Application specific includes
#include "smb4kmounter.h"
#include "smb4kmounter_p.h"
#include "smb4kauthinfo.h"
#include "smb4kshare.h"
#include "smb4ksettings.h"
#include "smb4khomesshareshandler.h"
#include "smb4kwalletmanager.h"
#include "smb4kprocess.h"
#include "smb4knotification.h"
#include "smb4kbookmarkhandler.h"
#include "smb4kcustomoptionsmanager.h"
#include "smb4kcustomoptions.h"
#include "smb4kbookmark.h"
#include "smb4kprofilemanager.h"
#include "smb4khardwareinterface.h"

#if defined(Q_OS_LINUX)
#include "smb4kmountsettings_linux.h"
#elif defined(Q_OS_FREEBSD) || defined(Q_OS_NETBSD)
#include "smb4kmountsettings_freebsd.h"
#endif

// Qt includes
#include <QDir>
#include <QTextStream>
#include <QTextCodec>
#include <QTimer>
#include <QFileInfo>
#include <QDebug>
#include <QApplication>
#include <QTest>
#include <QUdpSocket>

// KDE includes
#define TRANSLATION_DOMAIN "smb4k-core"
#include <KCoreAddons/KShell>
#include <KCoreAddons/KUser>
#include <KIOCore/KIO/Global>
#include <KIOCore/KIO/StatJob>
#include <KIOCore/KMountPoint>
#include <KIOCore/KDiskFreeSpaceInfo>
#include <KI18n/KLocalizedString>
#include <KWidgetsAddons/KMessageBox>
#include <KAuth/KAuthExecuteJob>

using namespace Smb4KGlobal;

#define TIMEOUT 50

Q_GLOBAL_STATIC(Smb4KMounterStatic, p);



Smb4KMounter::Smb4KMounter(QObject *parent)
: KCompositeJob(parent), d(new Smb4KMounterPrivate)
{
  setAutoDelete(false);

  if (!coreIsInitialized())
  {
    setDefaultSettings();
  }
  else
  {
    // Do nothing
  }

  d->timerId = -1;
  d->remountTimeout = 0;
  d->remountAttempts = 0;
  d->checkTimeout = 0;
  d->newlyMounted = 0;
  d->newlyUnmounted = 0;
  d->dialog = 0;
  d->firstImportDone = false;
  d->mountShares = false;
  d->unmountShares = false;
  d->activeProfile = Smb4KProfileManager::self()->activeProfile();
  d->detectAllShares = Smb4KSettings::detectAllShares();

  connect(QCoreApplication::instance(), SIGNAL(aboutToQuit()),
          this, SLOT(slotAboutToQuit()));
  
  connect(Smb4KHardwareInterface::self(), SIGNAL(networkConfigUpdated()), 
          this, SLOT(slotStartJobs()));
  
  connect(Smb4KHardwareInterface::self(), SIGNAL(onlineStateChanged(bool)),
          this, SLOT(slotOnlineStateChanged(bool)));
  
  connect(Smb4KHardwareInterface::self(), SIGNAL(networkShareAdded()),
          this, SLOT(slotTriggerImport()));
  
  connect(Smb4KHardwareInterface::self(), SIGNAL(networkShareRemoved()),
          this, SLOT(slotTriggerImport()));
  
  connect(Smb4KProfileManager::self(), SIGNAL(migratedProfile(QString,QString)),
          this, SLOT(slotProfileMigrated(QString,QString)));
  
  connect(Smb4KProfileManager::self(), SIGNAL(activeProfileChanged(QString)),
          this, SLOT(slotActiveProfileChanged(QString)));
  
  connect(Smb4KSettings::self(), SIGNAL(configChanged()),
          this, SLOT(slotConfigChanged()));
}


Smb4KMounter::~Smb4KMounter()
{
  while (!d->importedShares.isEmpty())
  {
    d->importedShares.takeFirst().clear();
  }

  while (!d->retries.isEmpty())
  {
    d->retries.takeFirst().clear();
  }
}


Smb4KMounter *Smb4KMounter::self()
{
  return &p->instance;
}


void Smb4KMounter::abortAll()
{
  if (!QCoreApplication::closingDown())
  {
    QListIterator<KJob *> it(subjobs());
    
    while (it.hasNext())
    {
      it.next()->kill(KJob::EmitResult);
    }
  }
  else
  {
    // Do nothing
  }
}


bool Smb4KMounter::isRunning()
{
  return hasSubjobs();
}


void Smb4KMounter::triggerRemounts(bool fill_list)
{
  if (Smb4KSettings::remountShares() /* one-time remounts */ || 
      !Smb4KCustomOptionsManager::self()->sharesToRemount().isEmpty() /* permanent remounts */)
  {
    if (fill_list)
    {
      //
      // Get the shares that are to be remounted
      //
      QList<OptionsPtr> list = Smb4KCustomOptionsManager::self()->sharesToRemount();

      if (!list.isEmpty())
      {
        //
        // Check which shares actually need to be remounted
        //
        for (const OptionsPtr &opt : list)
        {
          QList<SharePtr> mountedShares = findShareByUNC(opt->unc());
          
          if (!mountedShares.isEmpty())
          {
            bool mount = true;
            
            for (const SharePtr &s : mountedShares)
            {
              if (!s->isForeign())
              {
                mount = false;
                break;
              }
              else
              {
                continue;
              }
            }
            
            if (mount)
            {
              SharePtr share = SharePtr(new Smb4KShare());
              share->setURL(opt->url());
              share->setWorkgroupName(opt->workgroupName());
              share->setHostIP(opt->ip());
              
              if (share->url().isValid() && !share->url().isEmpty())
              {
                d->remounts << share;
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
            SharePtr share = SharePtr(new Smb4KShare());
            share->setURL(opt->url());
            share->setWorkgroupName(opt->workgroupName());
            share->setHostIP(opt->ip());
              
            if (share->url().isValid() && !share->url().isEmpty())
            {
              d->remounts << share;
            }
            else
            {
              // Do nothing
            }
          }
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
    
    if (!d->remounts.isEmpty())
    {
      mountShares(d->remounts);
    }
    else
    {
      // Do nothing
    }

    d->remountAttempts++;
  }
  else
  {
    // Do nothing
  }
}


void Smb4KMounter::import(bool checkInaccessible)
{
  //
  // Immediately return here if we are still processing imported shares
  //
  if (!d->importedShares.isEmpty())
  {
    return;
  }
  else
  {
    // Do nothing
  }
  
  //
  // Get the mountpoints that are present on the system
  //
  KMountPoint::List mountPoints = KMountPoint::currentMountPoints(KMountPoint::BasicInfoNeeded|KMountPoint::NeedMountOptions);
  
  // Now determine all mountpoints that have the SMBFS or the CIFS
  // filesystem.
  for (const QExplicitlySharedDataPointer<KMountPoint> &mountPoint : mountPoints)
  {
    if (QString::compare(mountPoint->mountType(), "cifs") == 0 || QString::compare(mountPoint->mountType(), "smbfs") == 0)
    {
      // Create new share and set the mountpoint and the filesystem
      SharePtr share = SharePtr(new Smb4KShare(mountPoint->mountedFrom()));
      share->setPath(mountPoint->mountPoint());
      share->setMounted(true);
      
      // Get all mount options
      for (const QString &option : mountPoint->mountOptions())
      {
        if (option.startsWith(QLatin1String("domain=")) || option.startsWith(QLatin1String("workgroup=")))
        {
          share->setWorkgroupName(option.section('=', 1, 1).trimmed());
        }
        else if (option.startsWith(QLatin1String("addr=")))
        {
          share->setHostIP(option.section('=', 1, 1).trimmed());
        }
        else if (option.startsWith(QLatin1String("username=")) || option.startsWith(QLatin1String("user=")))
        {
          share->setLogin(option.section('=', 1, 1).trimmed());
        }
        else
        {
          // Do nothing
        }
      }
      
      // Work around empty usernames
      if (share->login().isEmpty())
      {
        share->setLogin("guest");
      }
      else
      {
        // Do nothing
      }
      
      d->importedShares << share;
    }
    else
    {
      // Do nothing
    }
  }
  
  //
  // Check which shares were unmounted. Remove all obsolete mountpoints, emit
  // the unmounted() signal on each of the unmounted shares and remove them
  // from the global list.
  // NOTE: The unmount() signal is emitted *BEFORE* the share is removed
  // from the global list! You need to account for that in your application.
  //
  QList<SharePtr> unmountedShares;
  bool found = false;
  
  for (const SharePtr &mountedShare : mountedSharesList())
  {
    for (const SharePtr &importedShare : d->importedShares)
    {
      // Check the mountpoint, since that one is unique. We will only use
      // Smb4KShare::path(), so that we do not run into trouble if a share 
      // is inaccessible.
      if (QString::compare(mountedShare->path(), importedShare->path()) == 0)
      {
        found = true;
        break;
      }
      else
      {
        // Do nothing
      }
    }
    
    if (!found)
    {
      // Remove the mountpoint if the share is not a foreign one
      if (!mountedShare->isForeign())
      {
        QDir dir;
        dir.cd(mountedShare->canonicalPath());
        dir.rmdir(dir.canonicalPath());
        
        if (dir.cdUp())
        {
          dir.rmdir(dir.canonicalPath());
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
      
      mountedShare->setMounted(false);
      unmountedShares << mountedShare;
    }
    else
    {
      // Do nothing
    }
    
    found = false;
  }
  
  if (!unmountedShares.isEmpty())
  {
    d->newlyUnmounted += unmountedShares.size();
    
    if (!d->mountShares && !d->unmountShares)
    {
      if (d->newlyUnmounted == 1)
      {
        // Copy the share
        SharePtr unmountedShare = unmountedShares.first();
        
        // Remove the share from the global list and notify the program and user
        removeMountedShare(unmountedShares.first());
        emit unmounted(unmountedShare);
        Smb4KNotification::shareUnmounted(unmountedShare);
        unmountedShare.clear();
      }
      else
      {
        for (const SharePtr &share : unmountedShares)
        {
          // Copy the share
          SharePtr unmountedShare = share;
          
          // Remove the share from the global list and notify the program
          removeMountedShare(share);
          emit unmounted(unmountedShare);
          unmountedShare.clear();
        }
        
        // Notify the user
        Smb4KNotification::sharesUnmounted(d->newlyUnmounted);
      }
      
      d->newlyUnmounted = 0;
    }
    else
    {
      for (const SharePtr &share : unmountedShares)
      {
        // Copy the share
        SharePtr unmountedShare = share;
        
        // Remove the share from the global list and notify the program
        removeMountedShare(share);
        emit unmounted(unmountedShare);
        unmountedShare.clear();
      }
    }
    
    emit mountedSharesListChanged();
  }
  else
  {
    d->newlyUnmounted = 0;
  }
  
  //
  // Now stat the imported shares to get information about them.
  // Do not use Smb4KShare::canonicalPath() here, otherwise we might
  // get lock-ups with inaccessible shares.
  //
  if (Smb4KHardwareInterface::self()->isOnline())
  {
    QMutableListIterator<SharePtr> it(d->importedShares);
    
    while (it.hasNext())
    {
      SharePtr share = it.next();
      SharePtr mountedShare = findShareByPath(share->path());
      
      if (mountedShare)
      {
        if (mountedShare->isInaccessible() && !checkInaccessible)
        {
          it.remove();
          continue;
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
      
      QUrl url = QUrl::fromLocalFile(share->path());
      KIO::StatJob *job = KIO::stat(url, KIO::HideProgressInfo);
      job->setDetails(0);
      connect(job, SIGNAL(result(KJob*)), this, SLOT(slotStatResult(KJob*)));
       
      // Do not use addSubJob(), because that would confuse isRunning(), etc.
      
      job->start();
    }
    
    if (!d->firstImportDone && d->importedShares.isEmpty())
    {
      d->firstImportDone = true;
    }
    else
    {
      // Do nothing. d->firstImportDone will be set in slotStatResult().
    }
  }
  else
  {
    // Do nothing
  }
}


void Smb4KMounter::mountShare(const SharePtr &share, QWidget *parent)
{
  Q_ASSERT(share);
  
  if (share)
  {
    //
    // Check that the URL is valid
    //
    if (!share->url().isValid())
    {
      Smb4KNotification::invalidURLPassed();
      return;
    }
    else
    {
      // Do nothing
    }
    
    //
    // Check if the share has already been mounted. If it is already present,
    // do not process it and return.
    //
    QString unc;
    
    if (share->isHomesShare())
    {
      if (!Smb4KHomesSharesHandler::self()->specifyUser(share, true, parent))
      {
        return;
      }
      else
      {
        // Do nothing
      }

      unc = share->homeUNC();      
    }
    else
    {
      unc = share->unc();
    }
    
    QList<SharePtr> mountedShares = findShareByUNC(unc);
    bool isMounted = false;
      
    for (const SharePtr &s : mountedShares)
    {
      if (!s->isForeign())
      {
        isMounted = true;
      }
      else
      {
        // Do nothing
      }
    }
    
    if (isMounted)
    {
      return;
    }
    else
    {
      // Do nothing
    }

    //
    // Wake-On-LAN: Wake up the host before mounting 
    //
    if (Smb4KSettings::enableWakeOnLAN())
    {
      OptionsPtr options = Smb4KCustomOptionsManager::self()->findOptions(KIO::upUrl(share->url()));

      if (options && options->wolSendBeforeMount())
      {
        emit aboutToStart(WakeUp);

        QUdpSocket *socket = new QUdpSocket(this);
        QHostAddress addr;

        // Use the host's IP address directly from the share object.
        if (!share->hostIP().isEmpty())
        {
          addr.setAddress(share->hostIP());
        }
        else
        {
          addr.setAddress("255.255.255.255");
        }

        // Construct magic sequence
        QByteArray sequence;

        // 6 times 0xFF
        for (int j = 0; j < 6; ++j)
        {
          sequence.append(QChar(0xFF).toLatin1());
        }

        // 16 times the MAC address
        QStringList parts = options->macAddress().split(':', QString::SkipEmptyParts);

        for (int j = 0; j < 16; ++j)
        {
          for (int k = 0; k < parts.size(); ++k)
          {
            sequence.append(QChar(QString("0x%1").arg(parts.at(k)).toInt(0, 16)).toLatin1());
          }
        }
            
        socket->writeDatagram(sequence, addr, 9);
        
        delete socket;
        
        // Wait the defined time
        int stop = 1000 * Smb4KSettings::wakeOnLANWaitingTime() / 250;
        int i = 0;
        
        while (i++ < stop)
        {
          QTest::qWait(250);
        }
        
        emit finished(WakeUp);
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
    
    // 
    // Create the mountpoint
    //
    QString mountpoint;
    mountpoint += Smb4KSettings::mountPrefix().path();
    mountpoint += QDir::separator();
    mountpoint += (Smb4KSettings::forceLowerCaseSubdirs() ? share->hostName().toLower() : share->hostName());
    mountpoint += QDir::separator();

    if (!share->isHomesShare())
    {
      mountpoint += (Smb4KSettings::forceLowerCaseSubdirs() ? share->shareName().toLower() : share->shareName());
    }
    else
    {
      mountpoint += (Smb4KSettings::forceLowerCaseSubdirs() ? share->login().toLower() : share->login());
    }
    
    // Get the permissions that should be used for creating the
    // mount prefix and all its subdirectories. 
    // Please note that the actual permissions of the mount points
    // are determined by the mount utility.
    QFile::Permissions permissions;
    QUrl parentDirectory;
      
    if (QFile::exists(Smb4KSettings::mountPrefix().path()))
    {
      parentDirectory = Smb4KSettings::mountPrefix();
    }
    else
    {
      QUrl u = Smb4KSettings::mountPrefix();
      parentDirectory = KIO::upUrl(u);
    }
      
    QFile f(parentDirectory.path());
    permissions = f.permissions();
      
    QDir dir(mountpoint);

    if (!dir.mkpath(dir.path()))
    {
      share->setPath("");
      Smb4KNotification::mkdirFailed(dir);
      return;
    }
    else
    {
      QUrl u = QUrl::fromLocalFile(dir.path());
      
      while (!parentDirectory.matches(u, QUrl::StripTrailingSlash))
      {
        QFile(u.path()).setPermissions(permissions);
        u = KIO::upUrl(u);
      }
    }
    
    share->setPath(QDir::cleanPath(mountpoint));
    
    // 
    // Get the authentication information
    //
    Smb4KWalletManager::self()->readAuthInfo(share);

    //
    // Mount arguments
    //
    QVariantMap args;
    
    if (!fillMountActionArgs(share, args))
    {
      return;
    }
    else
    {
      // Do nothing
    }
    
    //
    // Emit the aboutToStart() signal
    //
    emit aboutToStart(MountShare);

    //
    // Create the mount action
    //
    KAuth::Action mountAction("org.kde.smb4k.mounthelper.mount");
    mountAction.setHelperId("org.kde.smb4k.mounthelper");
    mountAction.setArguments(args);
    
    KAuth::ExecuteJob *job = mountAction.execute();
      
    //
    // Modify the cursor, if necessary.
    //
    if (!hasSubjobs() && modifyCursor())
    {
      QApplication::setOverrideCursor(Qt::BusyCursor);
    }
    else
    {
      // Do nothing
    }
      
    //
    // Add the job
    //
    addSubjob(job);

    //
    // Start the job and process the returned result.
    //
    bool success = job->exec();
    
    if (success)
    {
      int errorCode = job->error();
      
      if (errorCode == 0)
      {
        // Get the error message
        QString errorMsg = job->data()["mh_error_message"].toString();
        
        if (!errorMsg.isEmpty())
        {
#if defined(Q_OS_LINUX)
          if (errorMsg.contains("mount error 13") || errorMsg.contains("mount error(13)") /* authentication error */)
          {
            if (Smb4KWalletManager::self()->showPasswordDialog(share, 0))
            {
              d->retries << share;
            }
            else
            {
              // Do nothing
            }
          }
          else if (errorMsg.contains("Unable to find suitable address."))
          {
            // Swallow this
          }
          else
          {
            Smb4KNotification::mountingFailed(share, errorMsg);
          }
#elif defined(Q_OS_FREEBSD) || defined(Q_OS_NETBSD)
          if (errorMsg.contains("Authentication error") || errorMsg.contains("Permission denied"))
          {
            if (Smb4KWalletManager::self()->showPasswordDialog(share, 0))
            {
              d->retries << share;
            }
            else
            {
              // Do nothing
            }
          }
          else
          {
            Smb4KNotification::mountingFailed(share, errorMsg);
          }
#else
          qWarning() << "Smb4KMounter::slotMountJobFinished(): Error handling not implemented!";
          Smb4KNotification::mountingFailed(share.data(), errorMsg);
#endif
        }
        else
        {
          // Do nothing
        }
      }
      else
      {
        Smb4KNotification::actionFailed(errorCode);
      }
    }
    else
    {
      // FIXME: Report that the action could not be started
      // Do nothing
    }
    
    //
    // Remove the job from the job list
    //
    removeSubjob(job);
      
    //
    // Reset the busy cursor
    //
    if (!hasSubjobs() && modifyCursor())
    {
      QApplication::restoreOverrideCursor();
    }
    else
    {
      // Do nothing
    }
    
    //
    // Emit the finished() signal
    //
    emit finished(MountShare);
  }
  else
  {
    // Do nothing
  }
}


void Smb4KMounter::mountShares(const QList<SharePtr> &shares, QWidget *parent)
{
  d->mountShares = true;
  
  for (const SharePtr &share : shares)
  {
    mountShare(share, parent);
  }
  
  d->mountShares = false;
}


void Smb4KMounter::unmountShare(const SharePtr &share, bool silent, QWidget *parent)
{
  Q_ASSERT(share);
  
  if (share)
  {
    //
    // Check that the URL is valid.
    //
    if (!share->url().isValid())
    {
      Smb4KNotification::invalidURLPassed();
      return;
    }
    else
    {
      // Do nothing
    }
    
    //
    // Handle foreign shares according to the settings
    //
    if (share->isForeign())
    {
      if (!Smb4KSettings::unmountForeignShares())
      {
        if (!silent)
        {
          Smb4KNotification::unmountingNotAllowed(share);
        }
        else
        {
          // Do nothing
        }
        return;
      }
      else
      {
        if (!silent)
        {
          if (KMessageBox::warningYesNo(parent,
              i18n("<qt><p>The share <b>%1</b> is mounted to <br><b>%2</b> and owned by user <b>%3</b>.</p>"
                  "<p>Do you really want to unmount it?</p></qt>",
                  share->unc(), share->path(), share->user().loginName()),
              i18n("Foreign Share")) == KMessageBox::No)
          {
            return;
          }
          else
          {
            // Do nothing
          }
        }
        else
        {
          // Without the confirmation of the user, we are not
          // unmounting a foreign share!
          return;
        }
      }
    }
    else
    {
      // Do nothing
    }
    
    //
    // Force the unmounting of the share either if the system went offline
    // or if the user chose to forcibly unmount inaccessible shares (Linux only).
    //
    bool force = false;
    
    if (Smb4KHardwareInterface::self()->isOnline())
    {
#if defined(Q_OS_LINUX)
      if (share->isInaccessible())
      {
        force = Smb4KSettings::forceUnmountInaccessible();
      }
      else
      {
        // Do nothing
      }
#endif
    }
    else
    {
      force = true;
    }
    
    //
    // Unmount arguments
    //
    QVariantMap args;

    if (!fillUnmountActionArgs(share, force, silent, args))
    {
      return;
    }
    else
    {
      // Do nothing
    }
    
    //
    // Emit the aboutToStart() signal
    //
    emit aboutToStart(UnmountShare);

    //
    // Create the unmount action
    //
    KAuth::Action unmountAction("org.kde.smb4k.mounthelper.unmount");
    unmountAction.setHelperId("org.kde.smb4k.mounthelper");
    unmountAction.setArguments(args);
      
    KAuth::ExecuteJob *job = unmountAction.execute();
    
    //
    // Modify the cursor, if necessary.
    //
    if (!hasSubjobs() && modifyCursor())
    {
      QApplication::setOverrideCursor(Qt::BusyCursor);
    }
    else
    {
      // Do nothing
    }
      
    //
    // Add the job
    //
    addSubjob(job);

    //
    // Start the job and process the returned result.
    //
    bool success = job->exec();
    
    if (success)
    {
      int errorCode = job->error();
      
      if (errorCode == 0)
      {
        // Get the error message
        QString errorMsg = job->data()["mh_error_message"].toString();
        
        if (!errorMsg.isEmpty())
        {
          // No error handling needed, just report the error message.
          Smb4KNotification::unmountingFailed(share, errorMsg);
        }
        else
        {
          // Do nothing
        }
      }
      else
      {
        Smb4KNotification::actionFailed(errorCode);
      }

    }
    else
    {
      // FIXME: Report that the action could not be started
      // Do nothing
    }
    
    //
    // Remove the job from the job list
    //
    removeSubjob(job);
      
    //
    // Reset the busy cursor
    //
    if (!hasSubjobs() && modifyCursor())
    {
      QApplication::restoreOverrideCursor();
    }
    else
    {
      // Do nothing
    }
    
    //
    // Emit the finished() signal
    //
    emit finished(UnmountShare);
  }
  else
  {
    // Do nothing
  }
}


void Smb4KMounter::unmountShares(const QList<SharePtr> &shares, bool silent, QWidget *parent)
{
#if defined(Q_OS_LINUX)
  //
  // Under Linux, we have to take an approach that is a bit awkward in this function. 
  // Since the import function is invoked via Smb4KHardwareInterface::networkShareRemoved()
  // before mountShare() returns, no unmount of multiple shares will ever be reported
  // when d->unmountShares is set to FALSE *after* the loop ended. To make the reporting
  // work correctly, we need to set d->unmountShares to FALSE before the last unmount
  // is started.
  //
  d->unmountShares = true;
  int number = shares.size();
  
  for (const SharePtr &share : shares)
  {
    number--;
    d->unmountShares = (number != 0);
    unmountShare(share, silent, parent);
  }
#elif defined(Q_OS_FREEBSD) || defined(Q_OS_NETBSD)
  //
  // Since under FreeBSD the emission of Smb4KHardwareInterface::networkShareRemoved() is 
  // triggered by a timer, we can use a nice approach here.
  //
  d->unmountShares = true;
  
  for (const SharePtr &share : shares)
  {
    unmountShare(share, silent, parent);
  }
  
  d->unmountShares = false;
#endif
}


void Smb4KMounter::unmountAllShares(bool silent, QWidget* parent)
{
  unmountShares(mountedSharesList(), silent, parent);
}


void Smb4KMounter::openMountDialog(QWidget *parent)
{
  if (!d->dialog)
  {
    SharePtr share = SharePtr(new Smb4KShare());
    
    d->dialog = new Smb4KMountDialog(share, parent);

    if (d->dialog->exec() == QDialog::Accepted && d->dialog->validUserInput())
    {
      // Pass the share to mountShare().
      mountShare(share, parent);
      
      // Bookmark the share if the user wants this.
      if (d->dialog->bookmarkShare())
      {
        Smb4KBookmarkHandler::self()->addBookmark(share);
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

    delete d->dialog;
    d->dialog = 0;

    share.clear();
  }
  else
  {
    // Do nothing
  }
}


void Smb4KMounter::start()
{
  //
  // Check the network configurations
  //
  Smb4KHardwareInterface::self()->updateNetworkConfig();
}


void Smb4KMounter::saveSharesForRemount()
{
  //
  // Save the shares for remount
  //
  for (const SharePtr &share : mountedSharesList())
  {
    if (!share->isForeign())
    {
      Smb4KCustomOptionsManager::self()->addRemount(share, false);
    }
    else
    {
      Smb4KCustomOptionsManager::self()->removeRemount(share, false);
    }
  }
  
  //
  // Also save each failed remount and remove it from the list
  //
  while (!d->remounts.isEmpty())
  {
    SharePtr share = d->remounts.takeFirst();
    Smb4KCustomOptionsManager::self()->addRemount(share, false);
    share.clear();
  }  
}


void Smb4KMounter::timerEvent(QTimerEvent *)
{
  // Try to remount those shares that could not be mounted 
  // before. Do this only if there are no subjobs, because we
  // do not want to get crashes because a share was invalidated
  // during processing the shares.
  if ((Smb4KSettings::remountShares() || !Smb4KCustomOptionsManager::self()->sharesToRemount().isEmpty()) && 
       Smb4KSettings::remountAttempts() > d->remountAttempts)
  {
    if (d->firstImportDone && !isRunning())
    {
      if (d->remountAttempts == 0)
      {
        triggerRemounts(true);
      }
      else if (!d->remounts.isEmpty() && d->remountTimeout >= (60000 * Smb4KSettings::remountInterval()))
      {
        triggerRemounts(false);
        d->remountTimeout = -TIMEOUT;
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
    
    d->remountTimeout += TIMEOUT;
  }
  else
  {
    // Do nothing
  }
  
  // Retry mounting those shares that failed. This is also only 
  // done when there are no subjobs.
  if (!d->retries.isEmpty() && !hasSubjobs())
  {
    mountShares(d->retries);
      
    while (!d->retries.isEmpty())
    {
      d->retries.takeFirst().clear();
    }
  }
  else
  {
    // Do nothing
  }
  
  //
  // Check the size, accessibility, etc. of the shares
  // 
  // FIXME: Hopefully we can replace this with a recursive QFileSystemWatcher 
  // approach in the future. However, using the existing QFileSystemWatcher
  // and a QDirIterator to add all the subdirectories of a share to the watcher
  // seems to be too resource consuming...
  //
  if (d->checkTimeout >= 2500 && !isRunning() && d->importedShares.isEmpty())
  {
    for (const SharePtr &share : mountedSharesList())
    {
      check(share);
      emit updated(share);
    }

    d->checkTimeout = 0;
  }
  else
  {
    d->checkTimeout += TIMEOUT;
  }
}


#if defined(Q_OS_LINUX)
//
// Linux arguments
//
bool Smb4KMounter::fillMountActionArgs(const SharePtr &share, QVariantMap& map)
{
  // Find the mount program.
  const QString mount = findMountExecutable();

  if (!mount.isEmpty())
  {
    map.insert("mh_command", mount);
  }
  else
  {
    Smb4KNotification::commandNotFound("mount.cifs");
    return false;
  }

  // Mount arguments.
  QMap<QString, QString> global_options = globalSambaOptions();
  OptionsPtr options = Smb4KCustomOptionsManager::self()->findOptions(share);

  if (options)
  {
    share->setPort(options->fileSystemPort() != Smb4KMountSettings::remoteFileSystemPort() ?
                   options->fileSystemPort() : Smb4KMountSettings::remoteFileSystemPort());
  }
  else
  {
    share->setPort(Smb4KMountSettings::remoteFileSystemPort());
  }
  
  // Compile the list of arguments, that is added to the
  // mount command via "-o ...".
  QStringList args_list;
  
  // Workgroup or domain
  if (!share->workgroupName().trimmed().isEmpty())
  {
    args_list << QString("domain=%1").arg(KShell::quoteArg(share->workgroupName()));
  }
  else
  {
    // Do nothing
  }
  
  // Host IP
  if (!share->hostIP().trimmed().isEmpty())
  {
    args_list << QString("ip=%1").arg(share->hostIP());
  }
  else
  {
    // Do nothing
  }
  
  // User name
  if (!share->login().isEmpty())
  {
    args_list << QString("username=%1").arg(share->login());
  }
  else
  {
    args_list << "guest";
  }
  
  // Client's and server's NetBIOS name
  // According to the manual page, this is only needed when port 139
  // is used. So, we only pass the NetBIOS name in that case.
  if (Smb4KMountSettings::remoteFileSystemPort() == 139 || (options && options->fileSystemPort() == 139))
  {
    // The client's NetBIOS name.
    if (!Smb4KSettings::netBIOSName().isEmpty())
    {
      args_list << QString("netbiosname=%1").arg(KShell::quoteArg(Smb4KSettings::netBIOSName()));
    }
    else
    {
      if (!global_options["netbios name"].isEmpty())
      {
        args_list << QString("netbiosname=%1").arg(KShell::quoteArg(global_options["netbios name"]));
      }
      else
      {
        // Do nothing
      }
    }

    // The server's NetBIOS name.
    // ('servern' is a synonym for 'servernetbiosname')
    args_list << QString("servern=%1").arg(KShell::quoteArg(share->hostName()));
  }
  else
  {
    // Do nothing
  }
  
  // UID
  args_list << QString("uid=%1").arg(options ? options->user().userId().nativeId() : (K_UID)Smb4KMountSettings::userID().toInt());
  
  // Force user
  if (Smb4KMountSettings::forceUID())
  {
    args_list << "forceuid";
  }
  else
  {
    // Do nothing
  }
  
  // GID
  args_list << QString("gid=%1").arg(options ? options->group().groupId().nativeId() : (K_GID)Smb4KMountSettings::groupID().toInt());
  
  // Force GID
  if (Smb4KMountSettings::forceGID())
  {
    args_list << "forcegid";
  }
  else
  {
    // Do nothing
  }
  
  // Client character set
  switch (Smb4KMountSettings::clientCharset())
  {
    case Smb4KMountSettings::EnumClientCharset::default_charset:
    {
      if (!global_options["unix charset"].isEmpty())
      {
        args_list << QString("iocharset=%1").arg(global_options["unix charset"].toLower());
      }
      else
      {
        // Do nothing
      }
      break;
    }
    default:
    {
      args_list << QString("iocharset=%1")
                   .arg(Smb4KMountSettings::self()->clientCharsetItem()->choices().value(Smb4KMountSettings::clientCharset()).label);
      break;
    }
  }
  
  // Port. 
  args_list << QString("port=%1").arg(share->port());
  
  // Write access
  if (options)
  {
    switch (options->writeAccess())
    {
      case Smb4KCustomOptions::ReadWrite:
      {
        args_list << "rw";
        break;
      }
      case Smb4KCustomOptions::ReadOnly:
      {
        args_list << "ro";
        break;
      }
      default:
      {
        switch (Smb4KMountSettings::writeAccess())
        {
          case Smb4KMountSettings::EnumWriteAccess::ReadWrite:
          {
            args_list << "rw";
            break;
          }
          case Smb4KMountSettings::EnumWriteAccess::ReadOnly:
          {
            args_list << "ro";
            break;
          }
          default:
          {
            break;
          }
        }
        break;
      }
    }
  }
  else
  {
    switch (Smb4KMountSettings::writeAccess())
    {
      case Smb4KMountSettings::EnumWriteAccess::ReadWrite:
      {
        args_list << "rw";
        break;
      }
      case Smb4KMountSettings::EnumWriteAccess::ReadOnly:
      {
        args_list << "ro";
        break;
      }
      default:
      {
        break;
      }
    }
  }
  
  // File mask
  if (!Smb4KMountSettings::fileMask().isEmpty())
  {
    args_list << QString("file_mode=%1").arg(Smb4KMountSettings::fileMask());
  }
  else
  {
    // Do nothing
  }

  // Directory mask
  if (!Smb4KMountSettings::directoryMask().isEmpty())
  {
    args_list << QString("dir_mode=%1").arg(Smb4KMountSettings::directoryMask());
  }
  else
  {
    // Do nothing
  }
  
  // Permission checks
  if (Smb4KMountSettings::permissionChecks())
  {
    args_list << "perm";
  }
  else
  {
    args_list << "noperm";
  }
  
  // Client controls IDs
  if (Smb4KMountSettings::clientControlsIDs())
  {
    args_list << "setuids";
  }
  else
  {
    args_list << "nosetuids";
  }
  
  // Server inode numbers
  if (Smb4KMountSettings::serverInodeNumbers())
  {
    args_list << "serverino";
  }
  else
  {
    args_list << "noserverino";
  }
  
  // Cache mode
  switch (Smb4KMountSettings::cacheMode())
  {
    case Smb4KMountSettings::EnumCacheMode::None:
    {
      args_list << "cache=none";
      break;
    }
    case Smb4KMountSettings::EnumCacheMode::Strict:
    {
      args_list << "cache=strict";
      break;
    }
    case Smb4KMountSettings::EnumCacheMode::Loose:
    {
      args_list << "cache=loose";
      break;
    }
    default:
    {
      break;
    }
  }
  
  // Translate reserved characters
  if (Smb4KMountSettings::translateReservedChars())
  {
    args_list << "mapchars";
  }
  else
  {
    args_list << "nomapchars";
  }
  
  // Locking
  if (Smb4KMountSettings::noLocking())
  {
    args_list << "nolock";
  }
  else
  {
    // Do nothing
  }
  
  // Security mode
  if (options)
  {
    switch (options->securityMode())
    {
      case Smb4KCustomOptions::NoSecurityMode:
      {
        args_list << "sec=none";
        break;
      }
      case Smb4KCustomOptions::Krb5:
      {
        args_list << "sec=krb5";
        args_list << QString("cruid=%1").arg(KUser(KUser::UseRealUserID).userId().nativeId());
        break;
      }
      case Smb4KCustomOptions::Krb5i:
      {
        args_list << "sec=krb5i";
        args_list << QString("cruid=%1").arg(KUser(KUser::UseRealUserID).userId().nativeId());
        break;
      }
      case Smb4KCustomOptions::Ntlm:
      {
        args_list << "sec=ntlm";
        break;
      }
      case Smb4KCustomOptions::Ntlmi:
      {
        args_list << "sec=ntlmi";
        break;
      }
      case Smb4KCustomOptions::Ntlmv2:
      {
        args_list << "sec=ntlmv2";
        break;
      }
      case Smb4KCustomOptions::Ntlmv2i:
      {
        args_list << "sec=ntlmv2i";
        break;
      }
      case Smb4KCustomOptions::Ntlmssp:
      {
        args_list << "sec=ntlmssp";
        break;
      }
      case Smb4KCustomOptions::Ntlmsspi:
      {
        args_list << "sec=ntlmsspi";
        break;
      }
      default:
      {
        // Smb4KCustomOptions::DefaultSecurityMode
        break;
      }
    }
  }
  else
  {
    switch (Smb4KMountSettings::securityMode())
    {
      case Smb4KMountSettings::EnumSecurityMode::None:
      {
        args_list << "sec=none";
        break;
      }
      case Smb4KMountSettings::EnumSecurityMode::Krb5:
      {
        args_list << "sec=krb5";
        args_list << QString("cruid=%1").arg(KUser(KUser::UseRealUserID).userId().nativeId());
        break;
      }
      case Smb4KMountSettings::EnumSecurityMode::Krb5i:
      {
        args_list << "sec=krb5i";
        args_list << QString("cruid=%1").arg(KUser(KUser::UseRealUserID).userId().nativeId());
        break;
      }
      case Smb4KMountSettings::EnumSecurityMode::Ntlm:
      {
        args_list << "sec=ntlm";
        break;
      }
      case Smb4KMountSettings::EnumSecurityMode::Ntlmi:
      {
        args_list << "sec=ntlmi";
        break;
      }
      case Smb4KMountSettings::EnumSecurityMode::Ntlmv2:
      {
        args_list << "sec=ntlmv2";
        break;
      }
      case Smb4KMountSettings::EnumSecurityMode::Ntlmv2i:
      {
        args_list << "sec=ntlmv2i";
        break;
      }
      case Smb4KMountSettings::EnumSecurityMode::Ntlmssp:
      {
        args_list << "sec=ntlmssp";
        break;
      }
      case Smb4KMountSettings::EnumSecurityMode::Ntlmsspi:
      {
        args_list << "sec=ntlmsspi";
        break;
      }
      default:
      {
        // Smb4KSettings::EnumSecurityMode::Default,
        break;
      }
    }
  }
  
  // SMB protocol version
  switch (Smb4KMountSettings::smbProtocolVersion())
  {
    case Smb4KMountSettings::EnumSmbProtocolVersion::OnePointZero:
    {
      args_list << "vers=1.0";
      break;
    }
    case Smb4KMountSettings::EnumSmbProtocolVersion::TwoPointZero:
    {
      args_list << "vers=2.0";
      break;
    }
    case Smb4KMountSettings::EnumSmbProtocolVersion::TwoPointOne:
    {
      args_list << "vers=2.1";
      break;
    }
    case Smb4KMountSettings::EnumSmbProtocolVersion::ThreePointZero:
    {
      args_list << "vers=3.0";
      break;
    }
    default:
    {
      break;
    }
  }
    
  // Global custom options provided by the user
  if (!Smb4KMountSettings::customCIFSOptions().isEmpty())
  {
    // SECURITY: Only pass those arguments to mount.cifs that do not pose
    // a potential security risk and that have not already been defined.
    //
    // This is, among others, the proper fix to the security issue reported
    // by Heiner Markert (aka CVE-2014-2581).
    QStringList whitelist = whitelistedMountArguments();
    QStringList list = Smb4KMountSettings::customCIFSOptions().split(',', QString::SkipEmptyParts);
    QMutableStringListIterator it(list);
    
    while (it.hasNext())
    {
      QString arg = it.next().section("=", 0, 0);
      
      if (!whitelist.contains(arg))
      {
        it.remove();
      }
      else
      {
        // Do nothing
      }
      
      args_list += list;
    }
  }
  else
  {
    // Do nothing
  }
  
  // Mount options
  QStringList mh_options;
  mh_options << "-o";
  mh_options << args_list.join(",");
  map.insert("mh_options", mh_options);
  
  // Mount point
  map.insert("mh_mountpoint", share->canonicalPath());
  
  if (!share->isHomesShare())
  {
    map.insert("mh_url", share->url());
    map.insert("mh_unc", share->unc());
  }
  else
  {
    map.insert("mh_url", share->homeURL());
    map.insert("mh_homes_url", share->url());
    map.insert("mh_unc", share->homeUNC());
    map.insert("mh_homes_unc", share->unc());
  }  

  map.insert("mh_workgroup", share->workgroupName());
  map.insert("mh_ip", share->hostIP());

  // The path to the Kerberos ticket is stored - if it exists - in the
  // KRB5CCNAME environment variable. By default, the ticket is located
  // at /tmp/krb5cc_[uid]. So, if the environment variable does not exist,
  // but the cache file is there, try to use it.
  if (QProcessEnvironment::systemEnvironment().contains("KRB5CCNAME"))
  {
    map.insert("mh_krb5ticket", QProcessEnvironment::systemEnvironment().value("KRB5CCNAME", ""));
  }
  else
  {
    QString ticket = QString("/tmp/krb5cc_%1").arg(KUser(KUser::UseRealUserID).userId().nativeId());
    
    if (QFile::exists(ticket))
    {
      map.insert("mh_krb5ticket", "FILE:"+ticket);
    }
    else
    {
      // Do nothing
    }
  }
  
  return true;
}
#elif defined(Q_OS_FREEBSD) || defined(Q_OS_NETBSD)
//
// FreeBSD and NetBSD arguments
//
bool Smb4KMounter::fillMountActionArgs(const SharePtr &share, QVariantMap& map)
{
  // Find the mount program.
  const QString mount = findMountExecutable();

  if (!mount.isEmpty())
  {
    map.insert("mh_command", mount);
  }
  else
  {
    Smb4KNotification::commandNotFound("mount_smbfs");
    return false;
  }
  
  // Mount arguments.
  QMap<QString, QString> global_options = globalSambaOptions();
  Smb4KCustomOptions *options  = Smb4KCustomOptionsManager::self()->findOptions(share);

  // Compile the list of arguments.
  QStringList args_list;
  
  // Workgroup
  if (!share->workgroupName().isEmpty())
  {
    args_list << "-W";
    args_list << KShell::quoteArg(share->workgroupName());
  }
  else
  {
    // Do nothing
  }
  
  // Host IP
  if (!share->hostIP().isEmpty())
  {
    args_list << "-I";
    args_list << share->hostIP();
  }
  else
  {
    // Do nothing
  }
  
  // UID 
  args_list << "-u";
  args_list << QString("%1").arg(options ? options->user().userId().nativeId() : (K_UID)Smb4KMountSettings::userID().toInt());
  
  // GID 
  args_list << "-g";
  args_list << QString("%1").arg(options ? options->group().groupId().nativeId() : (K_GID)Smb4KMountSettings::groupID().toInt());
  
  // Character sets for the client and server
  QString client_charset, server_charset;

  switch (Smb4KMountSettings::clientCharset())
  {
    case Smb4KMountSettings::EnumClientCharset::default_charset:
    {
      client_charset = global_options["unix charset"].toLower(); // maybe empty
      break;
    }
    default:
    {
      client_charset = Smb4KMountSettings::self()->clientCharsetItem()->choices().value(Smb4KMountSettings::clientCharset()).label;
      break;
    }
  }

  switch (Smb4KMountSettings::serverCodepage())
  {
    case Smb4KMountSettings::EnumServerCodepage::default_codepage:
    {
      server_charset = global_options["dos charset"].toLower(); // maybe empty
      break;
    }
    default:
    {
      server_charset = Smb4KMountSettings::self()->serverCodepageItem()->choices().value(Smb4KMountSettings::serverCodepage()).label;
      break;
    }
  }

  if (!client_charset.isEmpty() && !server_charset.isEmpty())
  {
    args_list << "-E";
    args_list << QString("%1:%2").arg(client_charset, server_charset);
  }
  else
  {
    // Do nothing
  }
  
  // File mask
  if (!Smb4KMountSettings::fileMask().isEmpty())
  {
    args_list << "-f";
    args_list << QString("%1").arg(Smb4KMountSettings::fileMask());
  }
  else
  {
    // Do nothing
  }

  // Directory mask
  if (!Smb4KMountSettings::directoryMask().isEmpty())
  {
    args_list << "-d";
    args_list << QString("%1").arg(Smb4KMountSettings::directoryMask());
  }
  else
  {
    // Do nothing
  }
  
  // User name
  if (!share->login().isEmpty())
  {
    args_list << "-U";
    args_list << QString("%1").arg(share->login());
  }
  else
  {
    args_list << "-N";
  }
  
  // Mount options
  map.insert("mh_options", args_list);
  
  // Mount point
  map.insert("mh_mountpoint", share->canonicalPath());
  
  if (!share->isHomesShare())
  {
    map.insert("mh_url", share->url());
    map.insert("mh_unc", share->unc());
  }
  else
  {
    map.insert("mh_url", share->homeURL());
    map.insert("mh_homes_url", share->url());
    map.insert("mh_unc", share->homeUNC());
    map.insert("mh_homes_unc", share->unc());
  }  

  map.insert("mh_workgroup", share->workgroupName());
  map.insert("mh_ip", share->hostIP());
  
  return true;
}
#else
//
// Dummy 
//
bool Smb4KMounter::fillMountActionArgs(const SharePtr &, QVariantMap&)
{
  qWarning() << "Smb4KMounter::fillMountActionArgs() is not implemented!";
  qWarning() << "Mounting under this operating system is not supported...";
  return false;
}
#endif


#if defined(Q_OS_LINUX)
//
// Linux arguments
//
bool Smb4KMounter::fillUnmountActionArgs(const SharePtr &share, bool force, bool silent, QVariantMap &map)
{
  //
  // The umount program
  //
  const QString umount = findUmountExecutable();

  if (umount.isEmpty() && !silent)
  {
    Smb4KNotification::commandNotFound("umount");
    return false;
  }
  else
  {
    // Do nothing
  }
  
  //
  // The options
  //
  QStringList options;

  if (force)
  {
    options << "-l"; // lazy unmount
  }
  else
  {
    // Do nothing
  }

  //
  // Insert data into the map
  //
  map.insert("mh_command", umount);
  map.insert("mh_url", share->url());
  map.insert("mh_unc", share->unc());
  if (Smb4KHardwareInterface::self()->isOnline())
  {
    map.insert("mh_mountpoint", share->canonicalPath());
  }
  else
  {
    map.insert("mh_mountpoint", share->path());
  }
  map.insert("mh_options", options);
  
  return true;
}
#elif defined(Q_OS_FREEBSD) || defined(Q_OS_NETBSD)
//
// FreeBSD and NetBSD arguments
//
bool Smb4KMounter::fillUnmountActionArgs(const SharePtr &share, bool force, bool silent, QVariantMap &map)
{
  //
  // The umount program
  //
  const QString umount = findUmountExecutable();

  if (umount.isEmpty() && !silent)
  {
    Smb4KNotification::commandNotFound("umount");
    return false;
  }
  else
  {
    // Do nothing
  }

  //
  // The options
  //
  QStringList options;
  
  if (force)
  {
    options << "-f";
  }
  else
  {
    // Do nothing
  }

  //
  // Insert data into the map
  //
  map.insert("mh_command", umount);
  map.insert("mh_url", share->url());
  map.insert("mh_unc", share->unc());
  if (Smb4KHardwareInterface::self()->isOnline())
  {
    map.insert("mh_mountpoint", share->canonicalPath());
  }
  else
  {
    map.insert("mh_mountpoint", share->path());
  }
  map.insert("mh_options", options);
  
  return true;
}
#else
//
// Dummy
//
bool Smb4KMounter::fillUnmountActionArgs(const SharePtr &, bool, bool, QVariantMap &)
{
  qWarning() << "Smb4KMounter::fillUnmountActionArgs() is not implemented!";
  qWarning() << "Unmounting under this operating system is not supported...";
  return false;
}
#endif


void Smb4KMounter::check(const SharePtr &share)
{
  // Get the info about the usage, etc.
  KDiskFreeSpaceInfo spaceInfo = KDiskFreeSpaceInfo::freeSpaceInfo(share->path());
    
  if (spaceInfo.isValid())
  {
    // Accessibility
    share->setInaccessible(false);
       
    // Size information
    share->setFreeDiskSpace(spaceInfo.available());
    share->setTotalDiskSpace(spaceInfo.size());
    share->setUsedDiskSpace(spaceInfo.used());
      
    // Get the owner an group, if possible.
    QFileInfo fileInfo(share->path());
    fileInfo.setCaching(false);

    if (fileInfo.exists())
    {
      share->setUser(KUser(static_cast<K_UID>(fileInfo.ownerId())));
      share->setGroup(KUserGroup(static_cast<K_GID>(fileInfo.groupId())));
      share->setInaccessible(!(fileInfo.isDir() && fileInfo.isExecutable()));
    }
    else
    {
      share->setInaccessible(true);
      share->setFreeDiskSpace(0);
      share->setTotalDiskSpace(0);
      share->setUsedDiskSpace(0);
      share->setUser(KUser(KUser::UseRealUserID));
      share->setGroup(KUserGroup(KUser::UseRealUserID));
    }
  }
  else
  {
    share->setInaccessible(true);
    share->setFreeDiskSpace(0);
    share->setTotalDiskSpace(0);
    share->setUsedDiskSpace(0);
    share->setUser(KUser(KUser::UseRealUserID));
    share->setGroup(KUserGroup(KUser::UseRealUserID));
  } 
}



/////////////////////////////////////////////////////////////////////////////
// SLOT IMPLEMENTATIONS
/////////////////////////////////////////////////////////////////////////////


void Smb4KMounter::slotStartJobs()
{
  //
  // Import the mounted shares
  //
  if (!d->firstImportDone)
  {
    import(true);
  }
  else
  {
    // Do nothing
  }
  
  //
  // Start the timer
  //
  if (d->timerId == -1)
  {
    d->timerId = startTimer(TIMEOUT);
  }
  else
  {
    // Do nothing
  }
}


void Smb4KMounter::slotAboutToQuit()
{
  //
  // Abort any actions
  //
  abortAll();

  //
  // Check if the user wants to remount shares and save the
  // shares for remount if so.
  //
  if (Smb4KSettings::remountShares())
  {
    saveSharesForRemount();
  }
  else
  {
    // Do nothing
  }

  //
  // Unmount the shares if the user chose to do so.
  //
  if (Smb4KSettings::unmountSharesOnExit())
  {
    unmountAllShares(true, 0);
  }
  else
  {
    // Do nothing
  }

  //
  // Clean up the mount prefix.
  //
  KMountPoint::List mountPoints = KMountPoint::currentMountPoints(KMountPoint::BasicInfoNeeded|KMountPoint::NeedMountOptions);
  
  QDir dir;
  dir.cd(Smb4KSettings::mountPrefix().path());
  QStringList hostDirs = dir.entryList(QDir::Dirs|QDir::NoDotAndDotDot, QDir::NoSort);
  QStringList mountpoints;
  
  for (const QString &hostDir : hostDirs)
  {
    dir.cd(hostDir);
    
    QStringList shareDirs = dir.entryList(QDir::Dirs|QDir::NoDotAndDotDot, QDir::NoSort);
    
    for (const QString &shareDir : shareDirs)
    {
      dir.cd(shareDir);
      mountpoints << dir.absolutePath();
      dir.cdUp();
    }
    
    dir.cdUp();
  }
  
  // Remove those mountpoints where a share is actually mounted.
  for (const QExplicitlySharedDataPointer<KMountPoint> &mountPoint : mountPoints)
  {
    mountpoints.removeOne(mountPoint->mountPoint());
  }
  
  // Remove the empty mountpoints.
  for (const QString &mp : mountpoints)
  {
    dir.cd(mp);
    dir.rmdir(dir.canonicalPath());
    
    if (dir.cdUp())
    {
      dir.rmdir(dir.canonicalPath());
    }
    else
    {
      // Do nothing
    }
  }
}


void Smb4KMounter::slotOnlineStateChanged(bool online)
{
  if (online)
  {
    // Remount shares after the network became available (again)
    // If the computer awakes from a sleep state, there might still be 
    // an unmount job in the queue. So, wait until all jobs have been
    // performed before starting to remount the shares.
    while (isRunning())
    {
      QTest::qWait(TIMEOUT);
    }
    
    triggerRemounts(true);
  }
  else
  {
    // Abort all running mount jobs
    abortAll();
    
    // Mark all mounted shares as inaccessible
    for (const SharePtr &share : mountedSharesList())
    {
      share->setInaccessible(true);
    }
    
    // Save the shares for automatic remounting
    saveSharesForRemount();
    
    // Unmount all shares
    unmountAllShares(true, 0);
  }
}


void Smb4KMounter::slotStatResult(KJob *job)
{
  Q_ASSERT(job);
  
  //
  // Stat job
  //
  KIO::StatJob *statJob = static_cast<KIO::StatJob *>(job);
  
  //
  // Get the mountpoint
  //
  QString mountpoint = statJob->url().toDisplayString(QUrl::PreferLocalFile);
  
  //
  // Find the imported share
  //
  SharePtr importedShare;
  
  for (int i = 0; i < d->importedShares.size(); ++i)
  {
    if (QString::compare(d->importedShares.at(i)->path(), mountpoint) == 0)
    {
      importedShare = d->importedShares.takeAt(i);
      break;
    }
    else
    {
      continue;
    }
  }
  
  //
  // If the share should have vanished in the meantime, return here.
  //
  if (!importedShare)
  {
    return;
  }
  else
  {
    // Do nothing
  }
  
  //
  // Add the size, user and group information
  //
  if (statJob->error() == 0 /* no error */)
  {
    check(importedShare);
  }
  else
  {
    importedShare->setInaccessible(true);
    importedShare->setFreeDiskSpace(0);
    importedShare->setTotalDiskSpace(0);
    importedShare->setUsedDiskSpace(0);
    importedShare->setUser(KUser(KUser::UseRealUserID));
    importedShare->setGroup(KUserGroup(KUser::UseRealUserID));    
  }
  
  //
  // Is this a mount done by the user or by someone else?
  // Make an educated guess...
  // 
  if ((importedShare->user().userId() == KUser(KUser::UseRealUserID).userId() &&
       importedShare->group().groupId() == KUserGroup(KUser::UseRealUserID).groupId()) ||
      importedShare->path().startsWith(Smb4KSettings::mountPrefix().path()) ||
      importedShare->path().startsWith(QDir::homePath()) ||
      importedShare->canonicalPath().startsWith(QDir(Smb4KSettings::mountPrefix().path()).canonicalPath()) ||
      importedShare->canonicalPath().startsWith(QDir::home().canonicalPath()))
  {
    // Same UID and GID
    importedShare->setForeign(false);
  }
  else
  {
    importedShare->setForeign(true);
  }
  
  //
  // Search for a previously added mounted share and try to update it. If this fails,
  // add the share to the global list.
  //
  if (!importedShare->isForeign() || Smb4KSettings::detectAllShares())
  {
    if (updateMountedShare(importedShare))
    {
      SharePtr updatedShare = findShareByPath(importedShare->path());
      
      if (updatedShare)
      {
        emit updated(updatedShare);
      }
      else
      {
        // Do nothing
      }
      
      importedShare.clear();
    }
    else
    {
      if (addMountedShare(importedShare))
      {
        // Remove the share from the list of shares that are to be remounted
        QMutableListIterator<SharePtr> s(d->remounts);

        while (s.hasNext())
        {
          SharePtr remount = s.next();

          if (!importedShare->isForeign() && QString::compare(remount->unc(), importedShare->unc(), Qt::CaseInsensitive) == 0)
          {
            Smb4KCustomOptionsManager::self()->removeRemount(remount);
            s.remove();
            break;
          }
          else
          {
            continue;
          }
        }
        
        // Tell the program and the user that the share was mounted. Also, reset the
        // counter of newly mounted shares, if necessary.
        d->newlyMounted += 1;
        emit mounted(importedShare);
        
        if (d->importedShares.isEmpty() && !d->mountShares && !d->unmountShares)
        {
          if (d->firstImportDone)
          {
            if (d->newlyMounted == 1)
            {
              Smb4KNotification::shareMounted(importedShare);
            }
            else
            {
              Smb4KNotification::sharesMounted(d->newlyMounted);
            }
          }
          else
          {
            // Do nothing
          }
          
          d->newlyMounted = 0;
        }
        else
        {
          // Do nothing
        }
        
        emit mountedSharesListChanged();
      }
      else
      {
        importedShare.clear();
      }
    }
  }
  else
  {
    importedShare.clear();
  }
  
  if (!d->firstImportDone && d->importedShares.isEmpty())
  {
    d->firstImportDone = true;
  }
  else
  {
    // Do nothing
  }
}


void Smb4KMounter::slotActiveProfileChanged(const QString &newProfile)
{
  if (QString::compare(d->activeProfile, newProfile) != 0)
  {
    // Stop the timer.
    killTimer(d->timerId);

    // Check if the user wants to remount shares and save the
    // shares for remount if so.
    if (Smb4KSettings::remountShares())
    {
      saveSharesForRemount();
    }
    else
    {
      // Do nothing
    }
    
    abortAll();
    
    // Clear all remounts.
    while (!d->remounts.isEmpty())
    {
      d->remounts.takeFirst().clear();
    }
    
    // Clear all retries.
    while (!d->retries.isEmpty())
    {
      d->retries.takeFirst().clear();
    }
    
    // Unmount all shares and wait until done.
    unmountAllShares(true, 0);
    
    // Reset some variables.
    d->remountTimeout = 0;
    d->remountAttempts = 0;
    d->firstImportDone = false;
    d->activeProfile = newProfile;
    
    // Start the timer again.
    d->timerId = startTimer(TIMEOUT);
  }
  else
  {
    // Do nothing
  }
}


void Smb4KMounter::slotProfileMigrated(const QString& from, const QString& to)
{
  if (QString::compare(from, d->activeProfile, Qt::CaseSensitive) == 0)
  {
    d->activeProfile = to;
  }
  else
  {
    // Do nothing
  }
}


void Smb4KMounter::slotTriggerImport()
{
  // Wait until there are no jobs anymore
  while(isRunning())
  {
    QTest::qWait(TIMEOUT);
  }
  
  // Initialize an import
  import(true);
}


void Smb4KMounter::slotConfigChanged()
{
  if (d->detectAllShares != Smb4KSettings::detectAllShares())
  {
    slotTriggerImport();
    d->detectAllShares = Smb4KSettings::detectAllShares();
  }
  else
  {
    // Do nothing
  }
}



