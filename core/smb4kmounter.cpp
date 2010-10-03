/***************************************************************************
    smb4kmounter.cpp  -  The core class that mounts the shares.
                             -------------------
    begin                : Die Jun 10 2003
    copyright            : (C) 2003-2010 by Alexander Reinholdt
    email                : dustpuppy@users.berlios.de
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
 *   Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,   *
 *   MA  02111-1307 USA                                                    *
 ***************************************************************************/

// Qt includes
#include <QApplication>
#include <QDir>
#include <QTextStream>
#include <QTextCodec>
#include <QDesktopWidget>
#ifdef __FreeBSD__
#include <QFileInfo>
#endif

// KDE includes
#include <kapplication.h>
#include <klocale.h>
#include <kdebug.h>
#include <kmessagebox.h>
#include <kshell.h>
#include <kstandarddirs.h>
#include <kmountpoint.h>
#include <kiconloader.h>

// system includes
#ifdef __FreeBSD__
#include <pwd.h>
#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/mount.h>
#else
#include <stdio.h>
#include <mntent.h>
#endif

// Application specific includes
#include <smb4kmounter.h>
#include <smb4kauthinfo.h>
#include <smb4ksambaoptionsinfo.h>
#include <smb4kglobal.h>
#include <smb4ksambaoptionshandler.h>
#include <smb4kshare.h>
#include <smb4ksettings.h>
#include <smb4kdefs.h>
#include <smb4khomesshareshandler.h>
#include <smb4kmounter_p.h>
#include <smb4kwalletmanager.h>
#include <smb4kprocess.h>
#include <smb4knotification.h>

using namespace Smb4KGlobal;

K_GLOBAL_STATIC( Smb4KMounterPrivate, priv );



Smb4KMounter::Smb4KMounter() : QObject()
{
  m_timer_id = -1;
  m_timeout = 0;

  connect( kapp,                        SIGNAL( aboutToQuit() ),
           this,                        SLOT( slotAboutToQuit() ) );

  connect( Smb4KSolidInterface::self(), SIGNAL( buttonPressed( Smb4KSolidInterface::ButtonType ) ),
           this,                        SLOT( slotHardwareButtonPressed( Smb4KSolidInterface::ButtonType ) ) );

  connect( Smb4KSolidInterface::self(), SIGNAL( wokeUp() ),
           this,                        SLOT( slotComputerWokeUp() ) );

  connect( Smb4KSolidInterface::self(), SIGNAL( networkStatusChanged( Smb4KSolidInterface::ConnectionStatus ) ),
           this,                        SLOT( slotNetworkStatusChanged( Smb4KSolidInterface::ConnectionStatus ) ) );
}


Smb4KMounter::~Smb4KMounter()
{
}


Smb4KMounter *Smb4KMounter::self()
{
  return &priv->instance;
}


void Smb4KMounter::init()
{
  m_timeout = Smb4KSettings::checkInterval();
  m_timer_id = startTimer( m_timeout );

  import();

  if ( Smb4KSolidInterface::self()->networkStatus() == Smb4KSolidInterface::Connected ||
       Smb4KSolidInterface::self()->networkStatus() == Smb4KSolidInterface::Unknown )
  {
    priv->setHardwareReason( false );
    triggerRemounts();
  }
  else
  {
    // Do nothing and wait until the network becomes available.
  }
}


void Smb4KMounter::abort( Smb4KShare *share )
{
  Q_ASSERT( share );

  BasicMountThread *thread = NULL;
  
  if ( !share->isHomesShare() )
  {
    thread = m_cache.object( share->unc( QUrl::None ) );
  }
  else
  {
    thread = m_cache.object( share->homeUNC( QUrl::None ) );
  }
  
  if ( thread && thread->process() &&
       (thread->process()->state() == KProcess::Running || thread->process()->state() == KProcess::Starting) )
  {
    if ( Smb4KSettings::alwaysUseSuperUser() ||
         (Smb4KSettings::useForceUnmount() && thread->process()->type() == Smb4KProcess::Unmount) )
    {
      // Find smb4k_kill program
      QString smb4k_kill = KGlobal::dirs()->findResource( "exe", "smb4k_kill" );

      if ( smb4k_kill.isEmpty() )
      {
        Smb4KNotification *notification = new Smb4KNotification();
        notification->commandNotFound( "smb4k_kill" );
        return;
      }
      else
      {
        // Do nothing
      }

      // Find sudo program
      QString sudo;
      
      if ( Smb4KSettings::useKdeSudo() && !KStandardDirs::findExe( "kdesudo" ).isEmpty() )
      {
        sudo = KStandardDirs::findExe( "kdesudo" );
        sudo += " -d";
        sudo += QString( " --comment \"%1\"" ).arg( i18n( "<b>smb4k_kill</b> needs administrative privileges. "
                                                          "Please enter your password." ) );
      }
      else
      {
        sudo = KStandardDirs::findExe( "sudo" );
      }

      if ( sudo.isEmpty() )
      {
        if ( Smb4KSettings::useKdeSudo() )
        {
          Smb4KNotification *notification = new Smb4KNotification();
          notification->commandNotFound( "kdesudo" );
        }
        else
        {
          Smb4KNotification *notification = new Smb4KNotification();
          notification->commandNotFound( "sudo" );
        }
        return;
      }
      else
      {
        // Do nothing
      }

      Smb4KProcess kill_proc( Smb4KProcess::Kill, this );
      kill_proc.setShellCommand( sudo+" "+smb4k_kill+" "+QString( thread->process()->pid() ) );
      kill_proc.setOutputChannelMode( KProcess::MergedChannels );
      kill_proc.start();
      kill_proc.waitForFinished( -1 );

      // Tell the process that it was just killed/aborted.
      thread->process()->abort();
    }
    else
    {
      thread->process()->abort();
    }
  }
  else
  {
    // Do nothing
  }
}


bool Smb4KMounter::isAborted( Smb4KShare *share )
{
  Q_ASSERT( share );
  
  BasicMountThread *thread = NULL;
  
  if ( !share->isHomesShare() )
  {
    thread = m_cache.object( share->unc( QUrl::None ) );
  }
  else
  {
    thread = m_cache.object( share->homeUNC( QUrl::None ) );
  }
  
  return (thread && thread->process() && thread->process()->isAborted());
}


void Smb4KMounter::abortAll()
{
  if ( !kapp->closingDown() )
  {
    QStringList keys = m_cache.keys();
    
    foreach ( const QString &key, keys )
    {
      BasicMountThread *thread = m_cache.object( key );
      
      if ( thread && thread->process() &&
            (thread->process()->state() == KProcess::Running || thread->process()->state() == KProcess::Starting) )
      {
        if ( Smb4KSettings::alwaysUseSuperUser() ||
            (Smb4KSettings::useForceUnmount() && thread->process()->type() == Smb4KProcess::Unmount) )
        {
          // Find smb4k_kill program
          QString smb4k_kill = KGlobal::dirs()->findResource( "exe", "smb4k_kill" );

          if ( smb4k_kill.isEmpty() )
          {
            Smb4KNotification *notification = new Smb4KNotification();
            notification->commandNotFound( "smb4k_kill" );
            return;
          }
          else
          {
            // Do nothing
          }

          // Find sudo program
          QString sudo;
      
          if ( Smb4KSettings::useKdeSudo() && !KStandardDirs::findExe( "kdesudo" ).isEmpty() )
          {
            sudo = KStandardDirs::findExe( "kdesudo" );
            sudo += " -d";
            sudo += QString( " --comment \"%1\"" ).arg( i18n( "<b>smb4k_kill</b> needs administrative privileges. "
                                                              "Please enter your password." ) );
          }
          else
          {
            sudo = KStandardDirs::findExe( "sudo" );
          }

          if ( sudo.isEmpty() )
          {
            if ( Smb4KSettings::useKdeSudo() )
            {
              Smb4KNotification *notification = new Smb4KNotification();
              notification->commandNotFound( "kdesudo" );
            }
            else
            {
              Smb4KNotification *notification = new Smb4KNotification();
              notification->commandNotFound( "sudo" );
            }
            return;
          }
          else
          {
            // Do nothing
          }

          Smb4KProcess kill_proc( Smb4KProcess::Kill, this );
          kill_proc.setShellCommand( sudo+" "+smb4k_kill+" "+QString( thread->process()->pid() ) );
          kill_proc.setOutputChannelMode( KProcess::MergedChannels );
          kill_proc.start();
          kill_proc.waitForFinished( -1 );
        }
        else
        {
          // Do nothing
        }
        
        thread->process()->abort();
      }
      else
      {
        // Do nothing
      }
    }
  }
  else
  {
    // priv has already been deleted
  }
}


bool Smb4KMounter::isRunning( Smb4KShare *share )
{
  Q_ASSERT( share );
  
  BasicMountThread *thread = NULL;
  
  if ( !share->isHomesShare() )
  {
    thread = m_cache.object( share->unc( QUrl::None ) );
  }
  else
  {
    thread = m_cache.object( share->homeUNC( QUrl::None ) );
  }
  
  return (thread && thread->process() && thread->process()->state() == KProcess::Running);
}


void Smb4KMounter::triggerRemounts()
{
  if ( Smb4KSettings::remountShares() || priv->hardwareReason() )
  {
    QList<Smb4KSambaOptionsInfo *> list = Smb4KSambaOptionsHandler::self()->sharesToRemount();
    
    for ( int i = 0; i < list.size(); ++i )
    {
      QList<Smb4KShare *> mounted_shares = findShareByUNC( list.at( i )->unc() );

      if ( !mounted_shares.isEmpty() )
      {
        bool mount = true;

        for ( int j = 0; j < mounted_shares.size(); ++j )
        {
          if ( !mounted_shares.at( j )->isForeign() )
          {
            mount = false;
            break;
          }
          else
          {
            continue;
          }
        }

        if ( mount )
        {
          // First of all initialize the wallet manager.
          Smb4KWalletManager::self()->init( 0 );

          // Mount the share.
          Smb4KShare share( list.at( i )->unc() );
          share.setWorkgroupName( list.at( i )->workgroupName() );
          share.setHostIP( list.at( i )->ip() );
          
          priv->addRemount();

          mountShare( &share );
        }
        else
        {
          // Do nothing
        }
      }
      else
      {
        // First of all initialize the wallet manager.
        Smb4KWalletManager::self()->init( 0 );

        // Mount the share.
        Smb4KShare share( list.at( i )->unc() );
        share.setWorkgroupName( list.at( i )->workgroupName() );
        share.setHostIP( list.at( i )->ip() );
        
        priv->addRemount();

        mountShare( &share );
      }
    }
  }
  else
  {
    // Do nothing
  }
}


void Smb4KMounter::import()
{
  KMountPoint::List mount_points = KMountPoint::currentMountPoints( KMountPoint::BasicInfoNeeded|KMountPoint::NeedMountOptions );
  QList<Smb4KShare> mounted_shares;
  
  for ( int i = 0; i < mount_points.size(); ++i )
  {
#ifndef Q_OS_FREEBSD
    if ( QString::compare( mount_points.at( i )->mountType(), "cifs" ) == 0 )
#else
    if ( QString::compare( mount_points.at( i )->mountType(), "smbfs" ) == 0 )
#endif
    {
      Smb4KShare share;
      share.setUNC( mount_points.at( i )->mountedFrom() );
      share.setPath( mount_points.at( i )->mountPoint() );

#ifndef Q_OS_FREEBSD
      share.setFileSystem( Smb4KShare::CIFS );
      
      // Check if the share is new and we have to open /proc/mounts (if it exists) 
      // to acquire all needed information.
      if ( findShareByPath( mount_points.at( i )->mountPoint().toUtf8() ) == NULL && QFile::exists( "/proc/mounts" ) )
      {
        QStringList contents;
        QFile proc_mounts( "/proc/mounts" );
          
        if ( proc_mounts.open( QIODevice::ReadOnly | QIODevice::Text ) )
        {
          QTextStream ts( &proc_mounts );
          // Note: With Qt 4.3 this seems to be obsolete, but we'll
          // keep it for now.
          ts.setCodec( "UTF-8" );
          ts.setAutoDetectUnicode( true );
            
          while ( 1 )
          {
            // Only import CIFS shares.
            QString line = ts.readLine( 0 );
              
            if ( !line.isNull() )
            {
              if ( line.contains( " cifs " ) )
              {
                contents << line;
                continue;
              }
              else
              {
                continue;
              }
            }
            else
            {
              break;
            }
          }
            
          proc_mounts.close();
        }
        else
        {
          Smb4KNotification *notification = new Smb4KNotification();
          notification->openingFileFailed( proc_mounts );
          return;
        }
        
        // Now find the share entry and extract to needed data.
        for ( int j = 0; j < contents.size(); ++j )
        {
          QString entry = contents.at( j );
          
          if ( entry.contains( mount_points.at( i )->mountPoint() ) )
          {
            // Get the options string. Since the string ends with something
            // like " 0 0", we need to remove the last four characters.
            QString mount_options = entry.section( " cifs ", 1, 1 ).remove( entry.length() - 4, 4 ).trimmed();
            
            // Domain
            if ( mount_options.contains( "domain=" ) )
            {
              QString tmp = mount_options.section( "domain=", 1, 1 );
              
              if ( tmp.contains( "," ) )
              {
                // The domain entry is somewhere in the middle of the options
                // string.
                share.setWorkgroupName( tmp.section( ",", 0, 0 ) );
              }
              else
              {
                // The domain entry is at the end of the options string.
                share.setWorkgroupName( tmp );
              }
            }
            else
            {
              // Do nothing
            }
            
            // IP address
            if ( mount_options.contains( "addr=" ) )
            {
              QString tmp = mount_options.section( "addr=", 1, 1 );
              
              if ( tmp.contains( "," ) )
              {
                // The IP address entry is somewhere in the middle of the options
                // string.
                share.setHostIP( tmp.section( ",", 0, 0 ) );
              }
              else
              {
                // The IP address entry is at the end of the options string.
                share.setHostIP( tmp );
              }
            }
            else
            {
              // Do nothing
            }
            
            // Login
            if ( mount_options.contains( "username=" ) )
            {
              QString tmp = mount_options.section( "username=", 1, 1 );
              
              if ( tmp.contains( "," ) )
              {
                // The user name entry is somewhere in the middle of the options
                // string.
                QString user = tmp.section( ",", 0, 0 );
                share.setLogin( user.isEmpty() ? "guest" : user );
              }
              else
              {
                // The user name entry is at the end of the options string.
                share.setLogin( tmp.isEmpty() ? "guest" : tmp );
              }
            }
            else if ( mount_options.contains( "user=" ) )
            {
              QString tmp = mount_options.section( "user=", 1, 1 );
              
              if ( tmp.contains( "," ) )
              {
                // The user name entry is somewhere in the middle of the options
                // string.
                QString user = tmp.section( ",", 0, 0 );
                share.setLogin( user.isEmpty() ? "guest" : user );
              }
              else
              {
                // The user name entry is at the end of the options string.
                share.setLogin( tmp.isEmpty() ? "guest" : tmp );
              }
            }
            else
            {
              // Do nothing
            }
            
            break;
          }
          else
          {
            continue;
          }
        }
        
        mounted_shares += share;
      }
      else
      {
        // The share is either already known or the user disabled support for
        // the proc file system in the kernel. Either way, just populate all 
        // possible entries. The rest will be added/updated by the code below.
        QString login = mount_points.at( i )->mountOptions().join( "," ).section( "user=", 1, 1 ).section( ",", 0, 0 ).trimmed();
        share.setLogin( !login.isEmpty() ? login : "guest" ); // Work around empty 'user=' entries
        share.setIsMounted( true );
        
        mounted_shares += share;
      }
#else
      share.setFileSystem( Smb4KShare::SMBFS );
      QString login = mount_points.at( i )->mountOptions().join( "," ).section( "username=", 1, 1 ).section( ",", 0, 0 ).trimmed();
      share.setLogin( !login.isEmpty() ? login : "guest" ); // Work around empty 'username=' entries
      share.setIsMounted( true );
      qDebug() << "Domain and ip address?";
      
      mounted_shares += share;
#endif
    }
    else
    {
      continue;
    }
  }

  // Check which shares were unmounted, emit the unmounted() signal
  // on each of the unmounted shares and remove them from the global
  // list.
  // NOTE: The unmount() signal is emitted *BEFORE* the share is removed
  // from the global list! You need to account for that in your application.
  bool found = false;
  
  for ( int i = 0; i < mountedSharesList().size(); ++i )
  {
    for ( int j = 0; j < mounted_shares.size(); ++j )
    {
      // Check the mount point, since that is unique.
      if ( QString::compare( mountedSharesList().at( i )->canonicalPath(), mounted_shares.at( j ).canonicalPath() ) == 0 ||
           QString::compare( mountedSharesList().at( i )->path(), mounted_shares.at( j ).path() ) == 0 )
      {
        found = true;
        break;
      }
      else
      {
        continue;
      }
    }
    
    if ( !found )
    {
      mountedSharesList()[i]->setIsMounted( false );
      emit unmounted( mountedSharesList().at( i ) );
      removeMountedShare( mountedSharesList().at( i ) );
    }
    else
    {
      // Do nothing
    }
    
    found = false;
  }

  // Now add additional information to the shares in the temporary
  // list and insert them to the global list. At the same time, remove
  // the old entry from the list. Also, emit either the updated() or
  // the mounted() signal.
  for ( int i = 0; i < mounted_shares.size(); ++i )
  {
    Smb4KShare *mounted_share = findShareByPath( mounted_shares.at( i ).canonicalPath() );
    
    if ( mounted_share )
    {
      // Check share.
      if ( !mounted_share->isInaccessible() )
      {
        check( &mounted_shares[i] );
      }
      else
      {
        mounted_shares[i].setInaccessible( true );
      }
      
      // Copy data.
      if ( !mounted_share->login().isEmpty() &&
           QString::compare( mounted_share->login(), mounted_shares.at( i ).login() ) != 0 )
      {
        mounted_shares[i].setLogin( mounted_share->login() );
      }
      else
      {
        // Do nothing
      }
      
      if ( !mounted_share->workgroupName().isEmpty() &&
           QString::compare( mounted_share->workgroupName(), mounted_shares.at( i ).workgroupName() ) != 0 )
      {
        mounted_shares[i].setWorkgroupName( mounted_share->workgroupName() );
      }
      else
      {
        // Do nothing
      }
      
      if ( !mounted_share->hostIP().isEmpty() &&
           QString::compare( mounted_share->hostIP(), mounted_shares.at( i ).hostIP() ) != 0 )
      {
        mounted_shares[i].setHostIP( mounted_share->hostIP() );
      }
      else
      {
        // Do nothing
      }
    }
    else
    {
      // Check share.
      check( &mounted_shares[i] );
    }
    
    // Is this a mount that was done by the user or by
    // someone else (or the system)?
    if ( (mounted_shares.at( i ).uid() == getuid() && mounted_shares.at( i ).gid() == getgid()) ||
         (!mounted_shares.at( i ).isInaccessible() &&
          (QString::fromUtf8( mounted_shares.at( i ).path() ).startsWith( Smb4KSettings::mountPrefix().path() ) ||
           QString::fromUtf8( mounted_shares.at( i ).canonicalPath() ).startsWith( QDir::homePath() ))) ||
         (!mounted_shares.at( i ).isInaccessible() &&
          (QString::fromUtf8( mounted_shares.at( i ).canonicalPath() ).startsWith( QDir( Smb4KSettings::mountPrefix().path() ).canonicalPath() ) ||
           QString::fromUtf8( mounted_shares.at( i ).canonicalPath() ).startsWith( QDir::home().canonicalPath() ))) )
    {
      mounted_shares[i].setForeign( false );
    }
    else
    {
      mounted_shares[i].setForeign( true );
    }
    
    // Get the host that shares this resource and check if we
    // need to set the IP address or workgroup/domain.
    Smb4KHost *host = findHost( mounted_shares.at( i ).hostName(), mounted_shares.at( i ).workgroupName() );
    
    if ( host )
    {
      // Set the IP address if necessary.
      if ( mounted_shares.at( i ).hostIP().isEmpty() || QString::compare( host->ip(), mounted_shares.at( i ).hostIP() ) != 0 )
      {
        mounted_shares[i].setHostIP( host->ip() );
      }
      else
      {
        // Do nothing
      }
      
      // Set the workgroup/domain name if necessary.
      if ( mounted_shares.at( i ).workgroupName().isEmpty() )
      {
        mounted_shares[i].setWorkgroupName( host->workgroupName() );
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
    
    // Now we decide whether we need to emit the update() or the mounted() 
    // signal.
    // It is important for the later processing of the shares that have
    // been unmounted in the meantime that we remove all shares from
    // the global list that have been processed.
    if ( mounted_share )
    {
      // This share was previouly mounted.
      removeMountedShare( mounted_share );

      Smb4KShare *new_share = new Smb4KShare( mounted_shares[i] );
      
      // To avoid incompatibilities, we remove a trailing slash from
      // the UNC now, if it is present.
      if ( new_share->unc( QUrl::None ).endsWith( "/" ) )
      {
        QString u = new_share->unc( QUrl::None );
        u.chop( 1 );
        new_share->setUNC( u );
      }
      else
      {
        // Do nothing
      }
      
      addMountedShare( new_share );
      emit updated( new_share );
    }
    else
    {
      // This is a new share.
      Smb4KShare *new_share = new Smb4KShare( mounted_shares[i] );
      
      // To avoid incompatibilities, we remove a trailing slash from
      // the UNC now, if it is present.
      if ( new_share->unc( QUrl::None ).endsWith( "/" ) )
      {
        QString u = new_share->unc( QUrl::None );
        u.chop( 1 );
        new_share->setUNC( u );
      }
      else
      {
        // Do nothing
      }
      
      addMountedShare( new_share );
      emit mounted( new_share );
    }
  }
}


void Smb4KMounter::mountShare( Smb4KShare *share )
{
  Q_ASSERT( share );

  // Check if the UNC is valid. Otherwise, we can just return here
  // with an error message.
  QUrl url( share->unc( QUrl::None ) );
  
  if ( !url.isValid() )
  {
    // FIXME: Throw an error.
    qDebug() << "Invalid UNC";
    return;
  }
  else
  {
    // Do nothing
  }
  
  // Find smb4k_mount program
  QString smb4k_mount = KGlobal::dirs()->findResource( "exe", "smb4k_mount" );

  if ( smb4k_mount.isEmpty() )
  {
    Smb4KNotification *notification = new Smb4KNotification();
    notification->commandNotFound( "smb4k_mount" );
    return;
  }
  else
  {
    // Do nothing
  }

  // Find sudo program
  QString sudo;
      
  if ( Smb4KSettings::useKdeSudo() && !KStandardDirs::findExe( "kdesudo" ).isEmpty() )
  {
    sudo = KStandardDirs::findExe( "kdesudo" );
    sudo += " -d";
    sudo += QString( " --comment \"%1\"" ).arg( i18n( "<b>smb4k_mount</b> needs administrative privileges. "
                                                      "Please enter your password." ) );
  }
  else
  {
    sudo = KStandardDirs::findExe( "sudo" );
  }

  // Check that sudo is installed in the case it is needed.
  if ( Smb4KSettings::alwaysUseSuperUser() && sudo.isEmpty() )
  {
    if ( Smb4KSettings::useKdeSudo() )
    {
      Smb4KNotification *notification = new Smb4KNotification();
      notification->commandNotFound( "kdesudo" );
    }
    else
    {
      Smb4KNotification *notification = new Smb4KNotification();
      notification->commandNotFound( "sudo" );
    }
    return;
  }
  else
  {
    // Do nothing
  }
  
  QList<Smb4KShare *> list;

  if ( share->isHomesShare() )
  {
    QWidget *parent = 0;

    if ( kapp )
    {
      if ( kapp->activeWindow() )
      {
        parent = kapp->activeWindow();
      }
      else
      {
        parent = kapp->desktop();
      }
    }
    else
    {
      // Do nothing
    }

    if ( !Smb4KHomesSharesHandler::self()->specifyUser( share, parent ) )
    {
      return;
    }
    else
    {
      // Do nothing
    }
    
    list = findShareByUNC( share->homeUNC( QUrl::None ) );
  }
  else
  {
    list = findShareByUNC( share->unc( QUrl::None ) );
  }
  
  // Before doing anything else let's check that the
  // share has not already been mounted by the user:
  for ( int i = 0; i != list.size(); ++i )
  {
    if ( !list.at( i )->isForeign() )
    {
      return;
    }
    else
    {
      continue;
    }
  }
  
  // Assemble the mount point and create it.
  QString path;
  path += Smb4KSettings::mountPrefix().path();
  path += QDir::separator();
  path += (Smb4KSettings::forceLowerCaseSubdirs() ? share->hostName().toLower() : share->hostName());
  path += QDir::separator();
  
  if ( !share->isHomesShare() )
  {
    path += (Smb4KSettings::forceLowerCaseSubdirs() ? share->shareName().toLower() : share->shareName());
  }
  else
  {
    path += (Smb4KSettings::forceLowerCaseSubdirs() ? share->login().toLower() : share->login());
  }

  QDir dir( QDir::cleanPath( path ) );

  if ( !dir.mkpath( dir.path() ) )
  {
    Smb4KNotification *notification = new Smb4KNotification();
    notification->mkdirFailed( dir );
    return;
  }
  else
  {
    share->setPath( dir.path() );
  }

  // Get the authentication information.
  Smb4KAuthInfo authInfo( share );
  Smb4KWalletManager::self()->readAuthInfo( &authInfo );

  // Set the login and the file system for the share.
#ifndef __FreeBSD__
  share->setFileSystem( Smb4KShare::CIFS );
#else
  share->setFileSystem( Smb4KShare::SMBFS );
#endif
  share->setLogin( QString::fromUtf8( authInfo.login() ) );

  // Compile the command
  QString command;
  Smb4KSambaOptionsInfo *options_info  = Smb4KSambaOptionsHandler::self()->findItem( share, true );
  QMap<QString, QString> global_options = Smb4KSambaOptionsHandler::self()->globalSambaOptions();

  if ( Smb4KSettings::alwaysUseSuperUser() )
  {
    command += sudo;
    command += " --";    
    command += " "+smb4k_mount;
  }
  else
  {
    command += smb4k_mount;
  }

#ifndef __FreeBSD__
  command += " -o";
  command += " ";

  // Workgroup
  command += !share->workgroupName().trimmed().isEmpty() ?
             QString( "domain=%1" ).arg( KShell::quoteArg( share->workgroupName() ) ) :
             "";
  
  // Host IP
  command += !share->hostIP().trimmed().isEmpty() ?
             QString( ",ip=%1" ).arg( share->hostIP() ) :
             "";

  // User
  command += !authInfo.login().isEmpty() ?
             QString( ",user=%1" ).arg( QString::fromUtf8( authInfo.login() ) ) :
             ",guest";
             
  // Client's and server's NetBIOS name
  // According to the manual page, this is only needed when port 139
  // is used. So, we only pass the NetBIOS name in that case.  
  if ( Smb4KSettings::remoteFileSystemPort() == 139 || (options_info && options_info->fileSystemPort() == 139) )
  {
    // The client's NetBIOS name.
    if ( !Smb4KSettings::netBIOSName().isEmpty() )
    {
      command += QString( ",netbiosname=%1" ).arg( KShell::quoteArg( Smb4KSettings::netBIOSName() ) );
    }
    else
    {
      if ( !global_options["netbios name"].isEmpty() )
      {
        command += QString( ",netbiosname=%1" ).arg( KShell::quoteArg( global_options["netbios name"] ) );
      }
      else
      {
        // Do nothing
      }
    }

    // The server's NetBIOS name.
    command += ",servern="+KShell::quoteArg( share->hostName() );
  }
  else
  {
    // Do nothing
  }
  
  // UID
  command += QString( ",uid=%1" ).arg( options_info ? options_info->uid() : (uid_t)Smb4KSettings::userID().toInt() );
  
  // GID
  command += QString( ",gid=%1" ).arg( options_info ? options_info->gid() : (gid_t)Smb4KSettings::groupID().toInt() );
  
  // Client character set
  switch ( Smb4KSettings::clientCharset() )
  {
    case Smb4KSettings::EnumClientCharset::default_charset:
    {
      if ( !global_options["unix charset"].isEmpty() )
      {
        command += QString( ",iocharset=%1" ).arg( global_options["unix charset"].toLower() );
      }
      else
      {
        // Do nothing
      }
      break;
    }
    default:
    {
      command += QString( ",iocharset=%1" ).arg( Smb4KSettings::self()->clientCharsetItem()->label() );
      break;
    }
  }
  
  // Port
  command += QString( ",port=%1" ).arg( (options_info && options_info->fileSystemPort() != -1) ?
                                        options_info->fileSystemPort() : Smb4KSettings::remoteFileSystemPort() );
                                        
  // Write access
  if ( options_info )
  {
    switch ( options_info->writeAccess() )
    {
      case Smb4KSambaOptionsInfo::ReadWrite:
      {
        command += ",rw";
        break;
      }
      case Smb4KSambaOptionsInfo::ReadOnly:
      {
        command += ",ro";
        break;
      }
      default:
      {
        switch ( Smb4KSettings::writeAccess() )
        {
          case Smb4KSettings::EnumWriteAccess::ReadWrite:
          {
            command += ",rw";
            break;
          }
          case Smb4KSettings::EnumWriteAccess::ReadOnly:
          {
            command += ",ro";
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
    switch ( Smb4KSettings::writeAccess() )
    {
      case Smb4KSettings::EnumWriteAccess::ReadWrite:
      {
        command += ",rw";
        break;
      }
      case Smb4KSettings::EnumWriteAccess::ReadOnly:
      {
        command += ",ro";
        break;
      }
      default:
      {
        break;
       }
    }
  }
  
  // File mask
  command += !Smb4KSettings::fileMask().isEmpty() ? QString( ",file_mode=%1" ).arg( Smb4KSettings::fileMask() ) : "";

  // Directory mask
  command += !Smb4KSettings::directoryMask().isEmpty() ? QString( ",dir_mode=%1" ).arg( Smb4KSettings::directoryMask() ) : "";

  // Permission checks
  command += Smb4KSettings::permissionChecks() ? ",perm" : ",noperm";

  // Client controls IDs
  command += Smb4KSettings::clientControlsIDs() ? ",setuids" : ",nosetuids";
  
  // Server inode numbers
  command += Smb4KSettings::serverInodeNumbers() ? ",serverino" : ",noserverino";

  // Inode data caching
  command += Smb4KSettings::noInodeDataCaching() ? ",directio" : "";
  
  // Translate reserved characters
  command += Smb4KSettings::translateReservedChars() ? ",mapchars" : ",nomapchars";
  
  // Locking
  command += Smb4KSettings::noLocking() ? ",nolock" : "";
  
  // Security mode
  switch ( Smb4KSettings::securityMode() )
  {
    case Smb4KSettings::EnumSecurityMode::None:
    {
      command += ",sec=none";
      break;
    }
    case Smb4KSettings::EnumSecurityMode::Krb5:
    {
      command += ",sec=krb5";
      break;
    }
    case Smb4KSettings::EnumSecurityMode::Krb5i:
    {
      command += ",sec=krb5i";
      break;
    }
    case Smb4KSettings::EnumSecurityMode::Ntlm:
    {
      command += ",sec=ntlm";
      break;
    }
    case Smb4KSettings::EnumSecurityMode::Ntlmi:
    {
      command += ",sec=ntlmi";
      break;
    }
    case Smb4KSettings::EnumSecurityMode::Ntlmv2:
    {
      command += ",sec=ntlmv2";
      break;
    }
    case Smb4KSettings::EnumSecurityMode::Ntlmv2i:
    {
      command += ",sec=ntlmv2i";
      break;
    }
    default:
    {
      break;
    }
  }

  // Global custom options provided by the user
  command += !Smb4KSettings::customCIFSOptions().isEmpty() ? ","+Smb4KSettings::customCIFSOptions() : "";
  
  // Fix existing comma, if necessary.
  if ( command.endsWith( "," ) )
  {
    command.truncate( command.length() - 1 );
  }
  else
  {
    // Do nothing
  }
#else
  // Workgroup
  command += !share->workgroupName().isEmpty() ?
             QString( " -W %1" ).arg( KShell::quoteArg( share->workgroupName() ) ) :
             "";
  
  // Host IP
  command += !share->hostIP().isEmpty() ? QString( " -I %1" ).arg( share->hostIP() ) : "";

  // Do not ask for a password. Use ~/.nsmbrc instead.
  command += " -N";
  
  // UID
  command += QString( " -u %1" ).arg( options_info ? options_info->uid() : (uid_t)Smb4KSettings::userID().toInt() );

  // GID
  command += QString( " -g %1" ).arg( options_info ?  options_info->gid() : (uid_t)Smb4KSettings::groupID().toInt() );
  
  // Client character set and server codepage
  QString charset, codepage;

  switch ( Smb4KSettings::clientCharset() )
  {
    case Smb4KSettings::EnumClientCharset::default_charset:
    {
      charset = global_options["unix charset"].toLower(); // maybe empty
      break;
    }
    default:
    {
      charset = Smb4KSettings::self()->clientCharsetItem()->label();
      break;
    }
  }
  
  switch ( Smb4KSettings::serverCodepage() )
  {
    case Smb4KSettings::EnumServerCodepage::default_codepage:
    {
      codepage = global_options["dos charset"].toLower(); // maybe empty
      break;
    }
    default:
    {
      codepage = Smb4KSettings::self()->serverCodepageItem()->label();
      break;
    }
  }
  
  command += (!charset.isEmpty() && !codepage.isEmpty()) ? QString( " -E %1:%2" ).arg( charset, codepage ) : "";

  // File mask
  command += !Smb4KSettings::fileMask().isEmpty() ? QString( " -f %1" ).arg( Smb4KSettings::fileMask() ) : "";

  // Directory mask
  command += !Smb4KSettings::directoryMask().isEmpty() ? QString( " -d %1" ).arg( Smb4KSettings::directoryMask() ) : "";
#endif
  command += " --";
#ifndef __FreeBSD__
  if ( !share->isHomesShare() )
  {
    command += " "+KShell::quoteArg( share->unc() );
  }
  else
  {
    command += " "+KShell::quoteArg( share->homeUNC() );
  }
#else
  if ( options_info )
  {
    share->setPort( options_info->smbPort() != -1 ? options_info->smbPort() : Smb4KSettings::remoteSMBPort() );
  }
  else
  {
    share->setPort( Smb4KSettings::remoteSMBPort() );
  }

  if ( !share->isHomesShare() )
  {
    command += " "+KShell::quoteArg( share->unc( QUrl::RemoveScheme|QUrl::RemovePassword ) );
  }
  else
  {
    command += " "+KShell::quoteArg( share->homeUNC( QUrl::RemoveScheme|QUrl::RemovePassword ) );
  }
#endif
  command += " "+KShell::quoteArg( share->path() );

  // Start mounting the share.
  if ( m_cache.size() == 0 )
  {
    QApplication::setOverrideCursor( Qt::WaitCursor );
    // State was set above.
    emit stateChanged();
  }
  else
  {
    // Already running
  }
  
  emit aboutToStart( share, MountShare );

  MountThread *thread = new MountThread( share, this );
  
  if ( !share->isHomesShare() )
  {
    m_cache.insert( share->unc( QUrl::None ), thread );
  }
  else
  {
    m_cache.insert( share->homeUNC( QUrl::None ), thread );
  }
  
  connect( thread, SIGNAL( finished() ),
           this,   SLOT( slotThreadFinished() ) );
  connect( thread, SIGNAL( mounted( Smb4KShare * ) ),
           this,   SLOT( slotShareMounted( Smb4KShare * ) ) );
           
  thread->start();
  thread->mount( &authInfo, command );
}


void Smb4KMounter::unmountShare( Smb4KShare *share, bool force, bool silent )
{
  Q_ASSERT( share );
  
  // Find the smb4k_umount program
  QString smb4k_umount = KGlobal::dirs()->findResource( "exe", "smb4k_umount" );

  if ( smb4k_umount.isEmpty() )
  {
    Smb4KNotification *notification = new Smb4KNotification();
    notification->commandNotFound( "smb4k_umount" );
    return;
  }
  else
  {
    // Do nothing
  }

  // Find sudo program
  QString sudo;
    
  if ( Smb4KSettings::useKdeSudo() && !KStandardDirs::findExe( "kdesudo" ).isEmpty() )
  {
    sudo = KStandardDirs::findExe( "kdesudo" );
    sudo += " -d";
    sudo += QString( " --comment \"%1\"" ).arg( i18n( "<b>smb4k_umount</b> needs administrative privileges. "
                                                      "Please enter your password." ) );
  }
  else
  {
    sudo = KStandardDirs::findExe( "sudo" );
  }

  // Check that sudo is installed in the case it is needed.
  if ( ((force && Smb4KSettings::useForceUnmount()) || Smb4KSettings::alwaysUseSuperUser()) &&
       sudo.isEmpty() )
  {
    if ( Smb4KSettings::useKdeSudo() )
    {
      Smb4KNotification *notification = new Smb4KNotification();
      notification->commandNotFound( "kdesudo" );
    }
    else
    {
      Smb4KNotification *notification = new Smb4KNotification();
      notification->commandNotFound( "sudo" );
    }
    return;
  }
  else
  {
    // Do nothing
  }

  // Complain if the share is a foreign one and unmounting those
  // is prohibited.
  if ( share->isForeign() && !Smb4KSettings::unmountForeignShares() )
  {
    if ( !silent )
    {
      Smb4KNotification *notification = new Smb4KNotification();
      notification->unmountingNotAllowed( share );
    }
    else
    {
      // Do nothing
    }

    return;
  }
  else
  {
    // Do nothing
  }

  if ( force )
  {
    QWidget *parent = 0;

    if ( kapp )
    {
      if ( kapp->activeWindow() )
      {
        parent = kapp->activeWindow();
      }
      else
      {
        parent = kapp->desktop();
      }
    }
    else
    {
      // Do nothing
    }

    // Ask the user, if he/she really wants to force the unmounting.
    if ( KMessageBox::questionYesNo( parent, i18n( "<qt>Do you really want to force the unmounting of this share?</qt>" ), QString(), KStandardGuiItem::yes(), KStandardGuiItem::no(), "Dont Ask Forced", KMessageBox::Notify ) == KMessageBox::No )
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
    // Do nothing
  }

  // Compile the command.
  QString command;

  if ( (force && Smb4KSettings::useForceUnmount()) || Smb4KSettings::alwaysUseSuperUser() )
  {
    command += sudo;
    command += " --";
    command += " "+smb4k_umount;
  }
  else
  {
    command += smb4k_umount;
  }

#ifdef __linux__
  if ( force && Smb4KSettings::useForceUnmount() )
  {
    command += " -l"; // lazy unmount
  }
  else
  {
    // Do nothing
  }
#endif

  command += " --";
  command += " "+KShell::quoteArg( share->canonicalPath() );
  
  // Start unmounting the share.
  if ( m_cache.size() == 0 )
  {
    QApplication::setOverrideCursor( Qt::WaitCursor );
    // State was set above.
    emit stateChanged();
  }
  else
  {
    // Already running
  }
  
  if ( !priv->aboutToQuit() )
  {
    emit aboutToStart( share, UnmountShare );
    
    UnmountThread *thread = new UnmountThread( share, this );
    m_cache.insert( share->unc( QUrl::None ), thread );
  
    connect( thread, SIGNAL( finished() ),
             this,   SLOT( slotThreadFinished() ) );
    connect( thread, SIGNAL( unmounted( Smb4KShare * ) ),
             this,   SLOT( slotShareUnmounted( Smb4KShare * ) ) );
  
    thread->start();
    thread->unmount( command );
  }
  else
  {
    // We only unmount the shares and do not need to connect
    // to any signals. Also, we will not enter the thread into
    // the cache.
    UnmountThread thread( share, this );
    thread.setStartDetached( true );
    thread.start();
    thread.unmount( command );
    thread.wait();
  }
}


void Smb4KMounter::unmountAllShares()
{
  // Never use 
  // 
  //    while ( !mountedSharesList().isEmpty() ) { ... } 
  // 
  // here, because then the mounter will loop indefinitely when the
  // unmounting of a share fails.
  QListIterator<Smb4KShare *> it( mountedSharesList() );

  while ( it.hasNext() )
  {
    unmountShare( it.next(), false, true );
    priv->addUnmount();
  }
}


void Smb4KMounter::prepareForShutdown()
{
  slotAboutToQuit();
}


void Smb4KMounter::check( Smb4KShare *share )
{
  if ( share )
  {
    CheckThread thread( share, this );
    thread.start();
    thread.wait();
  }
  else
  {
    // Do nothing
  }
}


void Smb4KMounter::saveSharesForRemount()
{
  if ( (Smb4KSettings::remountShares() && priv->aboutToQuit()) || priv->hardwareReason() )
  {
    for ( int i = 0; i < mountedSharesList().size(); ++i )
    {
      if ( !mountedSharesList().at( i )->isForeign() )
      {
        Smb4KSambaOptionsHandler::self()->addRemount( mountedSharesList().at( i ) );
      }
      else
      {
        Smb4KSambaOptionsHandler::self()->removeRemount( mountedSharesList().at( i ) );
      }
    }
  }
  else
  {
    if ( !Smb4KSettings::remountShares() )
    {
      Smb4KSambaOptionsHandler::self()->clearRemounts();
    }
    else
    {
      // Do nothing
    }
  }
}


void Smb4KMounter::timerEvent( QTimerEvent * )
{
  if ( !kapp->startingUp() && !isRunning() )
  {
    // Import the mounted shares.
    import();
  }
  else
  {
    // Do nothing and wait until the application started up.
  }

  if ( m_timeout != Smb4KSettings::checkInterval() )
  {
    m_timeout = Smb4KSettings::checkInterval();
    killTimer( m_timer_id );
    m_timer_id = startTimer( m_timeout );
  }
  else
  {
    // Do nothing
  }
}


/////////////////////////////////////////////////////////////////////////////
// SLOT IMPLEMENTATIONS
/////////////////////////////////////////////////////////////////////////////


void Smb4KMounter::slotAboutToQuit()
{
  // Tell the application it is about to quit.
  priv->setAboutToQuit();

  // Abort any actions.
  abortAll();

  // Save the shares that need to be remounted.
  saveSharesForRemount();

  // Unmount the shares if the user chose to do so.
  if ( Smb4KSettings::unmountSharesOnExit() )
  {
    unmountAllShares();
  }
  else
  {
    // Do nothing
  }

  // Clean up the mount prefix.
  QDir dir;
  dir.cd( Smb4KSettings::mountPrefix().path() );
  QStringList dirs = dir.entryList( QDir::Dirs|QDir::NoDotAndDotDot, QDir::NoSort );

  QList<Smb4KShare *> inaccessible = findInaccessibleShares();

  // Remove all directories from the list that belong to
  // inaccessible shares.
  for ( int i = 0; i < inaccessible.size(); ++i )
  {
    int index = dirs.indexOf( inaccessible.at( i )->hostName(), 0 );

    if ( index != -1 )
    {
      dirs.removeAt( index );
      continue;
    }
    else
    {
      continue;
    }
  }

  // Now it is save to remove all empty directories.
  for ( int i = 0; i < dirs.size(); ++i )
  {
    dir.cd( dirs.at( i ) );

    QStringList subdirs = dir.entryList( QDir::Dirs|QDir::NoDotAndDotDot, QDir::NoSort );

    for ( int k = 0; k < subdirs.size(); ++k )
    {
      dir.rmdir( subdirs.at( k ) );
    }

    dir.cdUp();
    dir.rmdir( dirs.at( i ) );
  }
}


void Smb4KMounter::slotThreadFinished()
{
  QStringList keys = m_cache.keys();

  foreach ( const QString &key, keys )
  {
    BasicMountThread *thread = m_cache.object( key );

    if ( thread->isFinished() )
    {
      (void) m_cache.take( key );
      
      switch ( thread->process()->type() )
      {
        case Smb4KProcess::Mount:
        {
          if ( thread->badShareNameError() )
          {
            Smb4KShare share( *thread->share() );
            share.setShareName( static_cast<QString>( thread->share()->shareName() ).replace( "_", " " ) );
            mountShare( &share );
          }
          else
          {
            // Do nothing
          }
          
          if ( thread->authenticationError() )
          {
            Smb4KAuthInfo authInfo( thread->share() );

            if ( Smb4KWalletManager::self()->showPasswordDialog( &authInfo, 0 ) )
            {
              // Kill the currently active override cursor. Another 
              // one will be set in an instant by mountShare().
              QApplication::restoreOverrideCursor();
              mountShare( thread->share() );
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
          
          emit finished( thread->share(), MountShare );
          break;
        }
        case Smb4KProcess::Unmount:
        {
          emit finished( thread->share(), UnmountShare );
          break;
        }
        default:
        {
          break;
        }
      }
      
      delete thread;
    }
    else
    {
      // Do nothing
    }
  }

  if ( m_cache.size() == 0 )
  {
    m_state = MOUNTER_STOP;
    emit stateChanged();
    QApplication::restoreOverrideCursor();
  }
  else
  {
    // Do nothing
  }
}


void Smb4KMounter::slotShareMounted( Smb4KShare *share )
{
  Q_ASSERT( share );
  
  // Check that we actually mounted the share and emit 
  // the mounted() signal if we found it.
  KMountPoint::List mount_points = KMountPoint::currentMountPoints( KMountPoint::BasicInfoNeeded|KMountPoint::NeedMountOptions );
  bool mountpoint_found = false;
  
  for ( int i = 0; i < mount_points.size(); ++i )
  {
    if ( QString::compare( mount_points.at( i )->mountPoint(), share->path() ) == 0 ||
         QString::compare( mount_points.at( i )->mountPoint(), share->canonicalPath() ) == 0 )
    {
      mountpoint_found = true;
      break;
    }
    else
    {
      continue;
    }
  }
  
  if ( mountpoint_found )
  {
    // Set the share as mounted.
    share->setIsMounted( true );
    
    // Check the usage, etc.
    check( share );
    
    // Create a new share object and add it to the list
    // of mounted shares.
    Smb4KShare *new_share = new Smb4KShare( *share );
  
    if ( share->isHomesShare() )
    {
      new_share->setUNC( share->homeUNC( QUrl::None ) );
    }
    else
    {
      // Do nothing
    }
  
    addMountedShare( new_share );
    
    // Check whether this was a remount or not, do the necessary 
    // things and notify the user.
    if ( priv->pendingRemounts() != 0 && Smb4KSambaOptionsHandler::self()->findItem( share ) != NULL )
    {
      Smb4KSambaOptionsHandler::self()->removeRemount( share );
      priv->removeRemount();
      
      if ( priv->pendingRemounts() == 0 )
      {
        Smb4KNotification *notification = new Smb4KNotification( this );
        notification->sharesRemounted( priv->initialRemounts(), priv->initialRemounts() );
        priv->clearRemounts();
      }
      else
      {
        if ( !m_cache.isEmpty() )
        {
          bool still_mounting = false;
          
          QStringList keys = m_cache.keys();

          foreach ( const QString &key, keys )
          {
            BasicMountThread *thread = m_cache.object( key );
            
            if ( thread->type() == BasicMountThread::MountThread &&
                 Smb4KSambaOptionsHandler::self()->findItem( thread->share() ) != NULL )
            {
              still_mounting = true;
              break;
            }
            else
            {
              continue;
            }
          }
          
          if ( !still_mounting )
          {
            Smb4KNotification *notification = new Smb4KNotification( this );
            notification->sharesRemounted( priv->initialRemounts(), (priv->initialRemounts() - priv->pendingRemounts()) );
            priv->clearRemounts();
          }
          else
          {
            // Do nothing
          }
        }
        else
        {
          Smb4KNotification *notification = new Smb4KNotification( this );
          notification->sharesRemounted( priv->initialRemounts(), (priv->initialRemounts() - priv->pendingRemounts()) );
          priv->clearRemounts();
        }
      }
    }
    else
    {
      Smb4KNotification *notification = new Smb4KNotification( this );
      notification->shareMounted( new_share );
    }
  
    // Finally, emit the mounted() signal.
    emit mounted( new_share );
  }
  else
  {
    // Set the share as not mounted and clear the mountpoint/path,
    share->setIsMounted( false );
    share->setPath( QString() );
  }
}


void Smb4KMounter::slotShareUnmounted( Smb4KShare *share )
{
  Q_ASSERT( share );
  
  // Check that we actually unmounted the share and emit 
  // the mounted() signal if it is really gone.
  KMountPoint::List mount_points = KMountPoint::currentMountPoints( KMountPoint::BasicInfoNeeded|KMountPoint::NeedMountOptions );
  bool mountpoint_found = false;
  
  for ( int i = 0; i < mount_points.size(); ++i )
  {
    if ( QString::compare( mount_points.at( i )->mountPoint(), share->path() ) == 0 ||
         QString::compare( mount_points.at( i )->mountPoint(), share->canonicalPath() ) == 0 )
    {
      mountpoint_found = true;
      break;
    }
    else
    {
      continue;
    }
  }
  
  if ( !mountpoint_found )
  {
    // Set the incoming share as unmounted.
    share->setIsMounted( false );
    
    // Clean up the mount prefix.
    if ( qstrncmp( share->canonicalPath(),
         QDir( Smb4KSettings::mountPrefix().path() ).canonicalPath().toUtf8(),
         QDir( Smb4KSettings::mountPrefix().path() ).canonicalPath().toUtf8().length() ) == 0 )
    {
      QDir dir( share->canonicalPath() );

      if ( dir.rmdir( dir.canonicalPath() ) )
      {
        dir.cdUp();
        dir.rmdir( dir.canonicalPath() );
      }
      else
      {
        // Do nothing
      }
    }
    else
    {
      // Do nothing here. Do not remove any paths that are outside the
      // mount prefix.
    }
    
    // Find the share in the list, emit the unmounted() signal and finally
    // remove the share from the list of mounted shares.
    Smb4KShare *mounted_share = findShareByPath( share->path() );
    
    if ( mounted_share )
    {
      mounted_share->setIsMounted( false );

      if ( priv->pendingUnmounts() != 0 )
      {
        priv->removeUnmount();
        
        if ( priv->pendingUnmounts() == 0 )
        {
          Smb4KNotification *notification = new Smb4KNotification( this );
          notification->allSharesUnmounted( priv->initialUnmounts(), priv->initialUnmounts() );
          priv->clearUnmounts();
        }
        else
        {
          if ( !m_cache.isEmpty() )
          {
            bool still_unmounting = false;
            
            QStringList keys = m_cache.keys();

            foreach ( const QString &key, keys )
            {
              BasicMountThread *thread = m_cache.object( key );
              
              if ( thread->type() == BasicMountThread::UnmountThread )
              {
                still_unmounting = true;
                break;
              }
              else
              {
                continue;
              }
            }
            
            if ( !still_unmounting )
            {
              Smb4KNotification *notification = new Smb4KNotification( this );
              notification->allSharesUnmounted( priv->initialUnmounts(), (priv->initialUnmounts() - priv->pendingUnmounts()) );
              priv->clearUnmounts();
            }
            else
            {
              // Do nothing
            }
          }
          else
          {
            Smb4KNotification *notification = new Smb4KNotification( this );
            notification->allSharesUnmounted( priv->initialUnmounts(), (priv->initialUnmounts() - priv->pendingUnmounts()) );
            priv->clearUnmounts();
          }
        }
      }
      else
      {
        Smb4KNotification *notification = new Smb4KNotification( this );
        notification->shareUnmounted( share );
      }
      
      emit unmounted( mounted_share );
      removeMountedShare( mounted_share );
    }
    else
    {
      // Do nothing
    }
  }
  else
  {
    // Do nothing.
  }
}


void Smb4KMounter::slotHardwareButtonPressed( Smb4KSolidInterface::ButtonType type )
{
  switch ( type )
  {
    case Smb4KSolidInterface::SleepButton:
    {
      if ( Smb4KSettings::unmountWhenSleepButtonPressed() )
      {
        priv->setHardwareReason( true );
        abortAll();
        saveSharesForRemount();
        unmountAllShares();
        priv->setHardwareReason( false );
      }
      else
      {
        // Do nothing
      }

      break;
    }
    case Smb4KSolidInterface::LidButton:
    {
      if ( Smb4KSettings::unmountWhenLidButtonPressed() )
      {
        priv->setHardwareReason( true );
        abortAll();
        saveSharesForRemount();
        unmountAllShares();
        priv->setHardwareReason( false );
      }
      else
      {
        // Do nothing
      }

      break;
    }
    case Smb4KSolidInterface::PowerButton:
    {
      if ( Smb4KSettings::unmountWhenPowerButtonPressed() )
      {
        priv->setHardwareReason( true );
        abortAll();
        saveSharesForRemount();
        unmountAllShares();
        priv->setHardwareReason( false );
      }
      else
      {
        // Do nothing
      }
    }
    default:
    {
      break;
    }
  }
}


void Smb4KMounter::slotComputerWokeUp()
{
  // Only trigger a remount here, if the network connection is
  // established. If the computer is still disconnected,
  // slotNetworkStatusChanged() will initiate the remounting.
  switch ( Smb4KSolidInterface::self()->networkStatus() )
  {
    case Smb4KSolidInterface::Connected:
    case Smb4KSolidInterface::Unknown:
    {
      priv->setHardwareReason( true );
      triggerRemounts();
      priv->setHardwareReason( false );
      break;
    }
    default:
    {
      break;
    }
  }
}


void Smb4KMounter::slotNetworkStatusChanged( Smb4KSolidInterface::ConnectionStatus status )
{
  switch ( status )
  {
    case Smb4KSolidInterface::Connected:
    {
      priv->setHardwareReason( true );
      triggerRemounts();
      priv->setHardwareReason( false );
      break;
    }
    case Smb4KSolidInterface::Disconnected:
    {
      priv->setHardwareReason( true );
      abortAll();
      saveSharesForRemount();
      unmountAllShares();
      priv->setHardwareReason( false );
      break;
    }
    case Smb4KSolidInterface::Unknown:
    {
      priv->setHardwareReason( true );
      triggerRemounts();
      priv->setHardwareReason( false );
      break;
    }
    default:
    {
      break;
    }
  }
}

#include "smb4kmounter.moc"
