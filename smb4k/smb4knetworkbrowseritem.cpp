/***************************************************************************
    smb4knetworkbrowseritem  -  Smb4K's network browser list item.
                             -------------------
    begin                : Mo Jan 8 2007
    copyright            : (C) 2007-2016 by Alexander Reinholdt
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
#include "smb4knetworkbrowseritem.h"
#include "core/smb4kglobal.h"
#include "core/smb4kworkgroup.h"
#include "core/smb4khost.h"
#include "core/smb4kshare.h"

// Qt includes
#include <QDebug>
#include <QBrush>
#include <QApplication>

using namespace Smb4KGlobal;


Smb4KNetworkBrowserItem::Smb4KNetworkBrowserItem(QTreeWidget *parent, Smb4KBasicNetworkItem *item)
: QTreeWidgetItem(parent, item->type()), m_item(item)
{
  m_tooltip   = new Smb4KToolTip();
  m_tooltip->setup(Smb4KToolTip::NetworkBrowser, m_item);
  
  switch (m_item->type())
  {
    case Workgroup:
    {
      Smb4KWorkgroup *workgroup = static_cast<Smb4KWorkgroup *>(m_item);
      setText(Network, workgroup->workgroupName());
      setIcon(Network, workgroup->icon());
      break;
    }
    case Host:
    {
      Smb4KHost *host = static_cast<Smb4KHost *>(m_item);
      setText(Network, host->hostName());
      setText(IP, host->ip());
      setText(Comment, host->comment());
      
      if (host->isMasterBrowser())
      {
        for (int i = 0; i < columnCount(); ++i)
        {
          QBrush brush(Qt::darkBlue);
          setForeground(i, brush);
        }
      }
      else
      {
        // Do nothing
      }

      setIcon(Network, host->icon());
      break;
    }
    case Share:
    {
      Smb4KShare *share = static_cast<Smb4KShare *>(m_item);
      setText(Network, share->shareName());
      setText(Type, share->translatedTypeString());
      setText(Comment, share->comment());

      if (!share->isPrinter() && share->isMounted())
      {
        for (int i = 0; i < columnCount(); ++i)
        {
          QFont f = font(i);
          f.setItalic(true);
          setFont(i, f);
        }
      }
      else
      {
        // Do nothing
      }
      
      setIcon(Network, share->icon());
      break;
    }
    default:
    {
      break;
    }
  }
}


Smb4KNetworkBrowserItem::Smb4KNetworkBrowserItem(QTreeWidgetItem *parent, Smb4KBasicNetworkItem *item)
: QTreeWidgetItem(parent, item->type()), m_item(item)
{
  m_tooltip   = new Smb4KToolTip();
  m_tooltip->setup(Smb4KToolTip::NetworkBrowser, m_item);
  
  switch (m_item->type())
  {
    case Workgroup:
    {
      Smb4KWorkgroup *workgroup = static_cast<Smb4KWorkgroup *>(m_item);
      setText(Network, workgroup->workgroupName());
      setIcon(Network, workgroup->icon());
      break;
    }
    case Host:
    {
      Smb4KHost *host = static_cast<Smb4KHost *>(m_item);
      setText(Network, host->hostName());
      setText(IP, host->ip());
      setText(Comment, host->comment());
      
      if (host->isMasterBrowser())
      {
        for (int i = 0; i < columnCount(); ++i)
        {
          QBrush brush(Qt::darkBlue);
          setForeground(i, brush);
        }
      }
      else
      {
        // Do nothing
      }

      setIcon(Network, host->icon());
      break;
    }
    case Share:
    {
      Smb4KShare *share = static_cast<Smb4KShare *>(m_item);
      setText(Network, share->shareName());
      setText(Type, share->translatedTypeString());
      setText(Comment, share->comment());

      if (!share->isPrinter() && share->isMounted())
      {
        for (int i = 0; i < columnCount(); ++i)
        {
          QFont f = font(i);
          f.setItalic(true);
          setFont(i, f);
        }
      }
      else
      {
        // Do nothing
      }
      
      setIcon(Network, share->icon());
      break;
    }
    default:
    {
      break;
    }
  }
}



Smb4KNetworkBrowserItem::~Smb4KNetworkBrowserItem()
{
  delete m_tooltip;
}


Smb4KWorkgroup *Smb4KNetworkBrowserItem::workgroupItem()
{
  if (!m_item || (m_item && m_item->type() != Workgroup))
  {
    return 0;
  }
  else
  {
    // Do nothing
  }
  
  return static_cast<Smb4KWorkgroup *>(m_item);
}


Smb4KHost *Smb4KNetworkBrowserItem::hostItem()
{
  if (!m_item || (m_item && m_item->type() != Host))
  {
    return 0;
  }
  else
  {
    // Do nothing
  }
  
  return static_cast<Smb4KHost *>(m_item);
}


Smb4KShare *Smb4KNetworkBrowserItem::shareItem()
{
  if (!m_item || (m_item && m_item->type() != Share))
  {
    return 0;
  }
  else
  {
    // Do nothing
  }
  
  return static_cast<Smb4KShare *>(m_item);
}


Smb4KBasicNetworkItem* Smb4KNetworkBrowserItem::networkItem()
{
  return m_item;
}


void Smb4KNetworkBrowserItem::update()
{
  switch (m_item->type())
  {
    case Host:
    {
      Smb4KHost *host = static_cast<Smb4KHost *>(m_item);
      
      // Adjust the item's color.
      if (host->isMasterBrowser())
      {
        for (int i = 0; i < columnCount(); ++i)
        {
          QBrush brush(Qt::darkBlue);
          setForeground(i, brush);
        }
      }
      else
      {
        for (int i = 0; i < columnCount(); ++i)
        {
          QBrush brush = QApplication::palette().text();
          setForeground(i, brush);
        }          
      }
        
      // Set the IP address
      setText(IP, host->ip());

      // Set the comment 
      setText(Comment, host->comment());
      break;
    }
    case Share:
    {
      Smb4KShare *share = static_cast<Smb4KShare *>(m_item);
      
      // Set the comment
      setText(Comment, share->comment());
    
      // Set the icon
      setIcon(Network, share->icon());
            
      // Set the font
      for (int i = 0; i < columnCount(); ++i)
      {
        QFont f = font(i);
        f.setItalic(share->isMounted());
        setFont(i, f);
      }
        
      break;
    }
    default:
    {
      break;
    }
  }
    
  m_tooltip->update(Smb4KToolTip::NetworkBrowser, m_item);
}


Smb4KToolTip* Smb4KNetworkBrowserItem::tooltip()
{
  return m_tooltip;
}

