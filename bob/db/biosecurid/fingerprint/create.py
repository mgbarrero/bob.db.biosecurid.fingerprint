#!/usr/bin/env python
# vim: set fileencoding=utf-8 :
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

"""This script creates the BiosecurId database in a single pass.
"""

import os

from .models import *

# clients
userid_training = range(1001,1601)
userid_dev_clients = range(1601, 2151)
userid_dev_impostors = range(2151, 2201)
userid_eval_clients = range(2201, 2561)
userid_eval_impostors = range(2561, 2601)


def nodot(item):
  """Can be used to ignore hidden files, starting with the . character."""
  return item[0] != '.'

def add_clients(session, verbose):
  """Add clients to the BiosecurId database."""
  users_list = (userid_training, userid_dev_clients, userid_dev_impostors, userid_eval_clients, userid_eval_impostors)
  group_choices = ('world', 'clientDev','impostorDev','clientEval','impostorEval')

  if verbose: print("Adding users...")
  for g, group in enumerate(group_choices):
    for cid in users_list[g]:
      if verbose>1: print("  Adding user '%d' on '%s' group" % (cid,group))
      
      session.add(Client(cid, group))

def add_files(session, imagedir, verbose):
  """Add files to the BiosecurId database."""

  def add_file(session, basename, userdir, sessiondir, realUser, realShot, finger, sensor):
    """Parse a single filename and add it to the list."""
    session.add(File(realUser, os.path.join(userdir, sessiondir, basename, finger, sensor), int(sessiondir[-1]), realShot, finger, sensor))

  for userdir in os.listdir(imagedir):
    sdirs = os.listdir(os.path.join(imagedir,userdir))
    sessiondirs = [v for v in sdirs if os.path.isdir(os.path.join(imagedir,userdir,v))]
       
    for sessiondir in sessiondirs:
      #if verbose: print("Adding files of sub-dir '%s'..." % subdir)

      filenames = os.listdir(os.path.join(imagedir,userdir,sessiondir))
      for filename in filenames:
        basename, extension = os.path.splitext(filename)
        if extension == '.bmp' and 'fo' in basename:
          if verbose>1: print("  Adding file '%s'..." % (basename))
          shotid = int(basename[-2:])
          userid = int(userdir[-3:])
          if shotid == 1:
            realShot = 1
            realUser = 4*userid - 3 + 1000
            finger = 'ri'
          elif shotid == 5:
            realShot = 2
            realUser = 4*userid - 3 + 1000
            finger = 'ri'
          elif shotid == 9:
            realShot = 3
            realUser = 4*userid - 3 + 1000
            finger = 'ri'
          elif shotid == 13:
            realShot = 4
            realUser = 4*userid - 3 + 1000
            finger = 'ri'
          
          elif shotid == 2:
            realShot = 1
            realUser = 4*userid - 2 + 1000
            finger = 'rm'
          elif shotid == 6:
            realShot = 2
            realUser = 4*userid - 2 + 1000
            finger = 'rm'
          elif shotid == 10:
            realShot = 3
            realUser = 4*userid - 2 + 1000
            finger = 'rm'
          elif shotid == 14:
            realShot = 4
            realUser = 4*userid - 2 + 1000
            finger = 'rm'
          
          elif shotid == 3:
            realShot = 1
            realUser = 4*userid - 1 + 1000
            finger = 'li'
          elif shotid == 7:
            realShot = 2
            realUser = 4*userid - 1 + 1000
            finger = 'li'
          elif shotid == 11:
            realShot = 3
            realUser = 4*userid - 1 + 1000
            finger = 'li'
          elif shotid == 15:
            realShot = 4
            realUser = 4*userid - 1 + 1000
            finger = 'li'
          
          elif shotid == 4:
            realShot = 1
            realUser = 4*userid + 1000
            finger = 'lm'
          elif shotid == 8:
            realShot = 2
            realUser = 4*userid + 1000
            finger = 'lm'
          elif shotid == 12:
            realShot = 3
            realUser = 4*userid + 1000
            finger = 'lm'
          elif shotid == 16:
            realShot = 4
            realUser = 4*userid + 1000
            finger = 'lm'
          
          add_file(session, basename, userdir, sessiondir, realUser, realShot, finger, 'optical')
        
        elif extension == '.bmp' and 'ft' in basename:
          if verbose>1: print("  Adding file '%s'..." % (basename))
          shotid = int(basename[-2:])
          userid = int(userdir[-3:])
          if shotid == 1:
            realShot = 1
            realUser = 4*userid - 3 + 1000
            finger = 'ri'
          elif shotid == 5:
            realShot = 2
            realUser = 4*userid - 3 + 1000
            finger = 'ri'
          elif shotid == 9:
            realShot = 3
            realUser = 4*userid - 3 + 1000
            finger = 'ri'
          elif shotid == 13:
            realShot = 4
            realUser = 4*userid - 3 + 1000
            finger = 'ri'
          
          elif shotid == 2:
            realShot = 1
            realUser = 4*userid - 2 + 1000
            finger = 'rm'
          elif shotid == 6:
            realShot = 2
            realUser = 4*userid - 2 + 1000
            finger = 'rm'
          elif shotid == 10:
            realShot = 3
            realUser = 4*userid - 2 + 1000
            finger = 'rm'
          elif shotid == 14:
            realShot = 4
            realUser = 4*userid - 2 + 1000
            finger = 'rm'
          
          elif shotid == 3:
            realShot = 1
            realUser = 4*userid - 1 + 1000
            finger = 'li'
          elif shotid == 7:
            realShot = 2
            realUser = 4*userid - 1 + 1000
            finger = 'li'
          elif shotid == 11:
            realShot = 3
            realUser = 4*userid - 1 + 1000
            finger = 'li'
          elif shotid == 15:
            realShot = 4
            realUser = 4*userid - 1 + 1000
            finger = 'li'
          
          elif shotid == 4:
            realShot = 1
            realUser = 4*userid + 1000
            finger = 'lm'
          elif shotid == 8:
            realShot = 2
            realUser = 4*userid + 1000
            finger = 'lm'
          elif shotid == 12:
            realShot = 3
            realUser = 4*userid + 1000
            finger = 'lm'
          elif shotid == 16:
            realShot = 4
            realUser = 4*userid + 1000
            finger = 'lm'
          
          add_file(session, basename, userdir, sessiondir, realUser, realShot, finger, 'thermal')
          



def add_protocols(session, verbose):
  """Adds protocols"""

  # 1. DEFINITIONS
  enroll_session = [1, 2]
  client_probe_session = [3, 4]
  protocols = ['Optical_All', 'Optical_RightIndex', 'Optical_LeftIndex', 'Optical_RightMiddle', 'Optical_LeftMiddle', 'Thermal_All', 'Thermal_RightIndex', 'Thermal_LeftIndex', 'Thermal_RightMiddle', 'Thermal_LeftMiddle']

  # 2. ADDITIONS TO THE SQL DATABASE
  protocolPurpose_list = [('world', 'train'), ('dev', 'enrol'), ('dev', 'probe'), ('eval', 'enrol'), ('eval', 'probe')]
  for proto in protocols:
    p = Protocol(proto)
    # Add protocol
    if verbose: print("Adding protocol %s..." % (proto))
    session.add(p)
    session.flush()
    session.refresh(p)
    
    # Add protocol purposes
    for key in range(len(protocolPurpose_list)):
      purpose = protocolPurpose_list[key]
      pu = ProtocolPurpose(p.id, purpose[0], purpose[1])
      if verbose>1: print("  Adding protocol purpose ('%s','%s')..." % (purpose[0], purpose[1]))
      session.add(pu)
      session.flush()
      session.refresh(pu)

      # Add files attached with this protocol purpose
      if(key == 0): # world
        if proto == 'Optical_RightIndex':
          q = session.query(File).filter(and_(File.finger == 'ri', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'world')
        elif proto == 'Optical_LeftIndex':
          q = session.query(File).filter(and_(File.finger == 'li', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'world')
        elif proto == 'Optical_RightMiddle':
          q = session.query(File).filter(and_(File.finger == 'rm', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'world')
        elif proto == 'Optical_LeftMiddle':
          q = session.query(File).filter(and_(File.finger == 'lm', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'world')
        elif proto == 'Optical_All':
          q = session.query(File).filter(File.sensor == 'optical').join(Client).filter(Client.sgroup == 'world')
        elif proto == 'Thermal_RightIndex':
          q = session.query(File).filter(and_(File.finger == 'ri', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'world')
        elif proto == 'Thermal_LeftIndex':
          q = session.query(File).filter(and_(File.finger == 'li', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'world')
        elif proto == 'Thermal_RightMiddle':
          q = session.query(File).filter(and_(File.finger == 'rm', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'world')
        elif proto == 'Thermal_LeftMiddle':
          q = session.query(File).filter(and_(File.finger == 'lm', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'world')
        elif proto == 'Thermal_All':
          q = session.query(File).filter(File.sensor == 'thermal').join(Client).filter(Client.sgroup == 'world')
        for k in q:
          if verbose>1: print("    Adding protocol file '%s'..." % (k.path))
          pu.files.append(k)

      elif(key == 1): #dev enroll
        if proto == 'Optical_RightIndex':
          q = session.query(File).filter(and_(File.finger == 'ri', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'clientDev').filter(File.session_id.in_(enroll_session))
        elif proto == 'Optical_LeftIndex':
          q = session.query(File).filter(and_(File.finger == 'li', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'clientDev').filter(File.session_id.in_(enroll_session))
        elif proto == 'Optical_RightMiddle':
          q = session.query(File).filter(and_(File.finger == 'rm', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'clientDev').filter(File.session_id.in_(enroll_session))
        elif proto == 'Optical_LeftMiddle':
          q = session.query(File).filter(and_(File.finger == 'lm', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'clientDev').filter(File.session_id.in_(enroll_session))
        elif proto == 'Optical_All':
          q = session.query(File).filter(File.sensor == 'optical').join(Client).filter(Client.sgroup == 'clientDev').filter(File.session_id.in_(enroll_session))
        elif proto == 'Thermal_RightIndex':
          q = session.query(File).filter(and_(File.finger == 'ri', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'clientDev').filter(File.session_id.in_(enroll_session))
        elif proto == 'Thermal_LeftIndex':
          q = session.query(File).filter(and_(File.finger == 'li', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'clientDev').filter(File.session_id.in_(enroll_session))
        elif proto == 'Thermal_RightMiddle':
          q = session.query(File).filter(and_(File.finger == 'rm', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'clientDev').filter(File.session_id.in_(enroll_session))
        elif proto == 'Thermal_LeftMiddle':
          q = session.query(File).filter(and_(File.finger == 'lm', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'clientDev').filter(File.session_id.in_(enroll_session))
        elif proto == 'Thermal_All':
          q = session.query(File).filter(File.sensor == 'thermal').join(Client).filter(Client.sgroup == 'clientDev').filter(File.session_id.in_(enroll_session))
        
        for k in q:
          if verbose>1: print("    Adding protocol file '%s'..." % (k.path))
          pu.files.append(k)

      elif(key == 2): #dev probe
        if proto == 'Optical_RightIndex':
          q = session.query(File).filter(and_(File.finger == 'ri', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'clientDev').filter(File.session_id.in_(client_probe_session))
        elif proto == 'Optical_LeftIndex':
          q = session.query(File).filter(and_(File.finger == 'li', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'clientDev').filter(File.session_id.in_(client_probe_session))
        elif proto == 'Optical_RightMiddle':
          q = session.query(File).filter(and_(File.finger == 'rm', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'clientDev').filter(File.session_id.in_(client_probe_session))
        elif proto == 'Optical_LeftMiddle':
          q = session.query(File).filter(and_(File.finger == 'lm', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'clientDev').filter(File.session_id.in_(client_probe_session))
        elif proto == 'Optical_All':
          q = session.query(File).filter(File.sensor == 'optical').join(Client).filter(Client.sgroup == 'clientDev').filter(File.session_id.in_(client_probe_session))
        elif proto == 'Thermal_RightIndex':
          q = session.query(File).filter(and_(File.finger == 'ri', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'clientDev').filter(File.session_id.in_(client_probe_session))
        elif proto == 'Thermal_LeftIndex':
          q = session.query(File).filter(and_(File.finger == 'li', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'clientDev').filter(File.session_id.in_(client_probe_session))
        elif proto == 'Thermal_RightMiddle':
          q = session.query(File).filter(and_(File.finger == 'rm', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'clientDev').filter(File.session_id.in_(client_probe_session))
        elif proto == 'Thermal_LeftMiddle':
          q = session.query(File).filter(and_(File.finger == 'lm', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'clientDev').filter(File.session_id.in_(client_probe_session))
        elif proto == 'Thermal_All':
          q = session.query(File).filter(File.sensor == 'thermal').join(Client).filter(Client.sgroup == 'clientDev').filter(File.session_id.in_(client_probe_session))
        
        for k in q:
          if verbose>1: print("    Adding protocol file '%s'..." % (k.path))
          pu.files.append(k)
        
        if proto == 'Optical_RightIndex':
          q = session.query(File).filter(and_(File.finger == 'ri', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'impostorDev')
        elif proto == 'Optical_LeftIndex':
          q = session.query(File).filter(and_(File.finger == 'li', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'impostorDev')
        elif proto == 'Optical_RightMiddle':
          q = session.query(File).filter(and_(File.finger == 'rm', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'impostorDev')
        elif proto == 'Optical_LeftMiddle':
          q = session.query(File).filter(and_(File.finger == 'lm', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'impostorDev')
        elif proto == 'Optical_All':
          q = session.query(File).filter(File.sensor == 'optical').join(Client).filter(Client.sgroup == 'impostorDev')
        elif proto == 'Thermal_RightIndex':
          q = session.query(File).filter(and_(File.finger == 'ri', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'impostorDev')
        elif proto == 'Thermal_LeftIndex':
          q = session.query(File).filter(and_(File.finger == 'li', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'impostorDev')
        elif proto == 'Thermal_RightMiddle':
          q = session.query(File).filter(and_(File.finger == 'rm', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'impostorDev')
        elif proto == 'Thermal_LeftMiddle':
          q = session.query(File).filter(and_(File.finger == 'lm', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'impostorDev')
        elif proto == 'Thermal_All':
          q = session.query(File).filter(File.sensor == 'thermal').join(Client).filter(Client.sgroup == 'impostorDev')
        for k in q:
          if verbose>1: print("    Adding protocol file '%s'..." % (k.path))
          pu.files.append(k)

      elif(key == 3): #test enrol
        if proto == 'Optical_RightIndex':
          q = session.query(File).filter(and_(File.finger == 'ri', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'clientEval').filter(File.session_id.in_(enroll_session))
        elif proto == 'Optical_LeftIndex':
          q = session.query(File).filter(and_(File.finger == 'li', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'clientEval').filter(File.session_id.in_(enroll_session))
        elif proto == 'Optical_RightMiddle':
          q = session.query(File).filter(and_(File.finger == 'rm', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'clientEval').filter(File.session_id.in_(enroll_session))
        elif proto == 'Optical_LeftMiddle':
          q = session.query(File).filter(and_(File.finger == 'lm', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'clientEval').filter(File.session_id.in_(enroll_session))
        elif proto == 'Optical_All':
          q = session.query(File).filter(File.sensor == 'optical').join(Client).filter(Client.sgroup == 'clientEval').filter(File.session_id.in_(enroll_session))
        elif proto == 'Thermal_RightIndex':
          q = session.query(File).filter(and_(File.finger == 'ri', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'clientEval').filter(File.session_id.in_(enroll_session))
        elif proto == 'Thermal_LeftIndex':
          q = session.query(File).filter(and_(File.finger == 'li', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'clientEval').filter(File.session_id.in_(enroll_session))
        elif proto == 'Thermal_RightMiddle':
          q = session.query(File).filter(and_(File.finger == 'rm', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'clientEval').filter(File.session_id.in_(enroll_session))
        elif proto == 'Thermal_LeftMiddle':
          q = session.query(File).filter(and_(File.finger == 'lm', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'clientEval').filter(File.session_id.in_(enroll_session))
        elif proto == 'Thermal_All':
          q = session.query(File).filter(File.sensor == 'thermal').join(Client).filter(Client.sgroup == 'clientEval').filter(File.session_id.in_(enroll_session))
        for k in q:
          if verbose>1: print("    Adding protocol file '%s'..." % (k.path))
          pu.files.append(k)

      elif(key == 4): #test probe
        if proto == 'Optical_RightIndex':
          q = session.query(File).filter(and_(File.finger == 'ri', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'clientEval').filter(File.session_id.in_(client_probe_session))
        elif proto == 'Optical_LeftIndex':
          q = session.query(File).filter(and_(File.finger == 'li', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'clientEval').filter(File.session_id.in_(client_probe_session))
        elif proto == 'Optical_RightMiddle':
          q = session.query(File).filter(and_(File.finger == 'rm', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'clientEval').filter(File.session_id.in_(client_probe_session))
        elif proto == 'Optical_LeftMiddle':
          q = session.query(File).filter(and_(File.finger == 'lm', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'clientEval').filter(File.session_id.in_(client_probe_session))
        elif proto == 'Optical_All':
          q = session.query(File).filter(File.sensor == 'optical').join(Client).filter(Client.sgroup == 'clientEval').filter(File.session_id.in_(client_probe_session))
        elif proto == 'Thermal_RightIndex':
          q = session.query(File).filter(and_(File.finger == 'ri', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'clientEval').filter(File.session_id.in_(client_probe_session))
        elif proto == 'Thermal_LeftIndex':
          q = session.query(File).filter(and_(File.finger == 'li', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'clientEval').filter(File.session_id.in_(client_probe_session))
        elif proto == 'Thermal_RightMiddle':
          q = session.query(File).filter(and_(File.finger == 'rm', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'clientEval').filter(File.session_id.in_(client_probe_session))
        elif proto == 'Thermal_LeftMiddle':
          q = session.query(File).filter(and_(File.finger == 'lm', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'clientEval').filter(File.session_id.in_(client_probe_session))
        elif proto == 'Thermal_All':
          q = session.query(File).filter(File.sensor == 'thermal').join(Client).filter(Client.sgroup == 'clientEval').filter(File.session_id.in_(client_probe_session))
        for k in q:
          if verbose>1: print("    Adding protocol file '%s'..." % (k.path))
          pu.files.append(k)
        
        if proto == 'Optical_RightIndex':
          q = session.query(File).filter(and_(File.finger == 'ri', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'impostorEval')
        elif proto == 'Optical_LeftIndex':
          q = session.query(File).filter(and_(File.finger == 'li', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'impostorEval')
        elif proto == 'Optical_RightMiddle':
          q = session.query(File).filter(and_(File.finger == 'rm', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'impostorEval')
        elif proto == 'Optical_LeftMiddle':
          q = session.query(File).filter(and_(File.finger == 'lm', File.sensor == 'optical')).join(Client).filter(Client.sgroup == 'impostorEval')
        elif proto == 'Optical_All':
          q = session.query(File).filter(File.sensor == 'optical').join(Client).filter(Client.sgroup == 'impostorEval')
        elif proto == 'Thermal_RightIndex':
          q = session.query(File).filter(and_(File.finger == 'ri', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'impostorEval')
        elif proto == 'Thermal_LeftIndex':
          q = session.query(File).filter(and_(File.finger == 'li', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'impostorEval')
        elif proto == 'Thermal_RightMiddle':
          q = session.query(File).filter(and_(File.finger == 'rm', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'impostorEval')
        elif proto == 'Thermal_LeftMiddle':
          q = session.query(File).filter(and_(File.finger == 'lm', File.sensor == 'thermal')).join(Client).filter(Client.sgroup == 'impostorEval')
        elif proto == 'Thermal_All':
          q = session.query(File).filter(File.sensor == 'thermal').join(Client).filter(Client.sgroup == 'impostorEval')
        
        for k in q:
          if verbose>1: print("    Adding protocol file '%s'..." % (k.path))
          pu.files.append(k)



def create_tables(args):
  """Creates all necessary tables (only to be used at the first time)"""

  from bob.db.base.utils import create_engine_try_nolock
  engine = create_engine_try_nolock(args.type, args.files[0], echo=(args.verbose > 2))
  Base.metadata.create_all(engine)

# Driver API
# ==========

def create(args):
  """Creates or re-creates this database"""

  from bob.db.base.utils import session_try_nolock

  dbfile = args.files[0]

  if args.recreate:
    if args.verbose and os.path.exists(dbfile):
      print('unlinking %s...' % dbfile)
    if os.path.exists(dbfile): os.unlink(dbfile)

  if not os.path.exists(os.path.dirname(dbfile)):
    os.makedirs(os.path.dirname(dbfile))

  # the real work...
  create_tables(args)
  s = session_try_nolock(args.type, dbfile, echo=(args.verbose > 2))
  add_clients(s, args.verbose)
  add_files(s, args.imagedir, args.verbose)
  add_protocols(s, args.verbose)
  s.commit()
  s.close()

def add_command(subparsers):
  """Add specific subcommands that the action "create" can use"""

  parser = subparsers.add_parser('create', help=create.__doc__)

  parser.add_argument('-R', '--recreate', action='store_true', help="If set, I'll first erase the current database")
  parser.add_argument('-v', '--verbose', action='count', help="Do SQL operations in a verbose way?")
  parser.add_argument('-D', '--imagedir', metavar='DIR', default='/home/bob/dataFingerprint/', help="Change the relative path to the directory containing the images of the BiosecurID database.")

  parser.set_defaults(func=create) #action
