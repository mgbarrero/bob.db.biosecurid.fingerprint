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

"""Table models and functionality for the BiosecurId database.
"""

import os, numpy
import bob.db.base.utils
from sqlalchemy import Table, Column, Integer, String, ForeignKey, or_, and_, not_
from bob.db.base.sqlalchemy_migration import Enum, relationship
from sqlalchemy.orm import backref
from sqlalchemy.ext.declarative import declarative_base

import bob.db.verification.utils

Base = declarative_base()

protocolPurpose_file_association = Table('protocolPurpose_file_association', Base.metadata,
  Column('protocolPurpose_id', Integer, ForeignKey('protocolPurpose.id')),
  Column('file_id',  Integer, ForeignKey('file.id')))

class Client(Base):
  """Database clients, marked by an integer identifier and the group they belong to"""

  __tablename__ = 'client'

  # Key identifier for the client
  id = Column(Integer, primary_key=True)
  # Group to which the client belongs to
  # There is no separate training, development and evaluation group in XM2VTS.
  # They are split into client, impostorDev and impostorEval (resp. labeled
  # "impostor evaluation" and "impostor test" in the original paper describing the database)
  group_choices = ('world', 'clientDev','impostorDev','clientEval','impostorEval')
  sgroup = Column(Enum(*group_choices)) # do NOT use group (SQL keyword)
  
  def __init__(self, id, group):
    self.id = id
    self.sgroup = group

  def __repr__(self):
    return "Client(%d, '%s')" % (self.id, self.sgroup)

class File(Base, bob.db.verification.utils.File):
  """Generic file container"""

  __tablename__ = 'file'

  # Key identifier for the file
  id = Column(Integer, primary_key=True)
  # Key identifier of the client associated with this file
  client_id = Column(Integer, ForeignKey('client.id')) # for SQL
  # Unique path to this file inside the database
  path = Column(String(100), unique=True)
  # Session identifier
  session_id = Column(Integer)
  # Shot identifier
  shot_id = Column(Integer)
  # Finger identifier - left/right, index/middle
  finger_choices = ('li', 'lm', 'ri', 'rm') 
  finger = Column(Enum(*finger_choices)) 
  # Sensor identifier
  sensor_choices = ('optical', 'thermal') 
  sensor = Column(Enum(*sensor_choices))
  
  # For Python: A direct link to the client object that this file belongs to
  client = relationship("Client", backref=backref("files", order_by=id))

  def __init__(self, client_id, path, session_id, shot_id, finger, sensor):
    # call base class constructor
    bob.db.verification.utils.File.__init__(self, client_id = client_id, path = path)

    self.session_id = session_id
    self.shot_id = shot_id
    self.finger = finger
    self.sensor = sensor


class Protocol(Base):
  """BiosecurId protocols"""

  __tablename__ = 'protocol'

  # Unique identifier for this protocol object
  id = Column(Integer, primary_key=True)
  # Name of the protocol associated with this object
  name = Column(String(20), unique=True)

  def __init__(self, name):
    self.name = name

  def __repr__(self):
    return "Protocol('%s')" % (self.name,)

class ProtocolPurpose(Base):
  """BiosecurId protocol purposes"""

  __tablename__ = 'protocolPurpose'

  # Unique identifier for this protocol purpose object
  id = Column(Integer, primary_key=True)
  # Id of the protocol associated with this protocol purpose object
  protocol_id = Column(Integer, ForeignKey('protocol.id')) # for SQL
  # Group associated with this protocol purpose object
  group_choices = ('world', 'dev', 'eval')
  sgroup = Column(Enum(*group_choices))
  # Purpose associated with this protocol purpose object
  purpose_choices = ('train', 'enrol', 'probe')
  purpose = Column(Enum(*purpose_choices))

  # For Python: A direct link to the Protocol object that this ProtocolPurpose belongs to
  protocol = relationship("Protocol", backref=backref("purposes", order_by=id))
  # For Python: A direct link to the File objects associated with this ProtcolPurpose
  files = relationship("File", secondary=protocolPurpose_file_association, backref=backref("protocolPurposes", order_by=id))

  def __init__(self, protocol_id, sgroup, purpose):
    self.protocol_id = protocol_id
    self.sgroup = sgroup
    self.purpose = purpose

  def __repr__(self):
    return "ProtocolPurpose('%s', '%s', '%s')" % (self.protocol.name, self.sgroup, self.purpose)

