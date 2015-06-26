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

"""A few checks at the Biosecurid database.
"""

import os, sys
import unittest
import bob.db.biosecurid.fingerprint

class BiosecuridDatabaseTest(unittest.TestCase):
  """Performs various tests on the Biosecurid database."""

  def test01_clients(self):
    db = bob.db.biosecurid.fingerprint.Database()
    self.assertEqual(len(db.groups()), 3)
    self.assertEqual(len(db.clients()), 1600)
    self.assertEqual(len(db.clients(groups='dev')), 600)
    self.assertEqual(len(db.clients(groups='eval')), 400)
    self.assertEqual(len(db.clients(groups='world')), 600)
    self.assertEqual(len(db.clients(groups='impostorDev')), 50)
    self.assertEqual(len(db.clients(groups='impostorEval')), 40)
    self.assertEqual(len(db.models()), 910)
    self.assertEqual(len(db.models(groups='dev')), 550)
    self.assertEqual(len(db.models(groups='eval')), 360)


  def test02_objects(self):
    db = bob.db.biosecurid.fingerprint.Database()
    self.assertEqual(len(db.objects()), 51200)
    # Optical_All
    self.assertEqual(len(db.objects(protocol='Optical_All')), 25600)
    self.assertEqual(len(db.objects(protocol='Optical_All', groups='world')), 9600)
    self.assertEqual(len(db.objects(protocol='Optical_All', groups='dev')), 9600)
    self.assertEqual(len(db.objects(protocol='Optical_All', groups='dev', purposes='enrol')), 4400)
    self.assertEqual(len(db.objects(protocol='Optical_All', groups='dev', purposes='probe')), 5200)
    self.assertEqual(len(db.objects(protocol='Optical_All', groups='dev', purposes='probe', classes='client')), 4400)
    self.assertEqual(len(db.objects(protocol='Optical_All', groups='dev', purposes='probe', classes='impostor')), 800)
    self.assertEqual(len(db.objects(protocol='Optical_All', groups='dev', purposes='probe', model_ids=[1601])), 808)
    self.assertEqual(len(db.objects(protocol='Optical_All', groups='dev', purposes='probe', model_ids=[1601], classes='client')), 8)
    self.assertEqual(len(db.objects(protocol='Optical_All', groups='dev', purposes='probe', model_ids=[1601], classes='impostor')), 800)
    self.assertEqual(len(db.objects(protocol='Optical_All', groups='dev', purposes='probe', model_ids=[1601,1602])), 816)
    self.assertEqual(len(db.objects(protocol='Optical_All', groups='dev', purposes='probe', model_ids=[1601,1602], classes='client')), 16)
    self.assertEqual(len(db.objects(protocol='Optical_All', groups='dev', purposes='probe', model_ids=[1601,1602], classes='impostor')), 800)
    self.assertEqual(len(db.objects(protocol='Optical_All', groups='eval')), 6400)
    self.assertEqual(len(db.objects(protocol='Optical_All', groups='eval', purposes='enrol')), 2880)
    self.assertEqual(len(db.objects(protocol='Optical_All', groups='eval', purposes='probe')), 3520)
    self.assertEqual(len(db.objects(protocol='Optical_All', groups='eval', purposes='probe', classes='client')), 2880)
    self.assertEqual(len(db.objects(protocol='Optical_All', groups='eval', purposes='probe', classes='impostor')), 640)
    self.assertEqual(len(db.objects(protocol='Optical_All', groups='eval', purposes='probe', model_ids=[2201])), 648)
    self.assertEqual(len(db.objects(protocol='Optical_All', groups='eval', purposes='probe', model_ids=[2201], classes='client')), 8)
    self.assertEqual(len(db.objects(protocol='Optical_All', groups='eval', purposes='probe', model_ids=[2201], classes='impostor')), 640)
    self.assertEqual(len(db.objects(protocol='Optical_All', groups='eval', purposes='probe', model_ids=[2201,2202])), 656)
    self.assertEqual(len(db.objects(protocol='Optical_All', groups='eval', purposes='probe', model_ids=[2201,2202], classes='client')), 16)
    self.assertEqual(len(db.objects(protocol='Optical_All', groups='eval', purposes='probe', model_ids=[2201,2202], classes='impostor')), 640)


    # Optical_RightIndex
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex')), 6400)
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex', groups='world')), 2400)
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex', groups='dev')), 2400)
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex', groups='dev', purposes='enrol')), 1104)
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex', groups='dev', purposes='probe')), 1296)
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex', groups='dev', purposes='probe', classes='client')), 1104)
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex', groups='dev', purposes='probe', classes='impostor')), 192)
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex', groups='dev', purposes='probe', model_ids=[1601])), 200)
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex', groups='dev', purposes='probe', model_ids=[1601], classes='client')), 8)
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex', groups='dev', purposes='probe', model_ids=[1601], classes='impostor')), 192)
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex', groups='dev', purposes='probe', model_ids=[1601,1605])), 208)
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex', groups='dev', purposes='probe', model_ids=[1601,1605], classes='client')), 16)
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex', groups='dev', purposes='probe', model_ids=[1601,1605], classes='impostor')), 192)
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex', groups='eval')), 1600)
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex', groups='eval', purposes='enrol')), 720)
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex', groups='eval', purposes='probe')), 880)
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex', groups='eval', purposes='probe', classes='client')), 720)
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex', groups='eval', purposes='probe', classes='impostor')), 160)
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex', groups='eval', purposes='probe', model_ids=[2201])), 168)
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex', groups='eval', purposes='probe', model_ids=[2201], classes='client')), 8)
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex', groups='eval', purposes='probe', model_ids=[2201], classes='impostor')), 160)
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex', groups='eval', purposes='probe', model_ids=[2201,2205])), 176)
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex', groups='eval', purposes='probe', model_ids=[2201,2205], classes='client')), 16)
    self.assertEqual(len(db.objects(protocol='Optical_RightIndex', groups='eval', purposes='probe', model_ids=[2201,2205], classes='impostor')), 160)
    
    
    # Optical_RightMiddle
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle')), 6400)
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle', groups='world')), 2400)
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle', groups='dev')), 2400)
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle', groups='dev', purposes='enrol')), 1104)
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle', groups='dev', purposes='probe')), 1296)
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle', groups='dev', purposes='probe', classes='client')), 1104)
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle', groups='dev', purposes='probe', classes='impostor')), 192)
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle', groups='dev', purposes='probe', model_ids=[1602])), 200)
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle', groups='dev', purposes='probe', model_ids=[1602], classes='client')), 8)
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle', groups='dev', purposes='probe', model_ids=[1602], classes='impostor')), 192)
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle', groups='dev', purposes='probe', model_ids=[1602,1606])), 208)
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle', groups='dev', purposes='probe', model_ids=[1602,1606], classes='client')), 16)
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle', groups='dev', purposes='probe', model_ids=[1602,1606], classes='impostor')), 192)
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle', groups='eval')), 1600)
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle', groups='eval', purposes='enrol')), 720)
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle', groups='eval', purposes='probe')), 880)
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle', groups='eval', purposes='probe', classes='client')), 720)
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle', groups='eval', purposes='probe', classes='impostor')), 160)
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle', groups='eval', purposes='probe', model_ids=[2202])), 168)
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle', groups='eval', purposes='probe', model_ids=[2202], classes='client')), 8)
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle', groups='eval', purposes='probe', model_ids=[2202], classes='impostor')), 160)
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle', groups='eval', purposes='probe', model_ids=[2202,2206])), 176)
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle', groups='eval', purposes='probe', model_ids=[2202,2206], classes='client')), 16)
    self.assertEqual(len(db.objects(protocol='Optical_RightMiddle', groups='eval', purposes='probe', model_ids=[2202,2206], classes='impostor')), 160)
    
    
    
    # Optical_LeftIndex
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex')), 6400)
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex', groups='world')), 2400)
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex', groups='dev')), 2400)
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex', groups='dev', purposes='enrol')), 1096)
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex', groups='dev', purposes='probe')), 1304)
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex', groups='dev', purposes='probe', classes='client')), 1096)
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex', groups='dev', purposes='probe', classes='impostor')), 208)
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex', groups='dev', purposes='probe', model_ids=[1603])), 216)
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex', groups='dev', purposes='probe', model_ids=[1603], classes='client')), 8)
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex', groups='dev', purposes='probe', model_ids=[1603], classes='impostor')), 208)
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex', groups='dev', purposes='probe', model_ids=[1603,1607])), 224)
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex', groups='dev', purposes='probe', model_ids=[1603,1607], classes='client')), 16)
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex', groups='dev', purposes='probe', model_ids=[1603,1607], classes='impostor')), 208)
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex', groups='eval')), 1600)
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex', groups='eval', purposes='enrol')), 720)
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex', groups='eval', purposes='probe')), 880)
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex', groups='eval', purposes='probe', classes='client')), 720)
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex', groups='eval', purposes='probe', classes='impostor')), 160)
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex', groups='eval', purposes='probe', model_ids=[2203])), 168)
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex', groups='eval', purposes='probe', model_ids=[2203], classes='client')), 8)
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex', groups='eval', purposes='probe', model_ids=[2203], classes='impostor')), 160)
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex', groups='eval', purposes='probe', model_ids=[2203,2207])), 176)
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex', groups='eval', purposes='probe', model_ids=[2203,2207], classes='client')), 16)
    self.assertEqual(len(db.objects(protocol='Optical_LeftIndex', groups='eval', purposes='probe', model_ids=[2203,2207], classes='impostor')), 160)
    
    
    
    # Optical_LeftMiddle
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle')), 6400)
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle', groups='world')), 2400)
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle', groups='dev')), 2400)
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle', groups='dev', purposes='enrol')), 1096)
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle', groups='dev', purposes='probe')), 1304)
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle', groups='dev', purposes='probe', classes='client')), 1096)
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle', groups='dev', purposes='probe', classes='impostor')), 208)
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle', groups='dev', purposes='probe', model_ids=[1604])), 216)
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle', groups='dev', purposes='probe', model_ids=[1604], classes='client')), 8)
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle', groups='dev', purposes='probe', model_ids=[1604], classes='impostor')), 208)
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle', groups='dev', purposes='probe', model_ids=[1604,1608])), 224)
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle', groups='dev', purposes='probe', model_ids=[1604,1608], classes='client')), 16)
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle', groups='dev', purposes='probe', model_ids=[1604,1608], classes='impostor')), 208)
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle', groups='eval')), 1600)
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle', groups='eval', purposes='enrol')), 720)
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle', groups='eval', purposes='probe')), 880)
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle', groups='eval', purposes='probe', classes='client')), 720)
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle', groups='eval', purposes='probe', classes='impostor')), 160)
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle', groups='eval', purposes='probe', model_ids=[2204])), 168)
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle', groups='eval', purposes='probe', model_ids=[2204], classes='client')), 8)
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle', groups='eval', purposes='probe', model_ids=[2204], classes='impostor')), 160)
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle', groups='eval', purposes='probe', model_ids=[2204,2208])), 176)
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle', groups='eval', purposes='probe', model_ids=[2204,2208], classes='client')), 16)
    self.assertEqual(len(db.objects(protocol='Optical_LeftMiddle', groups='eval', purposes='probe', model_ids=[2204,2208], classes='impostor')), 160)
    
    
    # Thermal_All
    self.assertEqual(len(db.objects(protocol='Thermal_All')), 25600)
    self.assertEqual(len(db.objects(protocol='Thermal_All', groups='world')), 9600)
    self.assertEqual(len(db.objects(protocol='Thermal_All', groups='dev')), 9600)
    self.assertEqual(len(db.objects(protocol='Thermal_All', groups='dev', purposes='enrol')), 4400)
    self.assertEqual(len(db.objects(protocol='Thermal_All', groups='dev', purposes='probe')), 5200)
    self.assertEqual(len(db.objects(protocol='Thermal_All', groups='dev', purposes='probe', classes='client')), 4400)
    self.assertEqual(len(db.objects(protocol='Thermal_All', groups='dev', purposes='probe', classes='impostor')), 800)
    self.assertEqual(len(db.objects(protocol='Thermal_All', groups='dev', purposes='probe', model_ids=[1601])), 808)
    self.assertEqual(len(db.objects(protocol='Thermal_All', groups='dev', purposes='probe', model_ids=[1601], classes='client')), 8)
    self.assertEqual(len(db.objects(protocol='Thermal_All', groups='dev', purposes='probe', model_ids=[1601], classes='impostor')), 800)
    self.assertEqual(len(db.objects(protocol='Thermal_All', groups='dev', purposes='probe', model_ids=[1601,1602])), 816)
    self.assertEqual(len(db.objects(protocol='Thermal_All', groups='dev', purposes='probe', model_ids=[1601,1602], classes='client')), 16)
    self.assertEqual(len(db.objects(protocol='Thermal_All', groups='dev', purposes='probe', model_ids=[1601,1602], classes='impostor')), 800)
    self.assertEqual(len(db.objects(protocol='Thermal_All', groups='eval')), 6400)
    self.assertEqual(len(db.objects(protocol='Thermal_All', groups='eval', purposes='enrol')), 2880)
    self.assertEqual(len(db.objects(protocol='Thermal_All', groups='eval', purposes='probe')), 3520)
    self.assertEqual(len(db.objects(protocol='Thermal_All', groups='eval', purposes='probe', classes='client')), 2880)
    self.assertEqual(len(db.objects(protocol='Thermal_All', groups='eval', purposes='probe', classes='impostor')), 640)
    self.assertEqual(len(db.objects(protocol='Thermal_All', groups='eval', purposes='probe', model_ids=[2201])), 648)
    self.assertEqual(len(db.objects(protocol='Thermal_All', groups='eval', purposes='probe', model_ids=[2201], classes='client')), 8)
    self.assertEqual(len(db.objects(protocol='Thermal_All', groups='eval', purposes='probe', model_ids=[2201], classes='impostor')), 640)
    self.assertEqual(len(db.objects(protocol='Thermal_All', groups='eval', purposes='probe', model_ids=[2201,2202])), 656)
    self.assertEqual(len(db.objects(protocol='Thermal_All', groups='eval', purposes='probe', model_ids=[2201,2202], classes='client')), 16)
    self.assertEqual(len(db.objects(protocol='Thermal_All', groups='eval', purposes='probe', model_ids=[2201,2202], classes='impostor')), 640)


    # Thermal_RightIndex
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex')), 6400)
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex', groups='world')), 2400)
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex', groups='dev')), 2400)
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex', groups='dev', purposes='enrol')), 1104)
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex', groups='dev', purposes='probe')), 1296)
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex', groups='dev', purposes='probe', classes='client')), 1104)
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex', groups='dev', purposes='probe', classes='impostor')), 192)
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex', groups='dev', purposes='probe', model_ids=[1601])), 200)
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex', groups='dev', purposes='probe', model_ids=[1601], classes='client')), 8)
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex', groups='dev', purposes='probe', model_ids=[1601], classes='impostor')), 192)
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex', groups='dev', purposes='probe', model_ids=[1601,1605])), 208)
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex', groups='dev', purposes='probe', model_ids=[1601,1605], classes='client')), 16)
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex', groups='dev', purposes='probe', model_ids=[1601,1605], classes='impostor')), 192)
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex', groups='eval')), 1600)
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex', groups='eval', purposes='enrol')), 720)
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex', groups='eval', purposes='probe')), 880)
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex', groups='eval', purposes='probe', classes='client')), 720)
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex', groups='eval', purposes='probe', classes='impostor')), 160)
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex', groups='eval', purposes='probe', model_ids=[2201])), 168)
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex', groups='eval', purposes='probe', model_ids=[2201], classes='client')), 8)
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex', groups='eval', purposes='probe', model_ids=[2201], classes='impostor')), 160)
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex', groups='eval', purposes='probe', model_ids=[2201,2205])), 176)
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex', groups='eval', purposes='probe', model_ids=[2201,2205], classes='client')), 16)
    self.assertEqual(len(db.objects(protocol='Thermal_RightIndex', groups='eval', purposes='probe', model_ids=[2201,2205], classes='impostor')), 160)
    
    
    # Thermal_RightMiddle
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle')), 6400)
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle', groups='world')), 2400)
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle', groups='dev')), 2400)
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle', groups='dev', purposes='enrol')), 1104)
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle', groups='dev', purposes='probe')), 1296)
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle', groups='dev', purposes='probe', classes='client')), 1104)
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle', groups='dev', purposes='probe', classes='impostor')), 192)
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle', groups='dev', purposes='probe', model_ids=[1602])), 200)
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle', groups='dev', purposes='probe', model_ids=[1602], classes='client')), 8)
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle', groups='dev', purposes='probe', model_ids=[1602], classes='impostor')), 192)
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle', groups='dev', purposes='probe', model_ids=[1602,1606])), 208)
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle', groups='dev', purposes='probe', model_ids=[1602,1606], classes='client')), 16)
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle', groups='dev', purposes='probe', model_ids=[1602,1606], classes='impostor')), 192)
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle', groups='eval')), 1600)
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle', groups='eval', purposes='enrol')), 720)
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle', groups='eval', purposes='probe')), 880)
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle', groups='eval', purposes='probe', classes='client')), 720)
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle', groups='eval', purposes='probe', classes='impostor')), 160)
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle', groups='eval', purposes='probe', model_ids=[2202])), 168)
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle', groups='eval', purposes='probe', model_ids=[2202], classes='client')), 8)
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle', groups='eval', purposes='probe', model_ids=[2202], classes='impostor')), 160)
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle', groups='eval', purposes='probe', model_ids=[2202,2206])), 176)
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle', groups='eval', purposes='probe', model_ids=[2202,2206], classes='client')), 16)
    self.assertEqual(len(db.objects(protocol='Thermal_RightMiddle', groups='eval', purposes='probe', model_ids=[2202,2206], classes='impostor')), 160)
    
    
    
    # Thermal_LeftIndex
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex')), 6400)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex', groups='world')), 2400)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex', groups='dev')), 2400)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex', groups='dev', purposes='enrol')), 1096)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex', groups='dev', purposes='probe')), 1304)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex', groups='dev', purposes='probe', classes='client')), 1096)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex', groups='dev', purposes='probe', classes='impostor')), 208)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex', groups='dev', purposes='probe', model_ids=[1603])), 216)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex', groups='dev', purposes='probe', model_ids=[1603], classes='client')), 8)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex', groups='dev', purposes='probe', model_ids=[1603], classes='impostor')), 208)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex', groups='dev', purposes='probe', model_ids=[1603,1607])), 224)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex', groups='dev', purposes='probe', model_ids=[1603,1607], classes='client')), 16)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex', groups='dev', purposes='probe', model_ids=[1603,1607], classes='impostor')), 208)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex', groups='eval')), 1600)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex', groups='eval', purposes='enrol')), 720)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex', groups='eval', purposes='probe')), 880)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex', groups='eval', purposes='probe', classes='client')), 720)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex', groups='eval', purposes='probe', classes='impostor')), 160)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex', groups='eval', purposes='probe', model_ids=[2203])), 168)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex', groups='eval', purposes='probe', model_ids=[2203], classes='client')), 8)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex', groups='eval', purposes='probe', model_ids=[2203], classes='impostor')), 160)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex', groups='eval', purposes='probe', model_ids=[2203,2207])), 176)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex', groups='eval', purposes='probe', model_ids=[2203,2207], classes='client')), 16)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftIndex', groups='eval', purposes='probe', model_ids=[2203,2207], classes='impostor')), 160)
    
    
    
    # Thermal_LeftMiddle
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle')), 6400)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle', groups='world')), 2400)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle', groups='dev')), 2400)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle', groups='dev', purposes='enrol')), 1096)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle', groups='dev', purposes='probe')), 1304)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle', groups='dev', purposes='probe', classes='client')), 1096)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle', groups='dev', purposes='probe', classes='impostor')), 208)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle', groups='dev', purposes='probe', model_ids=[1604])), 216)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle', groups='dev', purposes='probe', model_ids=[1604], classes='client')), 8)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle', groups='dev', purposes='probe', model_ids=[1604], classes='impostor')), 208)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle', groups='dev', purposes='probe', model_ids=[1604,1608])), 224)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle', groups='dev', purposes='probe', model_ids=[1604,1608], classes='client')), 16)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle', groups='dev', purposes='probe', model_ids=[1604,1608], classes='impostor')), 208)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle', groups='eval')), 1600)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle', groups='eval', purposes='enrol')), 720)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle', groups='eval', purposes='probe')), 880)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle', groups='eval', purposes='probe', classes='client')), 720)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle', groups='eval', purposes='probe', classes='impostor')), 160)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle', groups='eval', purposes='probe', model_ids=[2204])), 168)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle', groups='eval', purposes='probe', model_ids=[2204], classes='client')), 8)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle', groups='eval', purposes='probe', model_ids=[2204], classes='impostor')), 160)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle', groups='eval', purposes='probe', model_ids=[2204,2208])), 176)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle', groups='eval', purposes='probe', model_ids=[2204,2208], classes='client')), 16)
    self.assertEqual(len(db.objects(protocol='Thermal_LeftMiddle', groups='eval', purposes='probe', model_ids=[2204,2208], classes='impostor')), 160)



    

  def test03_driver_api(self):

    from bob.db.base.script.dbmanage import main
    self.assertEqual(main('biosecurid.fingerprint dumplist --self-test'.split()), 0)
    self.assertEqual(main('biosecurid.fingerprint dumplist --protocol=Optical_All --class=client --group=dev --purpose=enrol --client=1601 --self-test'.split()), 0)
    self.assertEqual(main('biosecurid.fingerprint checkfiles --self-test'.split()), 0)
    self.assertEqual(main('biosecurid.fingerprint reverse user1001/session0001/u1001s0001_fo0001/ri/optical --self-test'.split()), 0)
    self.assertEqual(main('biosecurid.fingerprint path 3011 --self-test'.split()), 0)

