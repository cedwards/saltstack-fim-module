# -*- coding: utf-8 -*-
'''
Generic hashing script. Supports files & directories
'''
from __future__ import absolute_import

import os
import sys
import logging
import salt.utils

HAS_PRELINK = False

PRELINK_PATHS = [
    '/bin',
    '/lib',
    '/sbin',
    '/lib64',
    '/usr/bin',
    '/usr/lib',
    '/usr/sbin',
    '/usr/lib64',
    '/usr/games',
    '/usr/libexec',
    '/var/ftp/bin',
    '/var/ftp/lib'
    '/var/ftp/lib64'
    '/usr/kerberos/bin',
]

LOG = logging.getLogger(__name__)

__virtualname__ = 'fim'


def __virtual__():
    if salt.utils.which('prelink'):
        HAS_PRELINK=True
        return __virtualname__
    if 'file.get_hash' in __salt__:
        return __virtualname__ 


def _unlink(target):
    '''
    Convenience function to handle prelinking issue
    '''
    cmd = '{0} {1} {2}'.format('prelink', '-u', target)
    __salt__['cmd.run'](cmd)


def _prelink(target):
    '''
    Convenience function to handle prelinking issue
    '''
    cmd = '{0} {1} {2}'.format('prelink', '-l', target)
    __salt__['cmd.run'](cmd)


def _hasher(algo, target):
    '''
    Convenience function to handle hashing
    '''
    ret = None
    prelink_path = None
    if HAS_PRELINK:
        for path in PRELINK_PATHS:
            if target.startswith(path):
                prelink_path = path
                _unlink(target)
                break
    ret =  __salt__['file.get_hash'](target, algo)
    if prelink_path:
        _prelink(target)
    return ret


def _stats(target):
    '''
    '''
    return __salt__['file.stats'](target)


def checksum(algo='sha256', targets=[], *args, **kwargs):
    '''
    Generate dictionary of hashes and corresponding filenames.

    Supports file paths and or directories.
    '''

    checksums = {}

    if not targets:
        try:
            if __salt__['config.get']('fim:algo'):
                algo = __salt__['config.get']('fim:algo')
            if __salt__['config.get']('fim:targets'):
                targets = __salt__['config.get']('fim:targets')
        except:
            LOG.debug('No targets found in minion config')

    for target in targets:
        if os.path.isdir(target):
            for root, dirs, files in os.walk(target):
                for file_ in files:
                    fullpath = os.path.join(root, file_)
                    if os.path.isfile(fullpath):
                        stats = _stats(fullpath)
                        digest = _hasher(algo, fullpath)
                        checksums.update({fullpath: {}})
                        checksums.update({fullpath: stats})
                        checksums[fullpath].update({'checksum': digest, 'algo': algo})
        if os.path.isfile(target):
            stats = _stats(target)
            digest = _hasher(algo, target)
            checksums.update({target: {}})
            checksums.update({target: stats})
            checksums[target].update({'checksum': digest, 'algo': algo})

    return checksums

