# -*- coding: utf-8 -*-
'''
Generic hashing script. Supports files & directories
'''
from __future__ import absolute_import

import os
import sys
import gzip
import json
import logging
import salt.utils
from time import strftime
from salt.utils.serializers.msgpack import serialize

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


def _collection(checksums, algo, path):
    '''
    standardizing the dictionary creation
    '''
    stats = _stats(path)
    digest = _hasher(algo, path)

    stats.update({'digest': digest, 'algo': algo})

    checksums['files'].append(stats)

    return checksums


def _compress(checksums, filename):
    '''
    json-ize and write the content
    '''
    json_formatted = json.dumps(checksums)

    with gzip.open(filename, 'w') as compressed:
        compressed.writelines(json_formatted)

    return 'wrote {0}: (gzipped)'.format(filename)


def checksum(algo='sha256', targets=[], filename='', *args, **kwargs):
    '''
    Generate dictionary of hashes and corresponding filenames.

    Supports file paths and or directories.
    '''
    checksums = {'files': []}
    timestamp = strftime("%Y-%m-%d %H:%M:%S")

    ## check for preconfigured filename
    if not filename:
        try:
            if __salt__['config.get']('fim:filename'):
                filename = __salt__['config.get']('fim:filename')
        except KeyError:
            LOG.debug('No filename defined. Sending to stdout')

    ## check for preconfigured algos
    if not algo:
        try:
            if __salt__['config.get']('fim:algo'):
                algo = __salt__['config.get']('fim:algo')
        except KeyError:
            LOG.debug('No algorithm defined. Defaulting to sha256')

    ## check for preconfigured targets
    if not targets:
        try:
            if __salt__['config.get']('fim:targets'):
                targets = __salt__['config.get']('fim:targets')
        except:
            return 'No targets defined. Exiting'

    ## iterate through list of targets and generate checksums
    for target in targets:
        if os.path.isdir(target):
            for root, dirs, files in os.walk(target):
                for file_ in files:
                    target = os.path.join(root, file_)
                    if os.path.isfile(target):
                        checksums = _collection(checksums, algo, target)
        if os.path.isfile(target):
            checksums = _collection(checksums, algo, target)

    checksums['files'].append({'timestamp':timestamp})
    ## if filename configured, write results to disk
    if filename:
        ret = _compress(checksums, filename)
        return ret

    return checksums

