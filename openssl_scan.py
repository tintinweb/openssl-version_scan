#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import with_statement

import logging

import re

import os
import sys

import string
import stat
import mmap
import subprocess

from collections import defaultdict

import getopt
import time

class Utils:
    @staticmethod
    def histogram(lst):
        d = defaultdict(int)
        for e in lst: d[e]+=1
        return d

    @staticmethod
    def walk_executables(base, flags=stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH):
        for root, dirs, files in os.walk(base, topdown=True, ):# followlinks=False): # py26 does not support this..crap            
            for name in files:
                fpath = os.path.join(root,name)
                if os.path.isfile(fpath):
                    if os.stat(fpath).st_mode & flags:
                        yield fpath
    
    @staticmethod
    def shell(cmd):
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        proc.wait()
        return proc.stdout.read().strip()
                        
class Linux:
    @staticmethod
    def process_list():
        procs = set([])
        for pid in [pid for pid in os.listdir('/proc') if pid.isdigit()]:
            try:
                cmdline =  open(os.path.join('/proc', pid, 'cmdline'), 'rb').read().replace("\x00"," ").strip().split(" ",1)[0]
                if not all(c in string.printable for c in cmdline):
                    continue
                if os.path.isfile(cmdline) or os.path.islink(cmdline):
                    procs.add(cmdline)
            except IOError: # proc has already terminated
                continue
        return procs

class OSSLVersionScan(object):
    REX_STATIC_VERSION=re.compile(r'(openssl [0-9a-zA-Z]+\.[0-9a-zA-Z\.]+)',re.IGNORECASE)
    REX_DYNAMIC_VERSION=re.compile(r'=> ([^\s(]+)',re.IGNORECASE)

    def __init__(self, scan_shared=True, scan_magic=["ELF"], scan_magic_size=10, use_mmap=True):
        self.results = {}                       # path : { static, dynamic }
        self.static_versions = {}               # path : set([version, ...])
        self.refs = defaultdict(int)            # path : num_refs
        self.supports_shell_ldd = True if scan_shared and os.path.isfile(Utils.shell("which ldd").strip()) else False
        self.scan_magic = scan_magic
        self.scan_magic_size = scan_magic_size
        if use_mmap:
            setattr(self,"find_static_versions",self.find_static_versions_mmap)
        self.num_files_total = 0                # total files
        self.num_files_scanned = 0              # all files that were scanned for openssl traces
        self.num_files_hit = 0                  # static openssl references

    def find_static_versions_strings(self, path):
        return set(self.REX_STATIC_VERSION.findall(Utils.shell("strings '%s' | grep -i openssl"%path)))

    def find_static_versions(self, path):
        # only check ELF files
        with open(path,'rb') as f:
            if self.scan_magic is not None:
                chunk = f.read(self.scan_magic_size)
                if not any((s for s in self.scan_magic if s in chunk)): # e.g. find (\x7)fELF within first 10 bytes 
                    return set([])
            return set(self.REX_STATIC_VERSION.findall(f.read()))

    def find_static_versions_mmap(self, path):
        result = set([])
        
        try:
            smf = SimpleMmapFile(path)
            
            if self.scan_magic is not None:
                if not any((s for s in self.scan_magic if s in smf.m.read(self.scan_magic_size))): # e.g. find (\x7)fELF within first 10 bytes
                    smf.close() 
                    return result
                    
            for line in smf.readlines():
                if "OpenSSL" in line:
                    result = set(self.REX_STATIC_VERSION.findall(line))
                    if result:
                        break
            smf.close()
        except EnvironmentError, ee:
            logging.warning("[!] exception: %s - %s"%(path,repr(ee)))
        return result

    def get_static_version(self, path):
        self.refs[path] +=1
        versions = self.static_versions.get(path)
        if versions is not None:
            return versions
        self.static_versions[path] = self.find_static_versions(path)
        if self.static_versions[path]:
            self.num_files_hit +=1
        #logging.debug("%s - %s"%(path,self.static_versions[path]))
        return self.static_versions[path]

    def get_dynamic_versions(self, path):
        if not self.supports_shell_ldd:
            return {}
        refs = self.results.get(path)
        if refs is not None:
            return refs
        out = Utils.shell("ldd '%s'"%path)
        dynrefs = self.REX_DYNAMIC_VERSION.findall(out)
        #logging.debug("%s refs %d dynamic libs"%(path,len(dynrefs)))
        refs = {}
        for ref in dynrefs:
            self.scan_file(ref)
            refs[ref] = self.get_static_version(ref)
        return refs

    def scan_file(self, path):
        if path in self.results:            # scanned already
            return
        static = self.get_static_version(path)
        dynamic = self.get_dynamic_versions(path)
        self.num_files_total +=1
        if not static and not dynamic:
            return
        self.num_files_scanned +=1
        self.results[path]={'static':static,
                            'dynamic':dynamic}
    def scan_path(self, base):
        if os.path.isfile(base):
            return self.scan_file(base)
        
        for nr,path in enumerate(Utils.walk_executables(base)):
            logging.debug("scanning: #%d - %s"%(nr+1,path))
            self.scan_file(path)
            
    def scan_processes(self):
        proclist = Linux.process_list()
        numprocs = len(proclist)
        for nr, path in enumerate(proclist):
            logging.debug("scanning: %d/%d - %s"%(nr+1,numprocs,path))
            self.scan_file(path)

    def get_static_results(self):
        return dict([(path,versions) for path,versions in self.static_versions.iteritems() if versions ])

    def get_static_versions(self):
        # flatten static results list
        return [item for sublist in self.get_static_results().itervalues() for item in sublist]

    def get_distinct_versions(self):
        return set(self.get_static_versions())

    def get_static_version_count(self):
        return Utils.histogram(self.get_static_versions())
    
    def get_dynamic_version_count(self):
        ref_count = defaultdict(int)
        for path,versions in self.get_static_results().iteritems():
            for version in versions:
                ref_count[version] += self.refs.get(path)
        return ref_count
    
    def get_version_count(self):
        d = {}
        static_version_count = self.get_static_version_count()
        dynamic_version_count = self.get_dynamic_version_count()
        
        for version in self.get_distinct_versions():
            d[version]={'static':static_version_count.get(version,0),
                        'dynamic':dynamic_version_count.get(version,0)}
            
        return d
    
    def get_versions_by_path(self):
        # only return elements which ref openssl libs
        d = {}
        for path, refs in self.results.iteritems():
            dyn = set([item for sublist in refs['dynamic'].values() for item in sublist])
            if not dyn and not refs['static']:
                continue
            d[path] = {'static':refs['static'],
                       'dynamic':dyn}
        return d
             

class SimpleMmapFile(object):
    def __init__(self, path, length=0):
        self.fp = os.open(path,os.O_RDONLY)
        self.m = mmap.mmap(self.fp,length=length, access=1)            # map whole file, read only
        
    def readlines(self):
        return iter(self.m.readline,"")
    
    def close(self):
        if self.m:
            self.m.close()
            self.m=None
        if self.fp:
            os.close(self.fp)
            self.fp=None
        
def usage():
    print """USAGE: %s [options...] <path1> ... <pathN>
    
    options:
    -p, --procs                   scan running processes

    -S, --no-shared               do NOT scan shared libraries   
    -M, --no-mmap                 do NOT use memory mapped files (significant slower)

    -w, --wikimarkup              enable wiki style table output
    -v, --verbosity=<level>       <level> 0 [none] ... 10 [debug] ... 20 [info] ... 50 [critical]
    -l, --logfile=<file>          log output to <file>
     """%sys.argv[0]

def parse_opts():
    options = {'verbosity':logging.INFO,
               'procs':False,
               'wikimarkup':False,
               'no-dynamic':False,
               'no-mmap':False,
               'logfile':None}
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hv=pwSMl=", ["help", "procs","verbosity=","wikimarkup", "no-shared", "no-mmap", "logfile="])
    except getopt.GetoptError, err:
        # print help information and exit:
        print str(err) # will print something like "option -a not recognized"
        usage()
        sys.exit(2)
    output = None
    verbose = False
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-v", "--verbosity"):
            options['verbosity']=int(a)
        elif o in ("-p", "--procs"):
            options['procs']=True
        elif o in ("-w", "--wikimarkup"):
            options['wikimarkup']=True
        elif o in ("-S", "--no-shared"):
            options['no-dynamic']=True
        elif o in ("-M", "--no-mmap"):
            options['no-mmap']=True
        elif o in ("-l", "--logfile"):
            options['logfile']=a
        else:
            assert False, "unhandled option"
    return options,args

def main():
    opts, args = parse_opts()
    if not opts['procs'] and not args:
        usage()
        sys.exit(2) 
    logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
    rootLogger = logging.getLogger()
    
    if opts['logfile']:
        fileHandler = logging.FileHandler(opts['logfile'], mode='w')
        fileHandler.setFormatter(logFormatter)
        rootLogger.addHandler(fileHandler)
    
    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    rootLogger.addHandler(consoleHandler)
    rootLogger.setLevel(opts['verbosity'])
    
    ossl = OSSLVersionScan(scan_shared=not opts['no-dynamic'],
                           use_mmap=not opts['no-mmap'])
    if not ossl.supports_shell_ldd:
        logging.warning("[!] scan support for shared libraries is disabled or 'ldd' utility is not in $PATH; cannot scan dynamic links")
    if opts['procs']:
        logging.info("[*] scanning process list...")
        ossl.scan_processes()
        
    for path in args:
        logging.info("[*] scanning path (recursive): %s ..."%path)
        ossl.scan_path(path)
        
        
    logging.info("Results".center(30,"="))
    logging.info("[>] File Overview: ")
    num_hit_static = 0
    num_hit_shared = 0
    num_hit_files = 0
    for path, refs in ossl.get_versions_by_path().iteritems():
        if refs['static'] or refs['dynamic']:
            num_hit_files +=1
            if refs['static']:
                num_hit_static +=1
            if refs['dynamic']:
                num_hit_shared +=1
        logging.info("* File: %s\n ** [static]  %s\n ** [dynamic] %s"%(path,refs['static'],refs['dynamic']))  
  
    logging.info("Statistics".center(30,"="))
    logging.info("[>] Scan:")
    logging.info(" Candidate files (total):    %6d"%ossl.num_files_total)
    logging.info(" Files scanned:              %6d"%ossl.num_files_scanned)
    logging.info(" Traces of openssl detected: %6d"%num_hit_files)
    logging.info(" * static traces:            %6d"%num_hit_static)
    logging.info(" * shared library references:%6d"%num_hit_shared)
    logging.info("[>] distinct openssl versions:")
    for v in ossl.get_distinct_versions():
        logging.info("* %s"%v)
        
    logging.info("[>] version overview:")
    logging.info("       version         |  static  | shared references | ")
    logging.info("---------------------- |----------|-------------------|")
    for version, refs in ossl.get_version_count().iteritems():
        logging.info("* %-20s |  %6d  |           %6d  |"%(version,refs['static'],refs['dynamic']))
        
    
    if opts['wikimarkup']:
        wikimarkup = '||file||static||dynamic||'
        for version, refs in ossl.get_versions_by_path().iteritems():
            wikimarkup += '\n|%s |%s |%s |'%(version,','.join(refs['static']),','.join(refs['dynamic']))
        logging.info("Wikimarkup: file overview\n%s"%wikimarkup)
        
        
        wikimarkup = '||version||static||dynamic||'
        for version, refs in ossl.get_version_count().iteritems():
            wikimarkup += '\n|%s |%s |%s |'%(version,refs['static'],refs['dynamic'])
        logging.info("Wikimarkup: version overview\n%s"%wikimarkup)

if __name__=="__main__":
    start = time.time()
    main()
    stop = time.time()
    logging.info("[i] this scan took %.2f seconds"%(stop-start))
