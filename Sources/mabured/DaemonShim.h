//
//  DaemonShim.h
//  mabured
//
//  Bridging header exposing the low-level Darwin/libproc APIs used for
//  process enumeration, argv retrieval, and process metadata lookup.
//  KERN_PROCARGS2 in particular has no public header declaring the mib
//  constant in a Swift-importable way, so we pull the raw sysctl headers.
//
#ifndef DaemonShim_h
#define DaemonShim_h

#include <libproc.h>
#include <sys/sysctl.h>
#include <sys/proc_info.h>
#include <signal.h>
#include <unistd.h>

#endif /* DaemonShim_h */
