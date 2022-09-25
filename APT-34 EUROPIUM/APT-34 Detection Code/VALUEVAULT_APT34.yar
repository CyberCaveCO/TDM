
rule VALUEVAULT_Malware {
   meta:
      description = "VALUEVAULT is a Golang compiled version of the Windows Vault Password Dumper browser credential theft tool"
      author = "CyberCave"
      reference = "https://cybercave.com.sa"
      date = "2022-09-24"
      hash1 = "6098d30d30603b6a6edd8f556479530ca7898bab529781e94989b47d6283e697"
   strings:
      $x1 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Central Brazilian Standard TimeDWOR" ascii
      $x2 = "sql/driver: couldn't convert %d into type boolsql/driver: couldn't convert %q into type boolsql: selected isolation level is not" ascii
      $x3 = "152587890625762939453125Bidi_ControlCoCreateGuidCreateEventWFindNextFileGetAddrInfoWGetConsoleCPGetLastErrorGetLengthSidGetStdHa" ascii
      $x4 = " to unallocated span%%!%c(*big.Float=%s)37252902984619140625: leftover defer sp=Arabic Standard TimeAzores Standard TimeCertOpen" ascii
      $x5 = "Pakistan Standard TimeParaguay Standard TimeRat.Scan: invalid verbSakhalin Standard TimeTasmania Standard TimeWaitForMultipleObj" ascii
      $x6 = "structure needs cleaningunexpected exponent baseunexpected mantissa base bytes failed with errno= to unused region of span with " ascii
      $x7 = "value size wrongworkbuf is empty initialHeapLive= spinningthreads=%%!%c(big.Int=%s)0123456789ABCDEFX0123456789abcdefx06010215040" ascii
      $x8 = " > (den<<shift)/2syntax error scanning numberunexpected end of JSON inputunsupported compression for  cannot be converted to typ" ascii
      $x9 = " of unexported method previous allocCount=186264514923095703125931322574615478515625AdjustTokenPrivilegesAlaskan Standard TimeAn" ascii
      $x10 = " MB) workers= called from  flushedWork  gcscanvalid  heap_marked= idlethreads= in host name is nil, not  is too large nStackRoot" ascii
      $x11 = "file descriptor in bad statefindrunnable: netpoll with pgcstopm: negative nmspinninggobytes: length out of rangehttps://accounts" ascii
      $x12 = " gcwaiting= gp.status= heap_live= idleprocs= in status  m->mcache= mallocing= ms clock,  nBSSRoots= p->mcache= p->status= s.nele" ascii
      $x13 = " lockedg= lockedm= m->curg= method:  ms cpu,  not in [ of type  runtime= s.limit= s.state= threads= u_a/u_g= wbuf1.n= wbuf2.n=%!" ascii
      $x14 = "TerminateJobObjectVariation_Selectorbad manualFreeListconnection refusedcontext.Backgroundfile name too longforEachP: not donega" ascii
      $x15 = "sqlite library was not compiled for thread-safe operationsync: WaitGroup misuse: Add called concurrently with WaitSQlite aggrega" ascii
      $x16 = "r in opening loginsJsonexplicit tag has no childhttps://www.facebook.com/inconsistent poll.fdMutexinvalid cross-device linkinval" ascii
      $x17 = "sql: expected %d destination arguments in Scan, not %dSELECT item1,item2 FROM metadata WHERE id = 'password';SOFTWARE\\Microsoft" ascii
      $x18 = ", not 390625<-chanAnswerArabicAugustBrahmiCOMMITCarianChakmaCommonCopticDELETEExpectFormatFridayGOROOTGetACPGothicHangulHatranHe" ascii
      $x19 = "23283064365386962890625<invalid reflect.Value>Argentina Standard TimeAstrakhan Standard TimeCertGetCertificateChainCryptEncoderS" ascii
      $x20 = "wrong medium type  but memory size  because dotdotdot to non-Go memory , locked to thread298023223876953125: day out of rangeAra" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      1 of ($x*)
}

