MemoryMonRWE
=============

Introduction
-------------
MemoryMon is able to detect execution of kernel memory where is not backed by
any image file (kernel modules) using extended page table (EPT). It can help
researchers analyze kernel mode code installs and runs code outside of an image
file.

A demo video using MemoryMon against Turla rootkit can be found in Youtube:
- https://www.youtube.com/watch?v=O5_ocsplrfA

MemoryMon is implemented on the top of HyperPlatform. See a project page for
more details of HyperPlatform:
- https://github.com/tandasat/HyperPlatform


Installation and Uninstallation
--------------------------------
Clone full source code from Github with a below command and compile it on Visual
Studio.

    $ git clone git@github.com:tandasat/MemoryMon.git
    $ cd MemoryMon/
    $ git checkout -b rwe_cdfs remotes/origin/rwe_cdfs
    $ git submodule update --init --recursive

On the x64 platform, you have to enable test signing to install the driver.
To do that, open the command prompt with the administrator privilege and type
the following command, and then restart the system to activate the change:

    >bcdedit /set testsigning on

To install and uninstall the driver, use the 'sc' command. For installation:

    >sc create MemoryMon type= kernel binPath= C:\Users\user\Desktop\MemoryMon.sys
    >sc start MemoryMon

For uninstallation:

    >sc stop MemoryMon
    >sc delete MemoryMon
    >bcdedit /deletevalue testsigning


Note that the system must support the Intel VT-x and EPT technology to
successfully install the driver.

To install the driver on a virtual machine on VMware Workstation, see an "Using
VMware Workstation" section in the HyperPlatform User Document.
- http://tandasat.github.io/HyperPlatform/userdocument/


Output
-------
All logs are printed out to DbgView and saved in C:\Windows\MemoryMon.log.

On a 64bit Windows, activities of PatchGuard are usually observed. The following
are those logs seen on Windows 7 system.

    08:47:07.276	INF	#0	    4	    0	System         	[EXEC] *** VA = FFFFFA800194A468, PA = 000000007fe89468, Return = FFFFF80002AD8C1C, ReturnBase = FFFFF80002A5A000
    08:47:07.276	INF	#0	    4	    0	System         	[EXEC] *** VA = FFFFFA8003D46007, PA = 000000007db46007, Return = FFFFFA800194A4AD, ReturnBase = 0000000000000000
    08:47:07.276	INF	#0	    4	    0	System         	[EXEC] *** VA = FFFFFA8003D47580, PA = 000000007db47580, Return = FFFFFA8003D460B0, ReturnBase = 0000000000000000
    08:47:07.291	INF	#0	    4	   64	System         	[EXEC] *** VA = FFFFFA8003D4AE1C, PA = 000000007db4ae1c, Return = FFFFF80002AD7B69, ReturnBase = FFFFF80002A5A000
    08:47:07.291	INF	#0	    4	   64	System         	[EXEC] *** VA = FFFFFA8003D4856B, PA = 000000007db4856b, Return = 0000000000000004, ReturnBase = 0000000000000000

The first line indicates that a virtual address FFFFFA800194A468 is executed and
its potential return address is FFFFF80002AD8C1C. Since execution of a non-image
region is not always triggered by the CALL instruction, a reported return address
can be wrong. For instance, the last line reports return address 0000000000000004.

Note that symbols names can be resolved with hyperplatform_log_parser. The above
logs are parsed as followings, for example:

    08:47:07.276     4:    0 executed fffffa800194a468, will return to fffff80002ad8c1c nt!KiRetireDpcList+0x1bc
    08:47:07.276     4:    0 executed fffffa8003d46007, will return to fffffa800194a4ad
    08:47:07.276     4:    0 executed fffffa8003d47580, will return to fffffa8003d460b0
    08:47:07.291     4:   64 executed fffffa8003d4ae1c, will return to fffff80002ad7b69 nt!ExpWorkerThread+0x111
    08:45:07.265     4:   64 executed fffffa8002626629, will return to                4

See a project page for more details.
- https://github.com/tandasat/hyperplatform_log_parser


Supported Platforms
----------------------
- x86 and x64 Windows 7, 8.1 and 10
- The system must support the Intel VT-x and EPT technology


License
--------
This software is released under the MIT License, see LICENSE.
