/*++

Copyright (c) 1997  Microsoft Corporation

Module Name:

    SIOCTL.H

Abstract:


    Defines the IOCTL codes that will be used by this driver.  The IOCTL code
    contains a command identifier, plus other information about the device,
    the type of access with which the file must have been opened,
    and the type of buffering.

Environment:

    Kernel mode only.

--*/

//
// Device type           -- in the "User Defined" range."
//
#define FILE_TYPE_GENERAL 0x00004000
//
// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
//


//#define IOCTL_SIOCTL_METHOD_IN_DIRECT \
//    CTL_CODE(FILE_TYPE_GENERAL, 0x900, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
//#define IOCTL_SIOCTL_METHOD_OUT_DIRECT \
//    CTL_CODE(FILE_TYPE_GENERAL, 0x901, METHOD_OUT_DIRECT , FILE_ANY_ACCESS)
//#define IOCTL_SIOCTL_METHOD_NEITHER \
//    CTL_CODE(FILE_TYPE_GENERAL, 0x903, METHOD_NEITHER , FILE_ANY_ACCESS)

#define IOCTL_FGE_HIDE \
    CTL_CODE(FILE_TYPE_GENERAL, 0x100, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FGE_HOOK_INF \
    CTL_CODE(FILE_TYPE_GENERAL, 0x101, METHOD_BUFFERED, FILE_ANY_ACCESS)


