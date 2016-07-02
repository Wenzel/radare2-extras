/* Instruction opcode header for vc4.

THIS FILE IS MACHINE GENERATED WITH CGEN.

Copyright 1996-2010 Free Software Foundation, Inc.

This file is part of the GNU Binutils and/or GDB, the GNU debugger.

   This file is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.

*/

#ifndef VC4_OPC_H
#define VC4_OPC_H

/* -- opc.h */

#ifndef CGEN_ASM_HASH
#define CGEN_ASM_HASH
# define CGEN_DIS_HASH_SIZE 127
#endif
#define CGEN_DIS_HASH(buf, value)					\
  ((((unsigned char *) buf)[1] & 0x80) == 0 ? 0      /* scalar16.  */	\
   : (((unsigned char *) buf)[1] & 0xf8) == 0xf8 ? 1 /* vector80.  */	\
   : (((unsigned char *) buf)[1] & 0xf8) == 0xf0 ? 2 /* vector48.  */	\
   : (((unsigned char *) buf)[1] & 0xf0) == 0xe0 ? 3 /* scalar48.  */	\
   : 4)						     /* scalar32.  */

#define CGEN_ASM_HASH_SIZE 5

/* -- asm.c */
/* Enum declaration for vc4 instruction types.  */
typedef enum cgen_insn_type {
  VC4_INSN_INVALID, VC4_INSN_BKPT, VC4_INSN_NOP, VC4_INSN_SLEEP
 , VC4_INSN_USER, VC4_INSN_EI, VC4_INSN_DI, VC4_INSN_CBCLR
 , VC4_INSN_CBINC, VC4_INSN_CBCHG, VC4_INSN_CBDEC, VC4_INSN_RTI
 , VC4_INSN_SWIREG, VC4_INSN_RTS, VC4_INSN_BREG, VC4_INSN_BLREG
 , VC4_INSN_TBB, VC4_INSN_TBH, VC4_INSN_MOVCPUID, VC4_INSN_SWIIMM
 , VC4_INSN_PUSHRN, VC4_INSN_PUSHRNLR, VC4_INSN_PUSHRNRM0, VC4_INSN_PUSHRNRM6
 , VC4_INSN_PUSHRNRM16, VC4_INSN_PUSHRNRM24, VC4_INSN_PUSHRNRM0_LR, VC4_INSN_PUSHRNRM6_LR
 , VC4_INSN_PUSHRNRM16_LR, VC4_INSN_PUSHRNRM24_LR, VC4_INSN_POPRN, VC4_INSN_POPRNPC
 , VC4_INSN_POPRNRM0, VC4_INSN_POPRNRM6, VC4_INSN_POPRNRM16, VC4_INSN_POPRNRM24
 , VC4_INSN_POPRNRM0_PC, VC4_INSN_POPRNRM6_PC, VC4_INSN_POPRNRM16_PC, VC4_INSN_POPRNRM24_PC
 , VC4_INSN_LDIND, VC4_INSN_STIND, VC4_INSN_LDOFF, VC4_INSN_STOFF
 , VC4_INSN_LDOFF12, VC4_INSN_STOFF12, VC4_INSN_LDOFF16, VC4_INSN_STOFF16
 , VC4_INSN_LDCNDIDX, VC4_INSN_LDCNDIDXH, VC4_INSN_LDCNDIDXB, VC4_INSN_LDCNDIDXSH
 , VC4_INSN_STCNDIDX, VC4_INSN_STCNDIDXH, VC4_INSN_STCNDIDXB, VC4_INSN_STCNDIDXSH
 , VC4_INSN_LDCNDDISP, VC4_INSN_LDCNDDISPH, VC4_INSN_LDCNDDISPB, VC4_INSN_LDCNDDISPSH
 , VC4_INSN_STCNDDISP, VC4_INSN_STCNDDISPH, VC4_INSN_STCNDDISPB, VC4_INSN_STCNDDISPSH
 , VC4_INSN_LDPREDEC, VC4_INSN_LDPREDECH, VC4_INSN_LDPREDECB, VC4_INSN_LDPREDECSH
 , VC4_INSN_STPREDEC, VC4_INSN_STPREDECH, VC4_INSN_STPREDECB, VC4_INSN_STPREDECSH
 , VC4_INSN_LDPOSTINC, VC4_INSN_LDPOSTINCH, VC4_INSN_LDPOSTINCB, VC4_INSN_LDPOSTINCSH
 , VC4_INSN_STPOSTINC, VC4_INSN_STPOSTINCH, VC4_INSN_STPOSTINCB, VC4_INSN_STPOSTINCSH
 , VC4_INSN_LDSP, VC4_INSN_STSP, VC4_INSN_ADDSP, VC4_INSN_LEA
 , VC4_INSN_BCC, VC4_INSN_MOV16, VC4_INSN_CMN16, VC4_INSN_ADD16
 , VC4_INSN_BIC16, VC4_INSN_MUL16, VC4_INSN_EOR16, VC4_INSN_SUB16
 , VC4_INSN_AND16, VC4_INSN_NOT16, VC4_INSN_ROR16, VC4_INSN_CMP16
 , VC4_INSN_RSUB16, VC4_INSN_BTST16, VC4_INSN_OR16, VC4_INSN_BMASK16
 , VC4_INSN_MAX16, VC4_INSN_BSET16, VC4_INSN_MIN16, VC4_INSN_BCLR16
 , VC4_INSN_ADDS216, VC4_INSN_BCHG16, VC4_INSN_ADDS416, VC4_INSN_ADDS816
 , VC4_INSN_ADDS1616, VC4_INSN_SIGNEXT16, VC4_INSN_NEG16, VC4_INSN_LSR16
 , VC4_INSN_MSB16, VC4_INSN_SHL16, VC4_INSN_BITREV16, VC4_INSN_ASR16
 , VC4_INSN_ABS16, VC4_INSN_MOVI16, VC4_INSN_ADDI16, VC4_INSN_MULI16
 , VC4_INSN_SUBI16, VC4_INSN_NOTI16, VC4_INSN_CMPI16, VC4_INSN_BTSTI16
 , VC4_INSN_BMASKI16, VC4_INSN_BSETI16, VC4_INSN_BCLRI16, VC4_INSN_BCHGI16
 , VC4_INSN_ADDS8I16, VC4_INSN_SIGNEXTI16, VC4_INSN_LSRI16, VC4_INSN_SHLI16
 , VC4_INSN_ASRI16, VC4_INSN_BCC32R, VC4_INSN_BCC32I, VC4_INSN_ADDCMPBRR
 , VC4_INSN_ADDCMPBRI, VC4_INSN_ADDCMPBIR, VC4_INSN_ADDCMPBII, VC4_INSN_BCC32
 , VC4_INSN_BL32, VC4_INSN_MOV32, VC4_INSN_CMN32, VC4_INSN_ADD32
 , VC4_INSN_BIC32, VC4_INSN_MUL32, VC4_INSN_EOR32, VC4_INSN_SUB32
 , VC4_INSN_AND32, VC4_INSN_NOT32, VC4_INSN_ROR32, VC4_INSN_CMP32
 , VC4_INSN_RSUB32, VC4_INSN_BTST32, VC4_INSN_OR32, VC4_INSN_BMASK32
 , VC4_INSN_MAX32, VC4_INSN_BSET32, VC4_INSN_MIN32, VC4_INSN_BCLR32
 , VC4_INSN_ADDS232, VC4_INSN_BCHG32, VC4_INSN_ADDS432, VC4_INSN_ADDS832
 , VC4_INSN_ADDS1632, VC4_INSN_SIGNEXT32, VC4_INSN_NEG32, VC4_INSN_LSR32
 , VC4_INSN_MSB32, VC4_INSN_SHL32, VC4_INSN_BITREV32, VC4_INSN_ASR32
 , VC4_INSN_ABS32, VC4_INSN_MOVI32, VC4_INSN_CMNI32, VC4_INSN_ADDI32
 , VC4_INSN_BICI32, VC4_INSN_MULI32, VC4_INSN_EORI32, VC4_INSN_SUBI32
 , VC4_INSN_ANDI32, VC4_INSN_NOTI32, VC4_INSN_RORI32, VC4_INSN_CMPI32
 , VC4_INSN_RSUBI32, VC4_INSN_BTSTI32, VC4_INSN_ORI32, VC4_INSN_BMASKI32
 , VC4_INSN_MAXI32, VC4_INSN_BSETI32, VC4_INSN_MINI32, VC4_INSN_BCLRI32
 , VC4_INSN_ADDS2I32, VC4_INSN_BCHGI32, VC4_INSN_ADDS4I32, VC4_INSN_ADDS8I32
 , VC4_INSN_ADDS16I32, VC4_INSN_SIGNEXTI32, VC4_INSN_NEGI32, VC4_INSN_LSRI32
 , VC4_INSN_MSBI32, VC4_INSN_SHLI32, VC4_INSN_BITREVI32, VC4_INSN_ASRI32
 , VC4_INSN_ABSI32, VC4_INSN_MULHDRSS, VC4_INSN_MULHDRSU, VC4_INSN_MULHDRUS
 , VC4_INSN_MULHDRUU, VC4_INSN_DIVRSS, VC4_INSN_DIVRSU, VC4_INSN_DIVRUS
 , VC4_INSN_DIVRUU, VC4_INSN_MULHDISS, VC4_INSN_MULHDISU, VC4_INSN_MULHDIUS
 , VC4_INSN_MULHDIUU, VC4_INSN_DIVISS, VC4_INSN_DIVISU, VC4_INSN_DIVIUS
 , VC4_INSN_DIVIUU, VC4_INSN_ADDSATR, VC4_INSN_SUBSATR, VC4_INSN_SHLSATR
 , VC4_INSN_ADDS5R, VC4_INSN_ADDS6R, VC4_INSN_ADDS7R, VC4_INSN_ADDS8R
 , VC4_INSN_SUBS1R, VC4_INSN_SUBS2R, VC4_INSN_SUBS3R, VC4_INSN_SUBS4R
 , VC4_INSN_SUBS5R, VC4_INSN_SUBS6R, VC4_INSN_SUBS7R, VC4_INSN_SUBS8R
 , VC4_INSN_CLAMP16R, VC4_INSN_COUNTR, VC4_INSN_ADDSATI, VC4_INSN_SUBSATI
 , VC4_INSN_SHLSATI, VC4_INSN_ADDS5I, VC4_INSN_ADDS6I, VC4_INSN_ADDS7I
 , VC4_INSN_ADDS8I, VC4_INSN_SUBS1I, VC4_INSN_SUBS2I, VC4_INSN_SUBS3I
 , VC4_INSN_SUBS4I, VC4_INSN_SUBS5I, VC4_INSN_SUBS6I, VC4_INSN_SUBS7I
 , VC4_INSN_SUBS8I, VC4_INSN_CLAMP16I, VC4_INSN_COUNTI, VC4_INSN_LEA32R
 , VC4_INSN_LEA32PC, VC4_INSN_MOVIU32, VC4_INSN_CMNIU32, VC4_INSN_ADDIU32
 , VC4_INSN_BICIU32, VC4_INSN_MULIU32, VC4_INSN_EORIU32, VC4_INSN_SUBIU32
 , VC4_INSN_ANDIU32, VC4_INSN_NOTIU32, VC4_INSN_RORIU32, VC4_INSN_CMPIU32
 , VC4_INSN_RSUBIU32, VC4_INSN_BTSTIU32, VC4_INSN_ORIU32, VC4_INSN_BMASKIU32
 , VC4_INSN_MAXIU32, VC4_INSN_BSETIU32, VC4_INSN_MINIU32, VC4_INSN_BCLRIU32
 , VC4_INSN_ADDS2IU32_SHL1, VC4_INSN_BCHGIU32, VC4_INSN_ADDS4IU32_SHL2, VC4_INSN_ADDS8IU32_SHL3
 , VC4_INSN_ADDS16IU32_SHL4, VC4_INSN_SIGNEXTIU32, VC4_INSN_NEGIU32, VC4_INSN_LSRIU32
 , VC4_INSN_MSBIU32, VC4_INSN_SHLIU32, VC4_INSN_BITREVIU32, VC4_INSN_ASRIU32
 , VC4_INSN_ABSIU32, VC4_INSN_FADDR, VC4_INSN_FSUBR, VC4_INSN_FMULR
 , VC4_INSN_FDIVR, VC4_INSN_FCMPR, VC4_INSN_FABSR, VC4_INSN_FRSBR
 , VC4_INSN_FMAXR, VC4_INSN_FRCPR, VC4_INSN_FRSQRTR, VC4_INSN_FNMULR
 , VC4_INSN_FMINR, VC4_INSN_FCEILR, VC4_INSN_FFLOORR, VC4_INSN_FLOG2R
 , VC4_INSN_FEXP2R, VC4_INSN_FADDI, VC4_INSN_FSUBI, VC4_INSN_FMULI
 , VC4_INSN_FDIVI, VC4_INSN_FCMPI, VC4_INSN_FABSI, VC4_INSN_FRSBI
 , VC4_INSN_FMAXI, VC4_INSN_FRCPI, VC4_INSN_FRSQRTI, VC4_INSN_FNMULI
 , VC4_INSN_FMINI, VC4_INSN_FCEILI, VC4_INSN_FFLOORI, VC4_INSN_FLOG2I
 , VC4_INSN_FEXP2I, VC4_INSN_FTRUNCR, VC4_INSN_FLOORR, VC4_INSN_FLTSR
 , VC4_INSN_FLTUR, VC4_INSN_FTRUNCI, VC4_INSN_FLOORI, VC4_INSN_FLTSI
 , VC4_INSN_FLTUI, VC4_INSN_LEA48, VC4_INSN_LDPCREL27, VC4_INSN_STPCREL27
 , VC4_INSN_LDOFF27, VC4_INSN_STOFF27, VC4_INSN_ADD48I, VC4_INSN_MOVI48
 , VC4_INSN_CMNI48, VC4_INSN_ADDI48, VC4_INSN_BICI48, VC4_INSN_MULI48
 , VC4_INSN_EORI48, VC4_INSN_SUBI48, VC4_INSN_ANDI48, VC4_INSN_CMPI48
 , VC4_INSN_RSUBI48, VC4_INSN_ORI48, VC4_INSN_MAXI48, VC4_INSN_MINI48
 , VC4_INSN_VEC48, VC4_INSN_VEC80
} CGEN_INSN_TYPE;

/* Index of `invalid' insn place holder.  */
#define CGEN_INSN_INVALID VC4_INSN_INVALID

/* Total number of insns in table.  */
#define MAX_INSNS ((int) VC4_INSN_VEC80 + 1)

/* This struct records data prior to insertion or after extraction.  */
struct cgen_fields
{
  int length;
  long f_nil;
  long f_anyof;
  long f_oplen;
  long f_op15_13;
  long f_op15_11;
  long f_op11_8;
  long f_ldstoff;
  long f_op11_9;
  long f_op11_10;
  long f_op11;
  long f_op10_9;
  long f_op10_7;
  long f_addspoffset;
  long f_op10_0;
  long f_alu16op;
  long f_alu16opi;
  long f_op9_8;
  long f_op9_5;
  long f_spoffset;
  long f_op8_5;
  long f_op8_4;
  long f_op8_4_shl3;
  long f_op8;
  long f_op7_4;
  long f_op7_4s;
  long f_op7_5;
  long f_op7_6;
  long f_op7;
  long f_op6_5;
  long f_op6_0;
  long f_pcrelcc;
  long f_op5;
  long f_op5_0;
  long f_op4;
  long f_op4_0;
  long f_op3_0;
  long f_op4_0_base_0;
  long f_op4_0_base_6;
  long f_op4_0_base_16;
  long f_op4_0_base_24;
  long f_op31_30;
  long f_op31_27;
  long f_op31_16;
  long f_op31_16s;
  long f_op31_16s_shl1;
  long f_op31_16s_shl2;
  long f_op31_16s_shl3;
  long f_op31_16s_shl4;
  long f_pcrel16;
  long f_op29_26;
  long f_op29_24;
  long f_op26_23;
  long f_op26_16;
  long f_pcrel10;
  long f_pcrel8;
  long f_op22_21;
  long f_op22;
  long f_op21_16;
  long f_op21_16s;
  long f_op21_16s_shl1;
  long f_op21_16s_shl2;
  long f_op21_16s_shl3;
  long f_op21_16s_shl4;
  long f_op21_16s_shl5;
  long f_op21_16s_shl6;
  long f_op21_16s_shl7;
  long f_op21_16s_shl8;
  long f_op20_16;
  long f_op47_16;
  long f_pcrel32_48;
  long f_op47_43;
  long f_offset27_48;
  long f_pcrel27_48;
  long f_op79_48;
  long f_offset23bits;
  long f_offset27bits;
  long f_offset12;
};

#define CGEN_INIT_PARSE(od) \
{\
}
#define CGEN_INIT_INSERT(od) \
{\
}
#define CGEN_INIT_EXTRACT(od) \
{\
}
#define CGEN_INIT_PRINT(od) \
{\
}


#endif /* VC4_OPC_H */